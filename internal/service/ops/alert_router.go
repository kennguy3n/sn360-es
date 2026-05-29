// Package ops contains the autonomous-ops surface for sn360-es.
//
// The package's first deliverable is the alert router: a small HTTP
// handler that receives Prometheus Alertmanager webhooks (the standard
// v4 payload shape), classifies each alert, and routes it to the
// correct action — runbook lookup, automated remediation (when
// explicitly enabled per-alert), or escalation-ticket creation.
//
// The router exists so a production deployment can run completely
// without a human on-call rotation for the common autonomic cases
// (e.g. a worker stalled because of a transient deadlock, where a
// pod-restart is the documented remediation). Anything we haven't
// taught the router to handle falls back to the same escalation-
// ticket path the AI Tier 2 pipeline uses, so a human SecOps engineer
// gets a structured incident with the runbook link pre-populated.
//
// Architecture:
//
//	Alertmanager ──webhook──▶ AlertRouter.ServeHTTP
//	                              │
//	                              ▼
//	                      classify(alert) ──▶ (action, remediator, reason)
//	                              │
//	                              ├── action=runbook       ──▶ no-op (link in annotations)
//	                              ├── action=remediate     ──▶ remediator.Remediate(ctx, alert)
//	                              └── action=escalate      ──▶ escalation.Escalate(ctx, ...)
//
// The Remediator interface is pluggable so the production wiring
// hooks the Kubernetes API client (rollout-restart, scale-up) and the
// tests use an in-memory fake.
package ops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// AlertmanagerPayload is the v4 webhook shape Prometheus Alertmanager
// posts. We only consume the fields the router needs; unknown fields
// are silently ignored by json.Unmarshal so future Alertmanager
// versions that add fields will not break the decoder.
//
// See https://prometheus.io/docs/alerting/latest/configuration/#webhook_config
// for the full schema. We deliberately do NOT model the entire payload
// because the router's decision tree depends on labels + annotations
// only.
type AlertmanagerPayload struct {
	Version  string  `json:"version"`
	Status   string  `json:"status"` // "firing" | "resolved"
	Receiver string  `json:"receiver"`
	Alerts   []Alert `json:"alerts"`
}

// Alert is a single firing or resolved alert inside the webhook
// payload. Labels carry the rule name + severity + component;
// Annotations carry the runbook URL + summary + description.
type Alert struct {
	Status       string            `json:"status"` // "firing" | "resolved"
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Fingerprint  string            `json:"fingerprint"`
}

// AlertAction is what the router decided to do with a single alert.
// Captured into a Decision so tests can assert against it without
// needing to mock the remediator + escalator side effects.
type AlertAction string

const (
	// ActionRunbook means the alert is informational + has a runbook;
	// the operator on rotation reads it and decides. We don't post
	// anywhere because the alert is already in the on-call channel
	// via the Alertmanager router rule.
	ActionRunbook AlertAction = "runbook"

	// ActionRemediate means a safe automated remediation exists for
	// this alert and is enabled via config. The remediator is invoked
	// synchronously inside handlePayload (NOT in a detached goroutine)
	// so the router has visibility over remediator success/failure for
	// logs + metrics + the critical-severity escalation fallback in
	// dispatch(). A slow K8s API call therefore extends the HTTP
	// response time for this webhook — Remediator implementations
	// MUST honour the ctx deadline (which inherits the HTTP request
	// deadline) and cap their own work so a stuck call cannot pin the
	// Alertmanager retry loop. See the Remediator interface doc for
	// the contract.
	ActionRemediate AlertAction = "remediate"

	// ActionEscalate means create a structured escalation ticket so a
	// human SecOps engineer gets a paged incident with full context.
	// Used for any alert that doesn't have a remediation AND has a
	// severity of `critical`.
	ActionEscalate AlertAction = "escalate"

	// ActionSkip means the alert is too noisy or already-handled to
	// merit any action — e.g. a `status=resolved` notification.
	ActionSkip AlertAction = "skip"
)

// Decision is the router's classification of a single alert.
// Returned alongside the action so callers (tests + audit log) can
// see WHY a particular action was chosen.
type Decision struct {
	Alert  Alert       `json:"alert"`
	Action AlertAction `json:"action"`
	Reason string      `json:"reason"`
}

// Remediator is the contract for the side effects ActionRemediate
// triggers. The production wiring is a thin wrapper over the
// Kubernetes client that issues `kubectl rollout restart` for the
// pod whose name matches the `component` label. Tests use the
// FakeRemediator in alert_router_test.go.
//
// Remediate is called SYNCHRONOUSLY by dispatch() (NOT in a
// detached goroutine) so the router can observe the error and apply
// the critical-severity escalation fallback. Implementations
// therefore directly extend the Alertmanager webhook response time —
// they MUST honour the ctx deadline and bound their own work so a
// blocked K8s API call cannot pin the webhook beyond Alertmanager's
// configured response timeout (default 10s on the `webhook_config`
// receiver; see Helm chart `alertmanagerconfig.yaml` if/when wired).
// The returned error is consumed by the router for logs + metrics
// + escalation-fallback only; Alertmanager itself only sees the
// router's HTTP 200.
type Remediator interface {
	Remediate(ctx context.Context, alert Alert) error
}

// Escalator is the contract for ActionEscalate. The production wiring
// is `internal/service/agent/EscalationService.Escalate`; the tests
// use a FakeEscalator that records the incidents.
type Escalator interface {
	Escalate(ctx context.Context, tenantID string, incident dto.EscalationIncident) (dto.EscalationTicket, error)
}

// RouterConfig wires the AlertRouter.
type RouterConfig struct {
	// Remediator is invoked for ActionRemediate decisions. May be nil
	// — in which case every otherwise-remediate alert falls through
	// to ActionEscalate so a human handles it. Default-nil is safe
	// because automated remediation is opt-in, not opt-out.
	Remediator Remediator

	// Escalator is invoked for ActionEscalate decisions. REQUIRED;
	// the router refuses to start without one because escalation is
	// the safety net that catches everything else.
	Escalator Escalator

	// TenantID is the deployment-scoped tenant the router books
	// escalations against. For multi-tenant deployments this is the
	// platform-owner tenant ID (i.e. the operator running the
	// service), NOT a customer tenant — alerts are infrastructure
	// concerns, not customer-data concerns.
	TenantID string

	// RemediableAlerts is the set of alert names the router is
	// allowed to remediate automatically. Unknown alert names always
	// fall through to ActionRunbook (info severity) or
	// ActionEscalate (critical severity). Default empty = remediator
	// is never invoked, every alert goes runbook/escalate.
	RemediableAlerts map[string]bool

	// Logger is required so the audit trail is centralised.
	Logger *slog.Logger

	// Clock is injected for deterministic tests; defaults to time.Now.
	Clock func() time.Time
}

// AlertRouter is the HTTP handler that consumes Alertmanager webhooks
// and routes the alerts to the right action surface. It is safe for
// concurrent use; each request is handled in its own goroutine by
// net/http, and the router holds no mutable state.
type AlertRouter struct {
	remediator       Remediator
	escalator        Escalator
	tenantID         string
	remediableAlerts map[string]bool
	logger           *slog.Logger
	now              func() time.Time
}

// NewAlertRouter validates the config and constructs the handler.
func NewAlertRouter(cfg RouterConfig) (*AlertRouter, error) {
	if cfg.Escalator == nil {
		return nil, errors.New("ops.AlertRouter: Escalator is required")
	}
	if cfg.TenantID == "" {
		return nil, errors.New("ops.AlertRouter: TenantID is required (use the platform-owner tenant ID, not a customer tenant)")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	if cfg.RemediableAlerts == nil {
		cfg.RemediableAlerts = map[string]bool{}
	}
	return &AlertRouter{
		remediator:       cfg.Remediator,
		escalator:        cfg.Escalator,
		tenantID:         cfg.TenantID,
		remediableAlerts: cfg.RemediableAlerts,
		logger:           cfg.Logger,
		now:              cfg.Clock,
	}, nil
}

// Classify is the pure decision function: given an alert + the router's
// remediable-alerts map + the router's remediator state, return the
// action to take and a human-readable reason. Pulled out of ServeHTTP
// so unit tests can exercise the decision tree without an HTTP server.
func (r *AlertRouter) Classify(a Alert) Decision {
	// Resolved alerts are always Skip — Alertmanager fires the
	// resolved notification informationally; remediating or
	// escalating on it would be a double-action.
	if strings.EqualFold(a.Status, "resolved") {
		return Decision{Alert: a, Action: ActionSkip, Reason: "alert resolved upstream"}
	}
	name := a.Labels["alertname"]
	severity := strings.ToLower(a.Labels["severity"])

	// Remediation path. Only fire if (a) the alert is on the
	// allow-list AND (b) a remediator is wired. Failing either gate
	// is intentional defense in depth: a misconfigured allow-list
	// without a remediator should produce the same observable
	// behaviour as the default (runbook/escalate).
	if r.remediableAlerts[name] && r.remediator != nil {
		return Decision{Alert: a, Action: ActionRemediate, Reason: fmt.Sprintf("%s on remediation allow-list", name)}
	}

	// Critical severity without remediation -> escalate. Critical is
	// the SLO-budget-burning tier; we cannot let it sit in a runbook
	// channel without a paged incident.
	if severity == "critical" {
		return Decision{Alert: a, Action: ActionEscalate, Reason: fmt.Sprintf("%s severity=critical, no remediator", name)}
	}

	// Default: runbook. Warning + info severities go to the on-call
	// channel via Alertmanager's own routing; the router records
	// receipt so we have an audit trail and observability over what
	// the deployment is signalling.
	return Decision{Alert: a, Action: ActionRunbook, Reason: fmt.Sprintf("%s severity=%s, runbook only", name, severity)}
}

// ServeHTTP implements http.Handler. Accepts POST with a JSON
// Alertmanager webhook v4 body. Returns 200 on successful classification
// (even when the chosen action's side effect failed) so Alertmanager
// does not retry — the router's logger + metrics are authoritative for
// failure visibility.
//
// Non-POST methods return 405. A malformed body returns 400 (the
// Alertmanager webhook config has a typo, we want operators to notice
// quickly). A body with version != "4" returns 400; future Alertmanager
// versions can extend the schema and we'd rather fail loud than process
// fields we don't understand.
func (r *AlertRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload AlertmanagerPayload
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		r.logger.Warn("ops.alert_router: decode failed",
			slog.Any("error", err),
			slog.String("remote", req.RemoteAddr))
		http.Error(w, fmt.Sprintf("decode: %v", err), http.StatusBadRequest)
		return
	}
	if payload.Version != "4" {
		// Alertmanager has been on v4 since 2017. A different value
		// means either (a) a future major version we haven't audited
		// or (b) an incorrectly-shaped body — either way, we want
		// human attention before processing.
		http.Error(w, fmt.Sprintf("unsupported webhook version %q", payload.Version), http.StatusBadRequest)
		return
	}
	decisions := r.handlePayload(req.Context(), payload)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"received":  len(payload.Alerts),
		"decisions": decisions,
	})
}

// handlePayload classifies every alert in the payload and dispatches
// the side effects. Returns the decisions for the response body and
// for tests. The remediator + escalator calls are NOT detached into
// goroutines so the router has visibility over their success — the
// previous design draft used go-routines but that made debugging
// "the alert fired but nothing happened" much harder. ServeHTTP runs
// in its own goroutine anyway, so we're not blocking the net/http
// server's accept loop here.
func (r *AlertRouter) handlePayload(ctx context.Context, payload AlertmanagerPayload) []Decision {
	out := make([]Decision, 0, len(payload.Alerts))
	for _, a := range payload.Alerts {
		d := r.Classify(a)
		out = append(out, d)
		r.dispatch(ctx, d)
	}
	return out
}

// dispatch performs the side effect for a single decision. Errors are
// logged but not returned — the HTTP response is "received N decisions"
// regardless of remediator / escalator success.
func (r *AlertRouter) dispatch(ctx context.Context, d Decision) {
	switch d.Action {
	case ActionSkip:
		r.logger.Debug("ops.alert_router: skip",
			slog.String("alert", d.Alert.Labels["alertname"]),
			slog.String("reason", d.Reason))
	case ActionRunbook:
		r.logger.Info("ops.alert_router: runbook",
			slog.String("alert", d.Alert.Labels["alertname"]),
			slog.String("severity", d.Alert.Labels["severity"]),
			slog.String("runbook_url", d.Alert.Annotations["runbook_url"]),
			slog.String("reason", d.Reason))
	case ActionRemediate:
		if err := r.remediator.Remediate(ctx, d.Alert); err != nil {
			r.logger.Error("ops.alert_router: remediation failed",
				slog.String("alert", d.Alert.Labels["alertname"]),
				slog.Any("error", err))
			// Defense-in-depth: a failing remediator on a
			// critical alert must NOT silently drop the incident.
			// The nil-remediator branch of Classify already routes
			// critical alerts to ActionEscalate; we want the same
			// observable outcome when a wired remediator returns an
			// error. Without this fallback, adding an alert to the
			// remediation allow-list actually degrades error
			// handling relative to leaving it off — the inverse of
			// the intent.
			//
			// Lower severities deliberately do NOT fall back: a
			// warning-level remediation failure is logged and left
			// for the operator to triage from the alert-history
			// dashboard. Escalating every warning would page humans
			// for transient remediator hiccups (network blips,
			// RBAC re-auth), defeating the autonomic point of the
			// remediator.
			if strings.EqualFold(d.Alert.Labels["severity"], "critical") {
				r.escalateAfterRemediationFailure(ctx, d.Alert, err)
			}
			return
		}
		r.logger.Info("ops.alert_router: remediated",
			slog.String("alert", d.Alert.Labels["alertname"]),
			slog.String("component", d.Alert.Labels["component"]))
	case ActionEscalate:
		incident := buildIncidentFromAlert(d.Alert, r.now())
		ticket, err := r.escalator.Escalate(ctx, r.tenantID, incident)
		if err != nil {
			r.logger.Error("ops.alert_router: escalation failed",
				slog.String("alert", d.Alert.Labels["alertname"]),
				slog.Any("error", err))
			return
		}
		r.logger.Info("ops.alert_router: escalated",
			slog.String("alert", d.Alert.Labels["alertname"]),
			slog.String("ticket_id", ticket.TicketID))
	}
}

// escalateAfterRemediationFailure builds an escalation incident
// derived from `a` but enriched with the remediation-failure
// context (the wrapped err on Indicators, a `remediation_failed`
// marker on AISummary) so the human SecOps engineer who picks up
// the ticket immediately sees the autonomous remediator already
// tried-and-failed. Used only by the critical-severity fallback
// path inside dispatch(); not exported.
func (r *AlertRouter) escalateAfterRemediationFailure(ctx context.Context, a Alert, remedErr error) {
	incident := buildIncidentFromAlert(a, r.now())
	// Prepend the remediation-failure marker so the operator sees
	// it at the top of the ticket summary. The original summary
	// follows so the alert's own context is preserved.
	incident.AISummary = fmt.Sprintf(
		"remediation_failed: %v | %s",
		remedErr,
		incident.AISummary,
	)
	// Add the remediator error as an indicator so it survives
	// downstream JSON-marshal without being lost in a free-form
	// summary string.
	incident.Indicators = append(incident.Indicators, fmt.Sprintf("remediation_error:%v", remedErr))
	ticket, escErr := r.escalator.Escalate(ctx, r.tenantID, incident)
	if escErr != nil {
		r.logger.Error("ops.alert_router: escalation after remediation failure also failed",
			slog.String("alert", a.Labels["alertname"]),
			slog.Any("remediation_error", remedErr),
			slog.Any("escalation_error", escErr))
		return
	}
	r.logger.Warn("ops.alert_router: escalated after remediation failure (critical-severity fallback)",
		slog.String("alert", a.Labels["alertname"]),
		slog.String("ticket_id", ticket.TicketID),
		slog.Any("remediation_error", remedErr))
}

// buildIncidentFromAlert maps an Alertmanager alert onto the
// dto.EscalationIncident shape the EscalationService consumes. The
// mapping uses the alert's annotations for the human-readable parts
// (summary -> AISummary, runbook_url as a single indicator), the
// labels for the categorical parts (alertname -> Category,
// component -> Tier), and the alert's fingerprint as the
// PseudoMessageID so duplicate fires of the same alert (Alertmanager
// re-resolves and re-fires) deduplicate at the ticket level.
func buildIncidentFromAlert(a Alert, now time.Time) dto.EscalationIncident {
	indicators := make([]string, 0, 2)
	if rb := a.Annotations["runbook_url"]; rb != "" {
		indicators = append(indicators, "runbook:"+rb)
	}
	if a.GeneratorURL != "" {
		indicators = append(indicators, "alertmanager:"+a.GeneratorURL)
	}
	detected := a.StartsAt
	if detected.IsZero() {
		detected = now
	}
	return dto.EscalationIncident{
		PseudoMessageID: a.Fingerprint,
		Tier:            a.Labels["component"],
		Category:        a.Labels["alertname"],
		// AlertManager doesn't map to one of the EscalationReason
		// constants cleanly — the closest match is "ai_low_confidence"
		// since alerts are typically a heuristic signal that needs
		// human verification. The annotations carry the real shape.
		Reason:            dto.EscalationReasonLowConfidence,
		Score:             0,
		AffectedUserCount: 0,
		AISummary:         a.Annotations["summary"],
		Indicators:        indicators,
		DetectedAt:        detected,
	}
}
