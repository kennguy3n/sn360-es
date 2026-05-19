package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// OnboardingConfig wires the onboarding agent's dependencies.
type OnboardingConfig struct {
	Directory     DirectoryClient
	VendorScanner VendorScanner
	Labels        LabelApplier
	Events        EventPublisher
	Audit         AuditLog
	Config        ConfigStore
	Hasher        PIIHasher

	// Persister stores discovered users/groups to Postgres after onboarding.
	Persister UserPersister
	// SensitivityClassifier is the tiered ML classifier (encoder+bonsai+fallback).
	SensitivityClassifier SensitivityClassifier

	// VendorScanWindow controls how far back the vendor scan looks
	// (default 30 days).
	VendorScanWindow time.Duration
	// MinVendorConfidence is the floor applied to VendorCandidate
	// scores; senders below this are not promoted (default 0.6).
	MinVendorConfidence float64
	// DefaultWeights is the baseline score-engine weights seeded into
	// the config store for new tenants.
	DefaultWeights ScoreWeights
	// DefaultThresholds is the baseline thresholds seeded for new
	// tenants.
	DefaultThresholds Thresholds

	Logger *slog.Logger
}

// UserPersister stores discovered users and groups to persistent storage
// after the onboarding flow completes.
type UserPersister interface {
	PersistDiscoveredUsers(ctx context.Context, tenantID string, users []DiscoveredUser, groups []DiscoveredGroup) error
}

// OnboardingAgent runs once per new tenant, performing the
// discovery + configuration steps described in PROPOSAL.md Section 7.
// It is safe for concurrent use but is normally invoked from a single
// goroutine that handles `es.onboarding.tenant.created`.
type OnboardingAgent struct {
	cfg OnboardingConfig
	log *slog.Logger
}

// NewOnboardingAgent validates cfg and returns an agent.
func NewOnboardingAgent(cfg OnboardingConfig) (*OnboardingAgent, error) {
	if cfg.Directory == nil {
		return nil, errors.New("agent: onboarding requires a DirectoryClient")
	}
	if cfg.Labels == nil {
		return nil, errors.New("agent: onboarding requires a LabelApplier")
	}
	if cfg.VendorScanWindow <= 0 {
		cfg.VendorScanWindow = 30 * 24 * time.Hour
	}
	if cfg.MinVendorConfidence <= 0 {
		cfg.MinVendorConfidence = 0.6
	}
	if cfg.DefaultWeights == (ScoreWeights{}) {
		cfg.DefaultWeights = ScoreWeights{AI: 0.60, Rspamd: 0.10, Attachments: 0.15, Links: 0.15}
	}
	if cfg.DefaultThresholds == (Thresholds{}) {
		cfg.DefaultThresholds = Thresholds{
			Tier1PassBelow: 20,
			Tier1FlagAbove: 60,
			BannerBlocked:  85,
			BannerHighRisk: 70,
			BannerWarning:  50,
			BannerCaution:  30,
			BannerInfo:     15,
		}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &OnboardingAgent{cfg: cfg, log: cfg.Logger}, nil
}

// Name implements Agent.
func (a *OnboardingAgent) Name() string { return "onboarding" }

// OnboardingResult captures everything the agent did during a single
// run. Returned for tests + audit consumers.
type OnboardingResult struct {
	TenantID         string
	UsersDiscovered  int
	GroupsDiscovered int
	LabelsApplied    int
	VendorsSeeded    int
	StartedAt        time.Time
	CompletedAt      time.Time
}

// Onboard executes the full onboarding flow for tctx.
//
// Steps (in order):
//  1. List users + groups from the provider directory.
//  2. Classify per-role sensitivity (C-suite, Finance, HR get high).
//  3. Ensure tier labels exist on every discovered mailbox.
//  4. Seed default config (weights, thresholds) in the config store.
//  5. Scan recent senders to seed the vendor allowlist.
//  6. Emit `es.onboarding.user.created` per discovered user so the
//     downstream services (ingestion polling, analytics) can react.
//  7. Record an audit entry summarising the run.
func (a *OnboardingAgent) Onboard(ctx context.Context, tctx TenantContext) (OnboardingResult, error) {
	if err := tctx.Validate(); err != nil {
		return OnboardingResult{}, err
	}
	res := OnboardingResult{TenantID: tctx.TenantID, StartedAt: time.Now().UTC()}
	log := a.log.With(slog.String("tenant_id", tctx.TenantID), slog.String("provider", string(tctx.Provider)))
	log.Info("agent.onboarding: starting")

	users, err := a.cfg.Directory.ListUsers(ctx, tctx.TenantID)
	if err != nil {
		return res, fmt.Errorf("onboarding: list users: %w", err)
	}
	res.UsersDiscovered = len(users)

	groups, err := a.cfg.Directory.ListGroups(ctx, tctx.TenantID)
	if err != nil {
		return res, fmt.Errorf("onboarding: list groups: %w", err)
	}
	res.GroupsDiscovered = len(groups)

	groupIndex := indexGroups(groups)

	// Classify sensitivity using tiered ML classifier if available,
	// otherwise fall back to keyword-based classification.
	if a.cfg.SensitivityClassifier != nil && len(users) > 0 {
		inputs := make([]UserClassifyInput, len(users))
		for i, u := range users {
			var groupNames []string
			for _, gid := range u.GroupIDs {
				if g, ok := groupIndex[gid]; ok {
					groupNames = append(groupNames, g.Name)
				}
			}
			inputs[i] = UserClassifyInput{
				JobTitle:    u.JobTitle,
				Department:  u.Department,
				DisplayName: u.DisplayName,
				GroupNames:  groupNames,
				IsAdmin:     u.IsAdmin,
			}
		}
		results, classErr := a.cfg.SensitivityClassifier.ClassifyBatch(ctx, inputs)
		if classErr != nil {
			log.Warn("agent.onboarding: ML classification failed, falling back to keywords",
				slog.String("err", classErr.Error()))
			for i := range users {
				users[i].SensitivityHint = ClassifyUserSensitivity(users[i], groupIndex)
				users[i].SensitivityConfidence = 1.0
			}
		} else {
			for i := range users {
				if i < len(results) {
					users[i].SensitivityHint = results[i].Sensitivity
					users[i].SensitivityConfidence = results[i].Confidence
					users[i].NeedsAdminReview = results[i].NeedsReview
				}
			}
		}
	} else {
		for i := range users {
			users[i].SensitivityHint = ClassifyUserSensitivity(users[i], groupIndex)
			users[i].SensitivityConfidence = 1.0
		}
	}

	for _, u := range users {
		if u.IsSuspended || u.Email == "" {
			continue
		}
		if err := a.cfg.Labels.EnsureTierLabels(ctx, tctx.TenantID, u.Email); err != nil {
			log.Warn("agent.onboarding: label apply failed",
				slog.String("mailbox", u.Email),
				slog.String("err", err.Error()))
			continue
		}
		res.LabelsApplied++
		if err := a.publishUserEvent(ctx, tctx, u); err != nil {
			log.Warn("agent.onboarding: emit user event failed",
				slog.String("mailbox", u.Email),
				slog.String("err", err.Error()))
		}
	}

	// Persist discovered users/groups to the database.
	if a.cfg.Persister != nil {
		if err := a.cfg.Persister.PersistDiscoveredUsers(ctx, tctx.TenantID, users, groups); err != nil {
			log.Warn("agent.onboarding: persist users failed", slog.String("err", err.Error()))
		}
	}

	if a.cfg.Config != nil {
		if err := a.cfg.Config.UpdateWeights(ctx, tctx.TenantID, a.cfg.DefaultWeights); err != nil {
			log.Warn("agent.onboarding: seed weights failed", slog.String("err", err.Error()))
		}
		if err := a.cfg.Config.UpdateThresholds(ctx, tctx.TenantID, a.cfg.DefaultThresholds); err != nil {
			log.Warn("agent.onboarding: seed thresholds failed", slog.String("err", err.Error()))
		}
	}

	if a.cfg.VendorScanner != nil {
		since := time.Now().Add(-a.cfg.VendorScanWindow)
		candidates, err := a.cfg.VendorScanner.ScanRecentSenders(ctx, tctx.TenantID, since)
		if err != nil {
			log.Warn("agent.onboarding: vendor scan failed", slog.String("err", err.Error()))
		} else {
			for _, c := range candidates {
				if c.Confidence < a.cfg.MinVendorConfidence {
					continue
				}
				res.VendorsSeeded++
				if err := a.publishVendorSeed(ctx, tctx, c); err != nil {
					log.Warn("agent.onboarding: vendor seed emit failed",
						slog.String("domain", c.Domain),
						slog.String("err", err.Error()))
				}
			}
		}
	}

	res.CompletedAt = time.Now().UTC()
	if a.cfg.Audit != nil {
		_ = a.cfg.Audit.Record(ctx, AuditEntry{
			Agent:      a.Name(),
			TenantID:   tctx.TenantID,
			Action:     "onboarding.completed",
			OccurredAt: res.CompletedAt,
			Detail: map[string]any{
				"users":   res.UsersDiscovered,
				"groups":  res.GroupsDiscovered,
				"labels":  res.LabelsApplied,
				"vendors": res.VendorsSeeded,
			},
		})
	}
	log.Info("agent.onboarding: completed",
		slog.Int("users", res.UsersDiscovered),
		slog.Int("groups", res.GroupsDiscovered),
		slog.Int("labels", res.LabelsApplied),
		slog.Int("vendors", res.VendorsSeeded))
	return res, nil
}

func (a *OnboardingAgent) publishUserEvent(ctx context.Context, tctx TenantContext, u DiscoveredUser) error {
	if a.cfg.Events == nil {
		return nil
	}

	// Pseudonymize PII before publishing — never emit raw email or
	// display name to the event bus.
	var emailHash, displayHash string
	if a.cfg.Hasher != nil {
		emailHash = a.cfg.Hasher.HashPII(tctx.TenantID, u.Email)
		displayHash = a.cfg.Hasher.HashPII(tctx.TenantID, u.DisplayName)
	} else {
		emailHash = "<redacted>"
		displayHash = "<redacted>"
	}

	payload := map[string]any{
		"tenant_id":    tctx.TenantID,
		"provider":     string(tctx.Provider),
		"user_id":      u.ID,
		"email_hash":   emailHash,
		"display_hash": displayHash,
		"department":   u.Department,
		"sensitivity":  u.SensitivityHint.String(),
		"confidence":   u.SensitivityConfidence,
		"occurred_at":  time.Now().UTC(),
	}
	blob, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return a.cfg.Events.Publish(ctx, "es.onboarding.user.created", blob)
}

func (a *OnboardingAgent) publishVendorSeed(ctx context.Context, tctx TenantContext, c VendorCandidate) error {
	if a.cfg.Events == nil {
		return nil
	}
	payload := map[string]any{
		"tenant_id":   tctx.TenantID,
		"domain":      c.Domain,
		"confidence":  c.Confidence,
		"seen_count":  c.SeenCount,
		"occurred_at": time.Now().UTC(),
	}
	blob, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return a.cfg.Events.Publish(ctx, "es.onboarding.vendor.seeded", blob)
}

// indexGroups builds a quick lookup by group ID; it is used during
// per-user sensitivity classification.
func indexGroups(groups []DiscoveredGroup) map[string]DiscoveredGroup {
	out := make(map[string]DiscoveredGroup, len(groups))
	for _, g := range groups {
		out[g.ID] = g
	}
	return out
}

// ClassifyUserSensitivity returns the sensitivity boost we apply to
// a user based on job title, department, and group memberships. Pure
// function, exported so tests can pin the matrix.
//
// Sensitivity matrix (in priority order):
//
//   - Infrastructure admins (DBA, SysAdmin, Cloud Admin) → Critical
//   - C-suite, founders, owners → Max
//   - Finance, treasury, AP/AR → High
//   - HR, legal, compliance → High
//   - Technology (DevOps, SecEng, DataEng) → High
//   - M&A, corporate development, investor relations → High
//   - Healthcare (Doctor, Pharmacist, Medical Director) → High
//   - R&D (Research Director, Data Scientist) → High
//   - DevOps Engineer, Nurse, Paralegal, Sales Director → Elevated
//   - Admin assistants, executive assistants → Elevated
//   - Procurement, vendor management → Elevated
//   - Everyone else → Default
func ClassifyUserSensitivity(u DiscoveredUser, groups map[string]DiscoveredGroup) Sensitivity {
	// Pad with spaces so word-boundary checks (e.g. " cto") work at
	// the start/end of the string without special-casing.
	hay := " " + normalizeHaystack(strings.ToLower(u.JobTitle+" "+u.Department+" "+u.DisplayName)) + " "
	for _, gID := range u.GroupIDs {
		if g, ok := groups[gID]; ok {
			hay += normalizeHaystack(strings.ToLower(g.Name)) + " "
		}
	}
	switch {
	// Critical — Infrastructure-level access roles (highest priority).
	// "dba " with trailing space avoids false positives like "feedback".
	case containsAny(hay, "database administrator", "dba ", "domain admin", "sysadmin",
		"system administrator", "cloud administrator", "infrastructure engineer", "sre lead",
		"devops lead", "root access",
		"security administrator", "platform engineer", "network administrator"):
		return SensitivityCritical
	// Max — C-suite, board members, founders.
	// " cto " / " coo " use both leading+trailing space to avoid
	// matching inside "director" / "coordinator".
	case containsAny(hay, "ceo", "cfo", " coo ", " cto ", "ciso", "founder",
		"chief executive", "chief financial", "chief operating", "chief technology", "owner"):
		return SensitivityMax
	// High — Finance, treasury.
	case containsAny(hay, "finance", "treasury", "accounts payable", "accounts receivable", "controller", "bookkeep"):
		return SensitivityHigh
	// High — HR, legal, compliance.
	// " legal" avoids matching inside "paralegal".
	case containsAny(hay, "human resources", "people ops", " legal", "compliance", "general counsel"):
		return SensitivityHigh
	// High — Technology (sensitive access, not infra-level).
	case containsAny(hay, "security engineer", "security analyst", "cloud engineer",
		"network engineer", "data engineer", "site reliability engineer"):
		return SensitivityHigh
	// High — M&A / Strategy.
	case containsAny(hay, "mergers and acquisitions", "m&a", "corporate development",
		"corp dev", "investor relations", "board secretary", "corporate strategy"):
		return SensitivityHigh
	// High — Healthcare / Medical.
	case containsAny(hay, "doctor", "physician", "surgeon", "medical director", "chief medical",
		"pharmacist", "clinical director", "medical records", "health information",
		"chief nursing", "nurse manager"):
		return SensitivityHigh
	// High — R&D / Intellectual Property.
	case containsAny(hay, "research director", "r&d", "patent", "intellectual property",
		"chief scientist", "data scientist", "ml engineer"):
		return SensitivityHigh
	// Elevated — Technology supporting roles.
	case containsAny(hay, "devops engineer", "devops", "junior dba", "help desk manager", "it support lead"):
		return SensitivityElevated
	// Elevated — Healthcare clinical support.
	case containsAny(hay, "nurse", "lab technician", "radiologist", "physical therapist",
		"clinical research", "clinical coordinator"):
		return SensitivityElevated
	// Elevated — Legal extended.
	case containsAny(hay, "paralegal", "litigation support", "privacy officer", "data protection officer"):
		return SensitivityElevated
	// Elevated — Sales (customer data access).
	case containsAny(hay, "sales director", "account executive", "customer success", "customer data"):
		return SensitivityElevated
	// Elevated — Executive / Admin assistants (existing).
	case containsAny(hay, "executive assistant", "admin assistant", "office manager"):
		return SensitivityElevated
	// Elevated — Procurement (existing).
	case containsAny(hay, "procurement", "vendor management", "supplier"):
		return SensitivityElevated
	default:
		return SensitivityDefault
	}
}

func containsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}
