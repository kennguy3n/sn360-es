// SMTP MX gateway: pre-delivery scanning entry point.
//
// Unlike the poller (which pulls already-delivered mail from provider
// APIs) and the push receivers (which react to provider webhooks),
// the MX gateway sits *in front of* the mailbox. Mail servers route
// inbound mail to it via MX records; it scans each message before it
// reaches the inbox and only then relays it on to the downstream mail
// store. This is the table-stakes deployment mode versus Proofpoint /
// Mimecast — detection happens pre-delivery, so a Blocked verdict can
// stop a message from ever landing in the user's inbox.
//
// Pipeline integration: every accepted message is normalized and
// published as an `es.evaluate.request` event, exactly like the
// poller and push paths, so the same 3-tier evaluation pipeline
// (Tier 0 → Tier 1 → Tier 2 + Rspamd) processes gateway-ingested
// mail. The gateway additionally performs inline DKIM verification
// and folds the result into a synthesized Authentication-Results
// header so the normalizer derives the same SPF/DKIM/DMARC risk
// signals it does for provider-sourced mail.
//
// Design notes:
//
//   - STARTTLS: when a TLSConfig is supplied the server advertises
//     STARTTLS (RFC 3207). RequireTLS additionally refuses MAIL FROM
//     on a plaintext session so credentials and message bodies are
//     never transmitted in the clear.
//   - DKIM: verification runs over the raw RFC 5322 bytes (the only
//     representation whose canonicalization is stable) before the
//     message is parsed for the pipeline.
//   - Pre-delivery decision: a PreDeliveryDecider may synchronously
//     accept / defer / reject a message (e.g. off fast Tier 0 rules)
//     so the gateway can block before relay. The default accepts and
//     relies on the async pipeline + post-delivery remediation.
//   - Relay: an accepted message is handed to a MessageDeliverer
//     (the downstream smarthost / mail store). When no deliverer is
//     wired the gateway scans-and-publishes only, which is the safe
//     default for a monitoring-mode rollout.
package ingestion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	smtp "github.com/emersion/go-smtp"

	"github.com/kennguy3n/sn360-es/internal/dto"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// DeliveryDecision is the verdict a PreDeliveryDecider returns for an
// inbound message. It maps onto SMTP reply classes so the gateway can
// accept, temporarily defer, or permanently reject a message before
// it is relayed downstream.
type DeliveryDecision int

const (
	// DecisionAccept relays the message and publishes it for
	// evaluation. This is the default when no decider is wired.
	DecisionAccept DeliveryDecision = iota
	// DecisionDefer returns a 4xx so the sending MTA retries later.
	// Used when a synchronous scan cannot complete in time.
	DecisionDefer
	// DecisionReject returns a 5xx so the message is bounced and
	// never delivered. Used for high-confidence pre-delivery blocks.
	DecisionReject
)

// PreDeliveryDecider optionally renders a synchronous verdict on a
// normalized message before it is relayed. Implementations must be
// fast (they run inline on the SMTP DATA path) and side-effect free
// beyond their decision; the heavy 3-tier evaluation always runs
// asynchronously off the published event regardless of the decision.
type PreDeliveryDecider interface {
	// Decide returns the delivery verdict for req. A non-empty reason
	// is surfaced in the SMTP reply (defer/reject) and the audit log.
	Decide(ctx context.Context, req dto.EvaluateRequest) (decision DeliveryDecision, reason string)
}

// SMTPEnvelope carries the SMTP-level addressing for a single message.
// These are the envelope (MAIL FROM / RCPT TO) values, which may
// differ from the RFC 5322 From/To header addresses.
type SMTPEnvelope struct {
	MailFrom string
	RcptTo   []string
	// RemoteAddr is the connecting MTA's network address, used for
	// logging and (in future) connection-level reputation.
	RemoteAddr string
	// TLS reports whether the inbound session was encrypted.
	TLS bool
}

// MessageDeliverer relays an accepted message to the downstream mail
// store (the smarthost behind the gateway). Implementations should be
// safe for concurrent use; the gateway calls Deliver once per accepted
// message. Returning an error fails the SMTP transaction so the
// sending MTA retries rather than silently dropping mail.
type MessageDeliverer interface {
	Deliver(ctx context.Context, env SMTPEnvelope, raw []byte) error
}

// SMTPGatewayConfig wires the MX gateway. Publisher is the only
// strictly-required field; every other zero value gets a sane default.
type SMTPGatewayConfig struct {
	// Addr is the listen address, e.g. ":25" or "0.0.0.0:2525".
	Addr string
	// Domain is the hostname announced in the SMTP banner / EHLO
	// response. Defaults to "sn360-es".
	Domain string
	// TLSConfig enables STARTTLS when non-nil.
	TLSConfig *tls.Config
	// RequireTLS rejects MAIL FROM until the session is encrypted.
	// Only meaningful when TLSConfig is set.
	RequireTLS bool

	Publisher  events.EventService
	Normalizer Normalizer
	Logger     *slog.Logger

	// Subject is the JetStream subject for emitted events. Defaults
	// to "es.evaluate.request".
	Subject string

	// MaxMessageBytes caps the accepted message size. Defaults to
	// 25 MiB (a common provider inbound ceiling).
	MaxMessageBytes int64
	// MaxRecipients caps RCPT TO count per transaction. Defaults to 100.
	MaxRecipients int
	// ReadTimeout / WriteTimeout bound per-connection IO. Default 60s.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// TenantResolver maps a recipient domain to the owning tenant ID.
	// When nil, the recipient domain itself is used as the tenant ID,
	// matching how the poller keys GWS tenants off the Workspace
	// domain. Returning ok=false drops the recipient with a logged
	// warning rather than attributing mail to the wrong tenant.
	TenantResolver func(recipientDomain string) (tenantID string, ok bool)

	// Decider optionally blocks/defers a message pre-delivery.
	Decider PreDeliveryDecider

	// Deliverer relays accepted messages downstream. When nil the
	// gateway scans-and-publishes only (monitoring mode).
	Deliverer MessageDeliverer

	// DKIMLookupTXT overrides DNS TXT resolution for DKIM public-key
	// retrieval. Production leaves this nil (net.LookupTXT); tests
	// inject a static resolver.
	DKIMLookupTXT func(domain string) ([]string, error)
	// MaxDKIMVerifications caps signatures verified per message to
	// bound CPU on adversarial input. Defaults to 10.
	MaxDKIMVerifications int

	// ShutdownTimeout bounds graceful drain on Run() cancellation.
	// Defaults to 10s.
	ShutdownTimeout time.Duration

	// now is injectable for deterministic tests. Defaults to
	// time.Now().UTC.
	now func() time.Time
}

// SMTPGateway is the running MX gateway server.
type SMTPGateway struct {
	cfg    SMTPGatewayConfig
	server *smtp.Server
}

// NewSMTPGateway validates the config and returns a ready gateway.
// Publisher is required; everything else defaults.
func NewSMTPGateway(cfg SMTPGatewayConfig) (*SMTPGateway, error) {
	if cfg.Publisher == nil {
		return nil, errors.New("ingestion: smtp gateway requires a publisher")
	}
	if cfg.Normalizer == nil {
		cfg.Normalizer = NewDefaultNormalizer()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Domain == "" {
		cfg.Domain = "sn360-es"
	}
	if cfg.Subject == "" {
		cfg.Subject = "es.evaluate.request"
	}
	if cfg.MaxMessageBytes <= 0 {
		cfg.MaxMessageBytes = 25 << 20
	}
	if cfg.MaxRecipients <= 0 {
		cfg.MaxRecipients = 100
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 60 * time.Second
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 60 * time.Second
	}
	if cfg.MaxDKIMVerifications <= 0 {
		cfg.MaxDKIMVerifications = 10
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = 10 * time.Second
	}
	if cfg.now == nil {
		cfg.now = func() time.Time { return time.Now().UTC() }
	}

	g := &SMTPGateway{cfg: cfg}

	srv := smtp.NewServer(smtp.BackendFunc(g.newSession))
	srv.Domain = cfg.Domain
	srv.MaxMessageBytes = cfg.MaxMessageBytes
	srv.MaxRecipients = cfg.MaxRecipients
	srv.ReadTimeout = cfg.ReadTimeout
	srv.WriteTimeout = cfg.WriteTimeout
	srv.EnableSMTPUTF8 = true
	if cfg.TLSConfig != nil {
		srv.TLSConfig = cfg.TLSConfig
	}
	g.server = srv
	return g, nil
}

// Addr returns the configured listen address.
func (g *SMTPGateway) Addr() string { return g.cfg.Addr }

// Run starts the SMTP listener and blocks until ctx is cancelled, then
// performs a bounded graceful shutdown. It owns the listener lifecycle
// so callers can spawn it as a tracked background goroutine.
func (g *SMTPGateway) Run(ctx context.Context) error {
	addr := g.cfg.Addr
	if addr == "" {
		addr = ":25"
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("ingestion: smtp gateway listen %q: %w", addr, err)
	}
	return g.serve(ctx, ln)
}

// serve runs the accept loop on an already-bound listener. Split out
// from Run so tests can bind an ephemeral port and dial it directly.
func (g *SMTPGateway) serve(ctx context.Context, ln net.Listener) error {
	g.cfg.Logger.Info("sn360-es: smtp mx gateway listening",
		slog.String("addr", ln.Addr().String()),
		slog.Bool("tls", g.cfg.TLSConfig != nil),
		slog.Bool("require_tls", g.cfg.RequireTLS))

	errCh := make(chan error, 1)
	go func() { errCh <- g.server.Serve(ln) }()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), g.cfg.ShutdownTimeout)
		defer cancel()
		if err := g.server.Shutdown(shutdownCtx); err != nil {
			g.cfg.Logger.Warn("sn360-es: smtp gateway shutdown error", slog.Any("error", err))
		}
		return nil
	case err := <-errCh:
		// smtp.Server.Serve returns ErrServerClosed on Close/Shutdown.
		if err != nil && !errors.Is(err, smtp.ErrServerClosed) {
			return fmt.Errorf("ingestion: smtp gateway serve: %w", err)
		}
		return nil
	}
}

// newSession is the smtp.Backend entry point invoked once per inbound
// connection.
func (g *SMTPGateway) newSession(c *smtp.Conn) (smtp.Session, error) {
	_, isTLS := c.TLSConnectionState()
	return &smtpSession{
		gw:         g,
		remoteAddr: addrString(c.Conn().RemoteAddr()),
		tls:        isTLS,
	}, nil
}

// smtpSession holds the per-transaction envelope state.
type smtpSession struct {
	gw         *SMTPGateway
	remoteAddr string
	tls        bool

	mailFrom string
	rcptTo   []string
}

// Reset discards the in-progress transaction state (between messages
// on the same connection).
func (s *smtpSession) Reset() {
	s.mailFrom = ""
	s.rcptTo = nil
}

// Logout releases connection resources. Nothing to free here.
func (s *smtpSession) Logout() error { return nil }

// Mail records the envelope sender and enforces RequireTLS.
func (s *smtpSession) Mail(from string, _ *smtp.MailOptions) error {
	if s.gw.cfg.RequireTLS && !s.tls {
		return &smtp.SMTPError{
			Code:         530,
			EnhancedCode: smtp.EnhancedCode{5, 7, 0},
			Message:      "Must issue a STARTTLS command first",
		}
	}
	s.mailFrom = from
	return nil
}

// Rcpt records a recipient. The go-smtp server enforces MaxRecipients.
func (s *smtpSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	s.rcptTo = append(s.rcptTo, to)
	return nil
}

// Data consumes the message body, verifies DKIM, runs the optional
// pre-delivery decision, publishes the message into the evaluation
// pipeline, and relays it downstream.
func (s *smtpSession) Data(r io.Reader) error {
	if s.mailFrom == "" || len(s.rcptTo) == 0 {
		return &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "Bad sequence: MAIL FROM and RCPT TO required before DATA",
		}
	}
	// Bound the read defensively even though go-smtp already wraps r
	// in a LimitReader at MaxMessageBytes — relying on the framework's
	// limit alone would couple our safety to its internals.
	raw, err := io.ReadAll(io.LimitReader(r, s.gw.cfg.MaxMessageBytes+1))
	if err != nil {
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "Failed to read message"}
	}
	if int64(len(raw)) > s.gw.cfg.MaxMessageBytes {
		return &smtp.SMTPError{Code: 552, EnhancedCode: smtp.EnhancedCode{5, 3, 4}, Message: "Message too large"}
	}

	ctx := context.Background()
	env := SMTPEnvelope{
		MailFrom:   s.mailFrom,
		RcptTo:     append([]string(nil), s.rcptTo...),
		RemoteAddr: s.remoteAddr,
		TLS:        s.tls,
	}

	dkimResult := s.gw.verifyDKIM(raw)

	parsed, perr := parseMessage(raw)
	if perr != nil {
		// A message we cannot parse cannot be safely evaluated. Defer
		// rather than accept-and-drop so the sender retries and we keep
		// a chance to deliver legitimate mail.
		s.gw.cfg.Logger.Warn("sn360-es: smtp gateway parse failed",
			slog.String("remote", s.remoteAddr), slog.Any("error", perr))
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "Cannot process message"}
	}

	// Process recipients in two phases so the SMTP reply and the
	// pipeline state can never disagree. A single DATA command yields a
	// single SMTP reply, yet each recipient is published as its own
	// per-tenant event; if we interleaved "decide then publish" per
	// recipient, a reject/defer on recipient N would return an error to
	// the sender *after* recipients 0..N-1 were already committed to the
	// bus. The sending MTA would then retry the bounced/deferred message
	// and re-publish 0..N-1 — duplicate scans plus a pipeline that acted
	// on a message the gateway claims to have refused.
	//
	// Phase 1 resolves, normalizes, and runs the pre-delivery decision
	// for every recipient, publishing nothing. Any non-accept verdict
	// returns immediately, before a single event exists.
	baseID := messageID(parsed.headers, raw)
	type acceptedRecipient struct {
		req  dto.EvaluateRequest
		rcpt string
	}
	accepted := make([]acceptedRecipient, 0, len(env.RcptTo))
	for i, rcpt := range env.RcptTo {
		rcptDomain := extractDomain(rcpt)
		tenant, ok := s.gw.resolveTenant(rcptDomain)
		if !ok {
			s.gw.cfg.Logger.Warn("sn360-es: smtp gateway dropping recipient with no tenant",
				slog.String("rcpt_domain", rcptDomain))
			continue
		}
		rawEmail := RawEmail{
			// Make the ID unique per recipient so multi-tenant fan-out
			// does not collide on the shared Message-ID.
			ProviderMessageID: fmt.Sprintf("%s-%d", baseID, i),
			TenantID:          tenant,
			Mailbox:           rcpt,
			Sender:            firstNonEmpty(parsed.from, s.mailFrom),
			Recipients:        []string{rcpt},
			CC:                parsed.cc,
			Subject:           parsed.subject,
			Body:              parsed.text,
			HTMLBody:          parsed.html,
			Headers:           s.gw.headersWithAuthResults(parsed.headers, dkimResult),
			ReceivedAt:        parsed.date(s.gw.cfg.now),
		}
		req, nerr := s.gw.cfg.Normalizer.Normalize(ctx, rawEmail)
		if nerr != nil {
			s.gw.cfg.Logger.Warn("sn360-es: smtp gateway normalize failed", slog.Any("error", nerr))
			continue
		}

		// A reject/defer for any recipient blocks the whole transaction.
		// Returning here is safe precisely because nothing has been
		// published yet, so a retry cannot duplicate earlier recipients.
		if decision, reason := s.gw.decide(ctx, req); decision != DecisionAccept {
			return decisionError(decision, reason)
		}

		accepted = append(accepted, acceptedRecipient{req: req, rcpt: rcpt})
	}

	if len(accepted) == 0 {
		// No recipient resolved to a known tenant — reject so the
		// sender is not misled into thinking we accepted delivery.
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "No deliverable recipients"}
	}

	// Phase 2: every recipient passed the decider; publish them all.
	for _, a := range accepted {
		if err := s.gw.publish(ctx, a.req); err != nil {
			s.gw.cfg.Logger.Warn("sn360-es: smtp gateway publish failed", slog.Any("error", err))
			// Defer: we could not enqueue the message for scanning, so
			// retry is preferable to delivering unscanned mail.
			return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "Temporary processing failure"}
		}
	}

	// Relay only the recipients we actually scanned. Recipients dropped
	// in phase 1 (no tenant / normalize failure) were never evaluated,
	// so the relay envelope must not include them — otherwise the
	// downstream store would receive mail this gateway never scanned.
	if s.gw.cfg.Deliverer != nil {
		relayEnv := env
		relayEnv.RcptTo = make([]string, len(accepted))
		for i, a := range accepted {
			relayEnv.RcptTo[i] = a.rcpt
		}
		if err := s.gw.cfg.Deliverer.Deliver(ctx, relayEnv, raw); err != nil {
			s.gw.cfg.Logger.Warn("sn360-es: smtp gateway downstream relay failed", slog.Any("error", err))
			return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "Downstream delivery temporarily unavailable"}
		}
	}

	s.gw.cfg.Logger.Info("sn360-es: smtp gateway accepted message",
		slog.String("remote", s.remoteAddr),
		slog.Int("recipients", len(accepted)),
		slog.String("dkim", dkimResult))
	return nil
}

// resolveTenant maps a recipient domain to a tenant ID via the
// configured resolver, defaulting to the domain itself.
func (g *SMTPGateway) resolveTenant(domain string) (string, bool) {
	if domain == "" {
		return "", false
	}
	if g.cfg.TenantResolver != nil {
		return g.cfg.TenantResolver(domain)
	}
	return domain, true
}

// decide runs the optional pre-delivery decider.
func (g *SMTPGateway) decide(ctx context.Context, req dto.EvaluateRequest) (DeliveryDecision, string) {
	if g.cfg.Decider == nil {
		return DecisionAccept, ""
	}
	return g.cfg.Decider.Decide(ctx, req)
}

// publish emits the evaluate.request event using the same envelope
// metadata the poller and push paths use, so downstream consumers see
// a uniform event regardless of ingress.
func (g *SMTPGateway) publish(ctx context.Context, req dto.EvaluateRequest) error {
	payload, err := marshalRequest(req)
	if err != nil {
		return err
	}
	return g.cfg.Publisher.Publish(ctx, g.cfg.Subject, payload,
		events.WithTenantID(req.TenantID),
		events.WithMessageID(req.MessageID),
		events.WithCorrelationID(req.CorrelationID),
		events.WithEventType("evaluate.request"),
	)
}

// verifyDKIM runs DKIM verification over the raw message bytes and
// returns the aggregate verdict ("pass" / "fail" / "none") for the
// synthesized Authentication-Results header. A message with at least
// one valid signature is "pass"; one or more signatures all failing is
// "fail"; no signatures present is "none".
func (g *SMTPGateway) verifyDKIM(raw []byte) string {
	opts := &dkim.VerifyOptions{
		MaxVerifications: g.cfg.MaxDKIMVerifications,
	}
	if g.cfg.DKIMLookupTXT != nil {
		opts.LookupTXT = g.cfg.DKIMLookupTXT
	}
	verifs, err := dkim.VerifyWithOptions(bytes.NewReader(raw), opts)
	if err != nil {
		// A hard verify error (e.g. malformed header block) is not a
		// signature pass; treat the message as unauthenticated.
		g.cfg.Logger.Debug("sn360-es: smtp gateway dkim verify error", slog.Any("error", err))
		return "none"
	}
	if len(verifs) == 0 {
		return "none"
	}
	for _, v := range verifs {
		if v.Err == nil {
			return "pass"
		}
	}
	return "fail"
}

// headersWithAuthResults clones the parsed headers and stamps the
// gateway's own synthesized Authentication-Results header carrying the
// DKIM verdict it just computed. The normalizer reads this header to
// populate RiskSignals, so the gateway path produces the same
// SPF/DKIM/DMARC signals as provider-sourced mail without special-casing
// the normalizer.
//
// Security: the MX gateway is the *border* MTA — it receives mail
// directly from arbitrary external senders, with no trusted relay in
// front of it. Any Authentication-Results header already present on the
// inbound message was therefore written by the (untrusted) sender, who
// can trivially forge "dkim=pass; spf=pass; dmarc=pass" to make a
// failing message look authenticated to the entire detection pipeline
// (normalizer -> RiskSignals -> AuthVerdict / ATO heuristic). Per
// RFC 7601 §5 a border receiver must remove any A-R header that does not
// carry its own authserv-id before adding its own. We do exactly that:
// drop every inbound A-R (any header-key casing) and stamp our verdict
// under our authserv-id (cfg.Domain). This differs from the poller/push
// paths, where Authentication-Results legitimately comes from the
// mailbox provider (Gmail/Outlook) — a trusted upstream — and is kept.
func (g *SMTPGateway) headersWithAuthResults(headers map[string]string, dkimResult string) map[string]string {
	out := make(map[string]string, len(headers)+1)
	for k, v := range headers {
		// Strip any sender-supplied Authentication-Results (regardless of
		// header-key casing) so a forged stamp can never reach the
		// normalizer. parseMessage canonicalizes keys, but scanning
		// case-insensitively keeps this correct for any caller.
		if strings.EqualFold(k, "Authentication-Results") {
			continue
		}
		out[k] = v
	}
	// Always stamp our own verified verdict under our authserv-id.
	out["Authentication-Results"] = fmt.Sprintf("%s; dkim=%s", g.cfg.Domain, dkimResult)
	return out
}

// parsedMessage is the extracted view of an RFC 5322 message the
// gateway needs to build a RawEmail.
type parsedMessage struct {
	headers map[string]string
	from    string
	cc      []string
	subject string
	text    string
	html    string
	dateHdr time.Time
}

// date returns the parsed Date header, falling back to now when the
// header is absent or unparseable so the checkpoint/age logic never
// sees a zero time.
func (p parsedMessage) date(now func() time.Time) time.Time {
	if p.dateHdr.IsZero() {
		return now()
	}
	return p.dateHdr
}

// parseMessage parses an RFC 5322 message into the fields the pipeline
// consumes. It extracts text/plain and text/html bodies from the
// (possibly multipart) MIME tree.
func parseMessage(raw []byte) (parsedMessage, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return parsedMessage{}, err
	}
	pm := parsedMessage{
		headers: map[string]string{},
		subject: decodeHeader(msg.Header.Get("Subject")),
	}
	for k := range msg.Header {
		// net/textproto canonicalizes header keys; collapse multi-value
		// headers to the first value (sufficient for our signal set).
		pm.headers[k] = msg.Header.Get(k)
	}
	if from := parseAddress(msg.Header.Get("From")); from != "" {
		pm.from = from
	}
	pm.cc = parseAddressList(msg.Header.Get("Cc"))
	if d, derr := msg.Header.Date(); derr == nil {
		pm.dateHdr = d.UTC()
	}

	text, html := extractBodies(msg.Header.Get("Content-Type"), msg.Header.Get("Content-Transfer-Encoding"), msg.Body)
	pm.text = text
	pm.html = html
	return pm, nil
}

// decodeTransferEncoding wraps r with a decoder for the message part's
// Content-Transfer-Encoding. base64 and quoted-printable (the two
// encodings real-world MTAs use for non-ASCII text bodies) are decoded;
// 7bit / 8bit / binary and any unrecognized value pass through
// unchanged so a mislabeled part degrades to raw bytes rather than an
// empty or corrupt body. Without this, the normalizer would receive the
// encoded blob (e.g. a base64 string) instead of the message text,
// silently degrading detection on the majority of HTML/UTF-8 mail.
func decodeTransferEncoding(r io.Reader, encoding string) io.Reader {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		// The stdlib streaming base64 decoder already skips the CRLFs
		// MIME inserts every 76 chars.
		return base64.NewDecoder(base64.StdEncoding, r)
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	default:
		return r
	}
}

// extractBodies walks the MIME tree rooted at the given Content-Type
// and returns the concatenated text/plain and text/html parts. Nested
// multiparts (multipart/alternative inside multipart/mixed) are walked
// recursively; non-text parts (attachments) are skipped.
func extractBodies(contentType, contentTransferEncoding string, body io.Reader) (text, html string) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		// Single-part message: classify by media type, default to text.
		data, _ := io.ReadAll(decodeTransferEncoding(body, contentTransferEncoding))
		if strings.EqualFold(mediaType, "text/html") {
			return "", string(data)
		}
		return string(data), ""
	}
	boundary := params["boundary"]
	if boundary == "" {
		data, _ := io.ReadAll(body)
		return string(data), ""
	}
	mr := multipart.NewReader(body, boundary)
	var textBuf, htmlBuf strings.Builder
	for {
		part, perr := mr.NextPart()
		if perr != nil {
			break // io.EOF or malformed trailing boundary; stop walking.
		}
		partType, partParams, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
		partCTE := part.Header.Get("Content-Transfer-Encoding")
		switch {
		case strings.HasPrefix(partType, "multipart/"):
			// A multipart container itself is never transfer-encoded
			// (RFC 2045 §6.4); its leaf parts carry their own CTE.
			t, h := extractBodies(part.Header.Get("Content-Type"), "", part)
			textBuf.WriteString(t)
			htmlBuf.WriteString(h)
		case strings.EqualFold(partType, "text/plain"):
			data, _ := io.ReadAll(decodeTransferEncoding(part, partCTE))
			textBuf.Write(data)
		case strings.EqualFold(partType, "text/html"):
			data, _ := io.ReadAll(decodeTransferEncoding(part, partCTE))
			htmlBuf.Write(data)
		default:
			_ = partParams
			// Attachment / inline binary: skip the body for scanning.
		}
		_ = part.Close()
	}
	return textBuf.String(), htmlBuf.String()
}

// messageID returns a stable per-message identifier derived from the
// RFC 5322 Message-ID header, falling back to a content hash of the raw
// message when the header is absent (some MTAs add it only on relay).
//
// The fallback must be deterministic across SMTP retries: the per-
// recipient event IDs the gateway publishes are derived from this base
// ID, and NATS dedup collapses re-published recipients only when those
// IDs are identical on retry. A random fallback (e.g. a UUID) would
// differ on every retry, so if a multi-recipient message lacking a
// Message-ID partially published and then deferred, the sending MTA's
// retry would re-publish the already-committed recipients under fresh
// IDs and defeat dedup. Hashing the raw bytes keeps the ID stable for
// the identical message the MTA resends.
func messageID(headers map[string]string, raw []byte) string {
	if id := strings.TrimSpace(headerLookup(headers, "Message-ID")); id != "" {
		return strings.Trim(id, "<>")
	}
	return fmt.Sprintf("smtp-%x", sha256.Sum256(raw))
}

// parseAddress parses a single RFC 5322 address, returning the bare
// addr-spec (no display name). Falls back to the trimmed raw value on
// parse failure so malformed-but-present senders are not lost.
func parseAddress(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if addr, err := mail.ParseAddress(raw); err == nil {
		return addr.Address
	}
	return raw
}

// parseAddressList parses a comma-separated address list into bare
// addr-specs, dropping entries that fail to parse.
func parseAddressList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	addrs, err := mail.ParseAddressList(raw)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.Address)
	}
	return out
}

// decodeHeader decodes RFC 2047 encoded-word headers (e.g. UTF-8
// Subject lines) to their plain-text form, returning the raw value
// when no decoding is needed or decoding fails.
func decodeHeader(raw string) string {
	dec := new(mime.WordDecoder)
	if out, err := dec.DecodeHeader(raw); err == nil {
		return out
	}
	return raw
}

// decisionError maps a non-accept decision onto the SMTP reply the
// gateway returns to the sending MTA.
func decisionError(decision DeliveryDecision, reason string) error {
	if reason == "" {
		reason = "Message rejected by policy"
	}
	switch decision {
	case DecisionDefer:
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 7, 1}, Message: reason}
	case DecisionReject:
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: reason}
	default:
		return nil
	}
}

// addrString renders a net.Addr defensively (nil-safe).
func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}
