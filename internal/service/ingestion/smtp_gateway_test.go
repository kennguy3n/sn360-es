package ingestion

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"testing"
	"time"

	dkimlib "github.com/emersion/go-msgauth/dkim"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// startGateway binds an ephemeral listener, runs the gateway on it, and
// returns the dial address plus a stop func. The caller sends mail with
// a plain net/smtp client.
func startGateway(t *testing.T, cfg SMTPGatewayConfig) (addr string, stop func()) {
	t.Helper()
	g, err := NewSMTPGateway(cfg)
	if err != nil {
		t.Fatalf("NewSMTPGateway: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = g.serve(ctx, ln)
	}()
	return ln.Addr().String(), func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("gateway did not shut down within 5s")
		}
	}
}

// sendRaw delivers a raw RFC 5322 message through a plaintext SMTP
// transaction using the low-level client so the test controls each
// command (net/smtp.SendMail would opportunistically STARTTLS/AUTH).
func sendRaw(t *testing.T, addr, from string, to []string, msg string) error {
	t.Helper()
	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Hello("client.test"); err != nil {
		t.Fatalf("hello: %v", err)
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func (b *capturingBus) snapshot() []capturedPublish {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]capturedPublish(nil), b.publishes...)
}

func TestSMTPGateway_Data_PublishesEvaluateRequestPerRecipient(t *testing.T) {
	bus := &capturingBus{}
	addr, stop := startGateway(t, SMTPGatewayConfig{
		Publisher: bus,
		Logger:    discardLogger(),
		// recipient domain -> tenant identity (default behaviour)
	})
	defer stop()

	msg := "From: Alice <alice@sender.example>\r\n" +
		"To: bob@acme.example\r\n" +
		"Subject: Quarterly invoice\r\n" +
		"Message-ID: <abc123@sender.example>\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Please review the attached invoice.\r\n"

	if err := sendRaw(t, addr, "alice@sender.example", []string{"bob@acme.example", "carol@acme.example"}, msg); err != nil {
		t.Fatalf("send: %v", err)
	}

	pubs := waitForPublishes(t, bus, 2)
	if len(pubs) != 2 {
		t.Fatalf("expected 2 published events, got %d", len(pubs))
	}
	for _, p := range pubs {
		if p.Subject != "es.evaluate.request" {
			t.Errorf("subject = %q, want es.evaluate.request", p.Subject)
		}
		if p.Opts.TenantID != "acme.example" {
			t.Errorf("tenant = %q, want acme.example", p.Opts.TenantID)
		}
		req := decodeRequest(t, p.Data)
		if req.Sender != "alice@sender.example" {
			t.Errorf("sender = %q", req.Sender)
		}
		if req.Subject != "Quarterly invoice" {
			t.Errorf("subject header = %q", req.Subject)
		}
		if !strings.Contains(req.Body, "review the attached invoice") {
			t.Errorf("body = %q", req.Body)
		}
	}
	// Per-recipient IDs must be unique so multi-tenant fan-out does not
	// collide on the shared Message-ID.
	if pubs[0].Opts.MessageID == pubs[1].Opts.MessageID {
		t.Errorf("expected distinct message IDs, both = %q", pubs[0].Opts.MessageID)
	}
}

func TestSMTPGateway_Data_ExtractsHTMLFromMultipart(t *testing.T) {
	bus := &capturingBus{}
	addr, stop := startGateway(t, SMTPGatewayConfig{Publisher: bus, Logger: discardLogger()})
	defer stop()

	msg := "From: news@sender.example\r\n" +
		"To: bob@acme.example\r\n" +
		"Subject: Hi\r\n" +
		"Message-ID: <m1@sender.example>\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=\"BOUND\"\r\n" +
		"\r\n" +
		"--BOUND\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"plain version\r\n" +
		"--BOUND\r\n" +
		"Content-Type: text/html\r\n\r\n" +
		"<p>html <b>version</b></p>\r\n" +
		"--BOUND--\r\n"

	if err := sendRaw(t, addr, "news@sender.example", []string{"bob@acme.example"}, msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	pubs := waitForPublishes(t, bus, 1)
	req := decodeRequest(t, pubs[0].Data)
	// The normalizer prefers the plain body when present.
	if !strings.Contains(req.Body, "plain version") {
		t.Errorf("body = %q, want plain text part", req.Body)
	}
}

func TestSMTPGateway_DKIM_PassFoldsIntoAuthResults(t *testing.T) {
	priv, txt := genDKIMKey(t)
	lookup := func(domain string) ([]string, error) {
		if domain == "sel._domainkey.sender.example" {
			return []string{txt}, nil
		}
		return nil, fmt.Errorf("no record for %s", domain)
	}

	signed := signMessage(t, priv, "sender.example", "sel",
		"From: alice@sender.example\r\n"+
			"To: bob@acme.example\r\n"+
			"Subject: Signed\r\n"+
			"Message-ID: <signed@sender.example>\r\n"+
			"\r\n"+
			"signed body\r\n")

	bus := &capturingBus{}
	addr, stop := startGateway(t, SMTPGatewayConfig{
		Publisher:     bus,
		Logger:        discardLogger(),
		DKIMLookupTXT: lookup,
	})
	defer stop()

	if err := sendRaw(t, addr, "alice@sender.example", []string{"bob@acme.example"}, signed); err != nil {
		t.Fatalf("send: %v", err)
	}
	pubs := waitForPublishes(t, bus, 1)
	req := decodeRequest(t, pubs[0].Data)
	if req.Signals.DKIMResult != "pass" {
		t.Errorf("DKIMResult = %q, want pass", req.Signals.DKIMResult)
	}
}

func TestSMTPGateway_DKIM_UnsignedIsNone(t *testing.T) {
	bus := &capturingBus{}
	addr, stop := startGateway(t, SMTPGatewayConfig{Publisher: bus, Logger: discardLogger()})
	defer stop()

	msg := "From: alice@sender.example\r\nTo: bob@acme.example\r\nSubject: Plain\r\nMessage-ID: <p@x>\r\n\r\nbody\r\n"
	if err := sendRaw(t, addr, "alice@sender.example", []string{"bob@acme.example"}, msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	pubs := waitForPublishes(t, bus, 1)
	req := decodeRequest(t, pubs[0].Data)
	if req.Signals.DKIMResult != "" && req.Signals.DKIMResult != "none" {
		t.Errorf("DKIMResult = %q, want none/empty", req.Signals.DKIMResult)
	}
}

// TestSMTPGateway_ForgedAuthResults_Stripped guards the border-MTA
// hardening: the gateway receives mail directly from untrusted senders,
// so a sender-supplied Authentication-Results header must never reach
// the normalizer. Here an UNSIGNED message arrives pre-stamped with a
// forged "dkim=pass; spf=pass; dmarc=pass". The pipeline must see the
// gateway's own verdict (dkim=none, no spf/dmarc), not the forgery —
// otherwise a phishing message could spoof full authentication and
// suppress the ATO heuristic.
func TestSMTPGateway_ForgedAuthResults_Stripped(t *testing.T) {
	bus := &capturingBus{}
	addr, stop := startGateway(t, SMTPGatewayConfig{Publisher: bus, Logger: discardLogger()})
	defer stop()

	// No valid DKIM signature, but the sender forges a passing A-R stamp.
	msg := "From: attacker@evil.example\r\n" +
		"To: bob@acme.example\r\n" +
		"Subject: Totally legit\r\n" +
		"Message-ID: <forged@evil.example>\r\n" +
		"Authentication-Results: evil.example; dkim=pass; spf=pass; dmarc=pass\r\n" +
		"\r\n" +
		"please reset your password\r\n"
	if err := sendRaw(t, addr, "attacker@evil.example", []string{"bob@acme.example"}, msg); err != nil {
		t.Fatalf("send: %v", err)
	}

	pubs := waitForPublishes(t, bus, 1)
	req := decodeRequest(t, pubs[0].Data)
	if req.Signals.DKIMResult == "pass" {
		t.Errorf("DKIMResult = %q, forged dkim=pass leaked into the pipeline", req.Signals.DKIMResult)
	}
	if req.Signals.SPFResult == "pass" {
		t.Errorf("SPFResult = %q, forged spf=pass leaked into the pipeline", req.Signals.SPFResult)
	}
	if req.Signals.DMARCResult == "pass" {
		t.Errorf("DMARCResult = %q, forged dmarc=pass leaked into the pipeline", req.Signals.DMARCResult)
	}
}

// TestSMTPGateway_NullReversePath_Accepted guards bounce / DSN
// handling. A message with the null reverse-path MAIL FROM:<>
// (RFC 5321 §4.5.5) is a perfectly valid transaction — it is how
// every bounce and delivery-status notification is sent. The earlier
// `mailFrom == ""` sequencing guard rejected these with a 503 "Bad
// sequence" because the null sender leaves mailFrom empty, silently
// bouncing a large fraction of real MX traffic. The transaction must
// be accepted and the message published for scanning, with the
// envelope sender recorded as empty.
func TestSMTPGateway_NullReversePath_Accepted(t *testing.T) {
	bus := &capturingBus{}
	addr, stop := startGateway(t, SMTPGatewayConfig{Publisher: bus, Logger: discardLogger()})
	defer stop()

	// A typical bounce: null reverse-path, From: a mailer-daemon.
	msg := "From: MAILER-DAEMON@acme.example\r\n" +
		"To: alice@acme.example\r\n" +
		"Subject: Undelivered Mail Returned to Sender\r\n" +
		"Message-ID: <bounce@acme.example>\r\n" +
		"\r\n" +
		"Delivery to the following recipient failed permanently.\r\n"
	// from == "" makes the stdlib client emit MAIL FROM:<>.
	if err := sendRaw(t, addr, "", []string{"alice@acme.example"}, msg); err != nil {
		t.Fatalf("bounce send rejected, want accepted: %v", err)
	}

	pubs := waitForPublishes(t, bus, 1)
	req := decodeRequest(t, pubs[0].Data)
	// The envelope sender is the null reverse-path; the published
	// request falls back to the From: header for the logical sender,
	// but the transaction itself must have been accepted.
	if req.MessageID == "" {
		t.Errorf("published request has empty MessageID; bounce was not normalized as expected")
	}
}

func TestSMTPGateway_PreDeliveryReject_BouncesMessage(t *testing.T) {
	bus := &capturingBus{}
	addr, stop := startGateway(t, SMTPGatewayConfig{
		Publisher: bus,
		Logger:    discardLogger(),
		Decider: deciderFunc(func(context.Context, dto.EvaluateRequest) (DeliveryDecision, string) {
			return DecisionReject, "blocked phishing"
		}),
	})
	defer stop()

	msg := "From: a@sender.example\r\nTo: bob@acme.example\r\nSubject: x\r\nMessage-ID: <r@x>\r\n\r\nbody\r\n"
	err := sendRaw(t, addr, "a@sender.example", []string{"bob@acme.example"}, msg)
	if err == nil {
		t.Fatal("expected rejection error, got nil")
	}
	if !strings.Contains(err.Error(), "550") {
		t.Errorf("error = %v, want 550 reject", err)
	}
	if got := bus.snapshot(); len(got) != 0 {
		t.Errorf("rejected message should not publish, got %d events", len(got))
	}
}

// TestSMTPGateway_PreDeliveryRejectMidLoop_PublishesNothing guards the
// two-phase decision/publish split: a reject on the SECOND recipient
// must not leak an event for the first. Before the fix the loop
// published recipient 0, then returned 550 on recipient 1 — so the
// pipeline saw a message the gateway told the sender it had refused,
// and the MTA retry re-published it.
func TestSMTPGateway_PreDeliveryRejectMidLoop_PublishesNothing(t *testing.T) {
	bus := &capturingBus{}
	addr, stop := startGateway(t, SMTPGatewayConfig{
		Publisher: bus,
		Logger:    discardLogger(),
		Decider: deciderFunc(func(_ context.Context, req dto.EvaluateRequest) (DeliveryDecision, string) {
			if req.Recipient == "carol@acme.example" {
				return DecisionReject, "blocked phishing"
			}
			return DecisionAccept, ""
		}),
	})
	defer stop()

	msg := "From: a@sender.example\r\nTo: bob@acme.example\r\nSubject: x\r\nMessage-ID: <mid@x>\r\n\r\nbody\r\n"
	// bob is accepted, carol is rejected; the whole transaction must fail.
	err := sendRaw(t, addr, "a@sender.example", []string{"bob@acme.example", "carol@acme.example"}, msg)
	if err == nil {
		t.Fatal("expected rejection error, got nil")
	}
	if !strings.Contains(err.Error(), "550") {
		t.Errorf("error = %v, want 550 reject", err)
	}
	// Give any erroneously-published event time to land before asserting.
	time.Sleep(50 * time.Millisecond)
	if got := bus.snapshot(); len(got) != 0 {
		t.Errorf("a mid-loop reject must publish nothing, got %d events", len(got))
	}
}

// TestSMTPGateway_Relay_OnlyScannedRecipients guards that the relay
// envelope contains only the recipients the gateway actually scanned.
// A recipient that resolves to no tenant is dropped from scanning, so
// it must also be dropped from the relay envelope — otherwise the
// downstream store receives mail this gateway never evaluated.
func TestSMTPGateway_Relay_OnlyScannedRecipients(t *testing.T) {
	bus := &capturingBus{}
	relay := &recordingDeliverer{}
	addr, stop := startGateway(t, SMTPGatewayConfig{
		Publisher: bus,
		Logger:    discardLogger(),
		Deliverer: relay,
		TenantResolver: func(domain string) (string, bool) {
			if domain == "acme.example" {
				return "acme.example", true
			}
			return "", false
		},
	})
	defer stop()

	msg := "From: a@sender.example\r\nTo: bob@acme.example\r\nSubject: x\r\nMessage-ID: <rel@x>\r\n\r\nbody\r\n"
	if err := sendRaw(t, addr, "a@sender.example",
		[]string{"bob@acme.example", "stranger@unknown.example"}, msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	waitForPublishes(t, bus, 1)
	if got := relay.count(); got != 1 {
		t.Fatalf("deliverer called %d times, want 1", got)
	}
	env := relay.lastEnv()
	if len(env.RcptTo) != 1 || env.RcptTo[0] != "bob@acme.example" {
		t.Errorf("relay RcptTo = %v, want [bob@acme.example] only (stranger dropped)", env.RcptTo)
	}
}

// TestSMTPGateway_Data_DecodesBase64Body guards that base64
// Content-Transfer-Encoding bodies are decoded before reaching the
// normalizer. Before the fix the raw base64 blob was passed through,
// garbling the text and degrading detection.
func TestSMTPGateway_Data_DecodesBase64Body(t *testing.T) {
	bus := &capturingBus{}
	addr, stop := startGateway(t, SMTPGatewayConfig{Publisher: bus, Logger: discardLogger()})
	defer stop()

	plaintext := "Wire $48,000 to the new account today."
	encoded := base64.StdEncoding.EncodeToString([]byte(plaintext))
	msg := "From: a@sender.example\r\n" +
		"To: bob@acme.example\r\n" +
		"Subject: Urgent\r\n" +
		"Message-ID: <b64@x>\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		encoded + "\r\n"

	if err := sendRaw(t, addr, "a@sender.example", []string{"bob@acme.example"}, msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	pubs := waitForPublishes(t, bus, 1)
	req := decodeRequest(t, pubs[0].Data)
	if !strings.Contains(req.Body, "Wire $48,000 to the new account") {
		t.Errorf("base64 body not decoded: %q", req.Body)
	}
}

// TestSMTPGateway_Data_DecodesQuotedPrintableHTML guards quoted-printable
// decoding of an HTML part inside a multipart message.
func TestSMTPGateway_Data_DecodesQuotedPrintableHTML(t *testing.T) {
	bus := &capturingBus{}
	addr, stop := startGateway(t, SMTPGatewayConfig{Publisher: bus, Logger: discardLogger()})
	defer stop()

	// "Pay =E2=82=AC50 now" decodes to "Pay €50 now"; the soft line break
	// "=\r\n" must be stripped by the decoder.
	msg := "From: a@sender.example\r\n" +
		"To: bob@acme.example\r\n" +
		"Subject: QP\r\n" +
		"Message-ID: <qp@x>\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=\"B\"\r\n" +
		"\r\n" +
		"--B\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"\r\n" +
		"<p>Pay =E2=82=AC50 =\r\nnow</p>\r\n" +
		"--B--\r\n"

	if err := sendRaw(t, addr, "a@sender.example", []string{"bob@acme.example"}, msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	pubs := waitForPublishes(t, bus, 1)
	req := decodeRequest(t, pubs[0].Data)
	// The normalizer strips HTML into the plaintext Body; a correctly
	// decoded QP part yields "Pay €50 now" (soft break removed, =E2=82=AC
	// → €).
	if !strings.Contains(req.Body, "Pay \u20ac50 now") {
		t.Errorf("quoted-printable HTML not decoded: %q", req.Body)
	}
}

func TestSMTPGateway_NoTenant_RejectsRecipients(t *testing.T) {
	bus := &capturingBus{}
	addr, stop := startGateway(t, SMTPGatewayConfig{
		Publisher: bus,
		Logger:    discardLogger(),
		TenantResolver: func(domain string) (string, bool) {
			return "", false // no domain maps to a tenant
		},
	})
	defer stop()

	msg := "From: a@sender.example\r\nTo: bob@unknown.example\r\nSubject: x\r\nMessage-ID: <n@x>\r\n\r\nbody\r\n"
	err := sendRaw(t, addr, "a@sender.example", []string{"bob@unknown.example"}, msg)
	if err == nil {
		t.Fatal("expected 550 for no deliverable recipients")
	}
	if !strings.Contains(err.Error(), "550") {
		t.Errorf("error = %v, want 550", err)
	}
}

func TestSMTPGateway_RelaysAcceptedMessage(t *testing.T) {
	bus := &capturingBus{}
	relay := &recordingDeliverer{}
	addr, stop := startGateway(t, SMTPGatewayConfig{
		Publisher: bus,
		Logger:    discardLogger(),
		Deliverer: relay,
	})
	defer stop()

	msg := "From: a@sender.example\r\nTo: bob@acme.example\r\nSubject: x\r\nMessage-ID: <d@x>\r\n\r\nbody\r\n"
	if err := sendRaw(t, addr, "a@sender.example", []string{"bob@acme.example"}, msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	waitForPublishes(t, bus, 1)
	if got := relay.count(); got != 1 {
		t.Fatalf("deliverer called %d times, want 1", got)
	}
	env := relay.lastEnv()
	if env.MailFrom != "a@sender.example" {
		t.Errorf("relay MailFrom = %q", env.MailFrom)
	}
	if len(env.RcptTo) != 1 || env.RcptTo[0] != "bob@acme.example" {
		t.Errorf("relay RcptTo = %v", env.RcptTo)
	}
}

// TestSMTPGateway_RequireTLS_RejectsPlaintextMail verifies that with
// RequireTLS set, MAIL FROM on a still-plaintext session (the client
// never issued STARTTLS) is rejected with 530 and nothing is published.
func TestSMTPGateway_RequireTLS_RejectsPlaintextMail(t *testing.T) {
	bus := &capturingBus{}
	addr, stop := startGateway(t, SMTPGatewayConfig{
		Publisher:  bus,
		Logger:     discardLogger(),
		TLSConfig:  genServerTLS(t),
		RequireTLS: true,
	})
	defer stop()

	msg := "From: a@sender.example\r\nTo: bob@acme.example\r\nSubject: x\r\nMessage-ID: <p@x>\r\n\r\nbody\r\n"
	err := sendRawSTARTTLS(t, addr, "a@sender.example", []string{"bob@acme.example"}, msg, false)
	if err == nil {
		t.Fatal("expected MAIL FROM rejection on plaintext session")
	}
	if !strings.Contains(err.Error(), "530") {
		t.Errorf("error = %v, want 530", err)
	}
	if got := bus.snapshot(); len(got) != 0 {
		t.Errorf("expected 0 publishes on rejected plaintext mail, got %d", len(got))
	}
}

// TestSMTPGateway_STARTTLS_AllowsMailAndMarksEnvelopeTLS guards the
// STARTTLS upgrade path end-to-end: after the client issues STARTTLS,
// MAIL FROM must succeed under RequireTLS and the envelope handed to the
// pipeline/relay must record TLS=true. go-smtp destroys the session on
// STARTTLS (conn.go:947-949) and re-invokes the backend's NewSession on
// the mandatory post-STARTTLS EHLO with the upgraded connection, so the
// session's cached TLS state correctly reflects the upgrade. A stale
// false (the failure mode a cached bool would exhibit if go-smtp reused
// the session) would surface here as a 530 rejection and TLS=false.
func TestSMTPGateway_STARTTLS_AllowsMailAndMarksEnvelopeTLS(t *testing.T) {
	bus := &capturingBus{}
	relay := &recordingDeliverer{}
	addr, stop := startGateway(t, SMTPGatewayConfig{
		Publisher:  bus,
		Logger:     discardLogger(),
		Deliverer:  relay,
		TLSConfig:  genServerTLS(t),
		RequireTLS: true,
	})
	defer stop()

	msg := "From: a@sender.example\r\nTo: bob@acme.example\r\nSubject: x\r\nMessage-ID: <s@x>\r\n\r\nbody\r\n"
	if err := sendRawSTARTTLS(t, addr, "a@sender.example", []string{"bob@acme.example"}, msg, true); err != nil {
		t.Fatalf("send over STARTTLS: %v", err)
	}

	waitForPublishes(t, bus, 1)
	if got := relay.count(); got != 1 {
		t.Fatalf("deliverer called %d times, want 1", got)
	}
	if !relay.lastEnv().TLS {
		t.Error("relay envelope TLS = false, want true after STARTTLS upgrade")
	}
}

// --- helpers ---

func waitForPublishes(t *testing.T, bus *capturingBus, want int) []capturedPublish {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := bus.snapshot(); len(got) >= want {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	got := bus.snapshot()
	t.Fatalf("timed out waiting for %d publishes, got %d", want, len(got))
	return got
}

func decodeRequest(t *testing.T, data []byte) dto.EvaluateRequest {
	t.Helper()
	var req dto.EvaluateRequest
	if err := json.Unmarshal(data, &req); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	return req
}

type deciderFunc func(context.Context, dto.EvaluateRequest) (DeliveryDecision, string)

func (f deciderFunc) Decide(ctx context.Context, req dto.EvaluateRequest) (DeliveryDecision, string) {
	return f(ctx, req)
}

type recordingDeliverer struct {
	mu   sync.Mutex
	envs []SMTPEnvelope
}

func (d *recordingDeliverer) Deliver(_ context.Context, env SMTPEnvelope, _ []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.envs = append(d.envs, env)
	return nil
}

func (d *recordingDeliverer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.envs)
}

func (d *recordingDeliverer) lastEnv() SMTPEnvelope {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.envs[len(d.envs)-1]
}

// genDKIMKey returns a fresh RSA key and the matching DKIM DNS TXT
// record value (v=DKIM1; k=rsa; p=<base64 DER>).
func genDKIMKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	return priv, "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
}

// signMessage DKIM-signs msg with priv and returns the signed message.
func signMessage(t *testing.T, priv crypto.Signer, domain, selector, msg string) string {
	t.Helper()
	var buf strings.Builder
	opts := &dkimlib.SignOptions{
		Domain:     domain,
		Selector:   selector,
		Signer:     priv,
		Hash:       crypto.SHA256,
		HeaderKeys: []string{"From", "To", "Subject", "Message-ID"},
	}
	if err := dkimlib.Sign(&buf, strings.NewReader(msg), opts); err != nil {
		t.Fatalf("dkim sign: %v", err)
	}
	return buf.String()
}

// sendRawSTARTTLS drives a transaction with the low-level client,
// optionally upgrading the connection via STARTTLS before MAIL FROM.
// The client trusts the gateway's self-signed cert (InsecureSkipVerify)
// since the test cert is generated per run.
func sendRawSTARTTLS(t *testing.T, addr, from string, to []string, msg string, startTLS bool) error {
	t.Helper()
	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Hello("client.test"); err != nil {
		t.Fatalf("hello: %v", err)
	}
	if startTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			t.Fatal("server did not advertise STARTTLS")
		}
		if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil { //nolint:gosec // self-signed test cert
			t.Fatalf("starttls: %v", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// genServerTLS builds a *tls.Config with a fresh self-signed cert valid
// for 127.0.0.1/localhost so the gateway can offer STARTTLS in tests.
func genServerTLS(t *testing.T) *tls.Config {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		MinVersion:   tls.VersionTLS12,
	}
}
