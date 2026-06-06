package ingestion

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
