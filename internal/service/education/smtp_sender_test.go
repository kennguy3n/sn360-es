package education

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/smtp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// fakeSMTPClient is a no-network smtpClient that records every method
// call and the bytes written to Data(). It returns errors when its
// `fail*` fields are set so tests can exercise the unhappy paths.
type fakeSMTPClient struct {
	mu          sync.Mutex
	helloCalled string
	starttls    bool
	extension   bool
	authCalled  bool
	mailFrom    string
	rcptTo      string
	body        strings.Builder
	closed      bool
	quitCalled  bool

	failHello, failStartTLS, failAuth                 error
	failMail, failRcpt, failData, failWrite, failQuit error
	hasStartTLS                                       bool
	// has8BITMIME defaults to true so existing tests preserve the
	// 8bit Content-Transfer-Encoding behaviour. Tests that exercise
	// the quoted-printable fallback can flip this to false.
	has8BITMIME bool
}

func (f *fakeSMTPClient) Hello(localName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.helloCalled = localName
	return f.failHello
}
func (f *fakeSMTPClient) Extension(ext string) (bool, string) {
	switch ext {
	case "STARTTLS":
		f.extension = true
		return f.hasStartTLS, ""
	case "8BITMIME":
		return f.has8BITMIME, ""
	}
	return false, ""
}
func (f *fakeSMTPClient) StartTLS(_ *tls.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starttls = true
	return f.failStartTLS
}
func (f *fakeSMTPClient) Auth(_ smtp.Auth) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authCalled = true
	return f.failAuth
}
func (f *fakeSMTPClient) Mail(from string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mailFrom = from
	return f.failMail
}
func (f *fakeSMTPClient) Rcpt(to string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rcptTo = to
	return f.failRcpt
}
func (f *fakeSMTPClient) Data() (writeCloser, error) {
	if f.failData != nil {
		return nil, f.failData
	}
	return &fakeWriter{parent: f}, nil
}
func (f *fakeSMTPClient) Quit() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.quitCalled = true
	return f.failQuit
}
func (f *fakeSMTPClient) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

// fakeWriter buffers writes and respects the parent's failWrite.
type fakeWriter struct {
	parent *fakeSMTPClient
}

func (w *fakeWriter) Write(p []byte) (int, error) {
	if w.parent.failWrite != nil {
		return 0, w.parent.failWrite
	}
	w.parent.mu.Lock()
	defer w.parent.mu.Unlock()
	return w.parent.body.Write(p)
}
func (w *fakeWriter) Close() error { return nil }

// senderWithFake constructs an SMTPSender whose dialer returns the
// supplied fake. The returned function lets the test mutate the fake
// between dials if needed.
func senderWithFake(t *testing.T, cfg SMTPConfig, fake *fakeSMTPClient) *SMTPSender {
	t.Helper()
	if cfg.Host == "" {
		cfg.Host = "relay.example.com"
	}
	if cfg.From == "" {
		cfg.From = "security@tenant.example.com"
	}
	s, err := NewSMTPSender(cfg)
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	s.dialer = func(_ context.Context, _ SMTPConfig) (smtpClient, error) {
		return fake, nil
	}
	return s
}

func newRendered() dto.RenderedSimulation {
	return dto.RenderedSimulation{
		TemplateID:    "tpl-1",
		Subject:       "Action required",
		Body:          "<p>Please verify your account.</p>",
		SenderDisplay: "Security Team",
		SenderDomain:  "tenant.example.com",
		LandingPage:   "https://example.com/learn",
	}
}

func newTarget() SimulationTarget {
	return SimulationTarget{
		UserHash:     "u-1",
		MailboxAlias: "alice+sim@tenant.example.com",
		DisplayName:  "Alice",
	}
}

func TestNewSMTPSender_RequiresHostAndFrom(t *testing.T) {
	if _, err := NewSMTPSender(SMTPConfig{}); err == nil {
		t.Errorf("expected error for missing host")
	}
	if _, err := NewSMTPSender(SMTPConfig{Host: "relay"}); err == nil {
		t.Errorf("expected error for missing from")
	}
	s, err := NewSMTPSender(SMTPConfig{Host: "relay", From: "a@b"})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	if s.cfg.Port != 587 {
		t.Errorf("default port = %d, want 587", s.cfg.Port)
	}
	if s.cfg.Timeout != 10*time.Second {
		t.Errorf("default timeout = %s, want 10s", s.cfg.Timeout)
	}
}

func TestSend_HappyPath_RFC822EnvelopeAndCommands(t *testing.T) {
	fake := &fakeSMTPClient{hasStartTLS: true, has8BITMIME: true}
	s := senderWithFake(t, SMTPConfig{
		StartTLS: true,
		User:     "alice",
		Password: "secret",
	}, fake)

	err := s.Send(context.Background(), newTarget(), newRendered())
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	if !fake.starttls {
		t.Errorf("expected STARTTLS upgrade")
	}
	if !fake.authCalled {
		t.Errorf("expected AUTH when user/password set")
	}
	if fake.mailFrom != "security@tenant.example.com" {
		t.Errorf("MAIL FROM = %q", fake.mailFrom)
	}
	if fake.rcptTo != "alice+sim@tenant.example.com" {
		t.Errorf("RCPT TO = %q", fake.rcptTo)
	}
	if !fake.quitCalled {
		t.Errorf("expected QUIT")
	}
	if !fake.closed {
		t.Errorf("expected Close on defer")
	}

	body := fake.body.String()
	for _, want := range []string{
		"From: Security Team <security@tenant.example.com>",
		"To: Alice <alice+sim@tenant.example.com>",
		"Subject: Action required",
		"Content-Type: text/html; charset=UTF-8",
		"X-SN360-Simulation: true",
		"X-SN360-Template: tpl-1",
		"<p>Please verify your account.</p>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\nbody:\n%s", want, body)
		}
	}
}

func TestSend_RejectsMissingTargetFields(t *testing.T) {
	s := senderWithFake(t, SMTPConfig{}, &fakeSMTPClient{})
	tests := []struct {
		name     string
		target   SimulationTarget
		rendered dto.RenderedSimulation
	}{
		{"no mailbox", SimulationTarget{}, newRendered()},
		{"no subject", newTarget(), dto.RenderedSimulation{Body: "x"}},
		{"no body", newTarget(), dto.RenderedSimulation{Subject: "x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := s.Send(context.Background(), tt.target, tt.rendered); err == nil {
				t.Errorf("expected error")
			}
		})
	}
}

func TestSend_SkipsAuthWhenNoUser(t *testing.T) {
	fake := &fakeSMTPClient{hasStartTLS: false}
	s := senderWithFake(t, SMTPConfig{StartTLS: true}, fake)
	if err := s.Send(context.Background(), newTarget(), newRendered()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if fake.authCalled {
		t.Errorf("expected no AUTH when user is empty")
	}
	if fake.starttls {
		t.Errorf("expected no STARTTLS when server does not advertise it")
	}
}

func TestSend_PropagatesEachStageError(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*fakeSMTPClient)
		want string
	}{
		{"HELO", func(f *fakeSMTPClient) { f.failHello = errors.New("helo-fail") }, "HELO"},
		{"AUTH", func(f *fakeSMTPClient) { f.failAuth = errors.New("auth-fail") }, "AUTH"},
		{"MAIL", func(f *fakeSMTPClient) { f.failMail = errors.New("mail-fail") }, "MAIL FROM"},
		{"RCPT", func(f *fakeSMTPClient) { f.failRcpt = errors.New("rcpt-fail") }, "RCPT TO"},
		{"DATA", func(f *fakeSMTPClient) { f.failData = errors.New("data-fail") }, "DATA"},
		{"BODY", func(f *fakeSMTPClient) { f.failWrite = errors.New("write-fail") }, "body"},
		{"QUIT", func(f *fakeSMTPClient) { f.failQuit = errors.New("quit-fail") }, "QUIT"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeSMTPClient{}
			tt.mod(fake)
			s := senderWithFake(t, SMTPConfig{User: "u", Password: "p"}, fake)
			err := s.Send(context.Background(), newTarget(), newRendered())
			if err == nil {
				t.Fatalf("expected error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.want)
			}
		})
	}
}

func TestSend_PropagatesDialError(t *testing.T) {
	s, err := NewSMTPSender(SMTPConfig{Host: "relay", From: "a@b"})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	s.dialer = func(_ context.Context, _ SMTPConfig) (smtpClient, error) {
		return nil, errors.New("dial-fail")
	}
	err = s.Send(context.Background(), newTarget(), newRendered())
	if err == nil || !strings.Contains(err.Error(), "smtp dial") {
		t.Fatalf("expected smtp dial error, got %v", err)
	}
}

func TestBuildMessage_NonASCIISubjectIsBase64Encoded(t *testing.T) {
	rendered := newRendered()
	rendered.Subject = "Atención: verifica tu cuenta"
	rendered.SenderDisplay = "Seguridad técnica"
	msg := buildMessage("security@tenant.example.com", newTarget(), rendered, "8bit")
	body := string(msg)
	if !strings.Contains(body, "Subject: =?UTF-8?B?") {
		t.Errorf("expected MIME-encoded subject, got body:\n%s", body)
	}
	if !strings.Contains(body, "From: =?UTF-8?B?") {
		t.Errorf("expected MIME-encoded display, got body:\n%s", body)
	}
}

func TestBuildMessage_QuotedPrintableFallback(t *testing.T) {
	rendered := newRendered()
	// Non-ASCII body bytes that quoted-printable must escape:
	// 'é' is 0xC3 0xA9, which encodes to =C3=A9.
	rendered.Body = "<p>Café acción</p>"
	msg := buildMessage("security@tenant.example.com", newTarget(), rendered, "quoted-printable")
	body := string(msg)
	if !strings.Contains(body, "Content-Transfer-Encoding: quoted-printable") {
		t.Errorf("expected CTE header to be quoted-printable, got body:\n%s", body)
	}
	if !strings.Contains(body, "=C3=A9") {
		t.Errorf("expected quoted-printable-escaped UTF-8 body, got body:\n%s", body)
	}
	// And the original raw UTF-8 byte must NOT appear, since it
	// would have to come through as 0xC3 0xA9 — confirm the
	// printable escape replaced it.
	if strings.Contains(body, "Café") {
		t.Errorf("body still contains raw UTF-8 instead of QP escape:\n%s", body)
	}
}

func TestSend_FallsBackToQuotedPrintableWhenNo8BITMIME(t *testing.T) {
	fake := &fakeSMTPClient{hasStartTLS: false, has8BITMIME: false}
	s := senderWithFake(t, SMTPConfig{}, fake)
	rendered := newRendered()
	rendered.Body = "<p>Café</p>"
	if err := s.Send(context.Background(), newTarget(), rendered); err != nil {
		t.Fatalf("Send: %v", err)
	}
	body := fake.body.String()
	if !strings.Contains(body, "Content-Transfer-Encoding: quoted-printable") {
		t.Errorf("expected quoted-printable CTE when 8BITMIME is absent, got body:\n%s", body)
	}
	if !strings.Contains(body, "=C3=A9") {
		t.Errorf("expected QP-escaped body bytes, got body:\n%s", body)
	}
}

func TestSend_Uses8bitWhen8BITMIMEAdvertised(t *testing.T) {
	fake := &fakeSMTPClient{hasStartTLS: false, has8BITMIME: true}
	s := senderWithFake(t, SMTPConfig{}, fake)
	if err := s.Send(context.Background(), newTarget(), newRendered()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	body := fake.body.String()
	if !strings.Contains(body, "Content-Transfer-Encoding: 8bit") {
		t.Errorf("expected 8bit CTE when 8BITMIME advertised, got body:\n%s", body)
	}
}

func TestSenderHostname(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"a@example.com", "example.com"},
		{"a@", "localhost"},
		{"a", "localhost"},
		{"a@x.y.z", "x.y.z"},
	}
	for _, tt := range tests {
		if got := senderHostname(tt.in); got != tt.want {
			t.Errorf("senderHostname(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMimeEncode_ASCIIPassThrough(t *testing.T) {
	if got := mimeEncode("Hello"); got != "Hello" {
		t.Errorf("ASCII should pass through, got %q", got)
	}
}

// Verify *fakeWriter implements writeCloser at compile time.
var _ writeCloser = (*fakeWriter)(nil)
var _ io.Writer = (*fakeWriter)(nil)
