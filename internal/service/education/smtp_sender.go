package education

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// SMTPConfig wires SMTPSender. Host, Port, and From are required.
// User/Password may be empty for relay servers that accept
// unauthenticated submissions (e.g. an internal MTA).
type SMTPConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	From     string
	StartTLS bool
	Timeout  time.Duration
	// SkipVerify is an opt-in escape hatch for STARTTLS / implicit-TLS
	// connections against a self-signed test relay (mailpit /
	// mailhog). It is wired to crypto/tls.Config.InsecureSkipVerify
	// and therefore disables certificate validation when true.
	// Operators must NOT enable this in production — leaving the
	// default (false) preserves full chain verification.
	SkipVerify bool
	// Logger is used for non-fatal diagnostics (STARTTLS downgrade,
	// 8BITMIME fallback). Defaults to slog.Default() when nil so the
	// sender works without a wired logger.
	Logger *slog.Logger
}

// SMTPSender is the production implementation of SimulationSender. It
// composes a minimal RFC-822 message from the rendered template and
// hands it off to the configured SMTP relay over either implicit TLS
// (port 465) or STARTTLS (typically port 587).
type SMTPSender struct {
	cfg SMTPConfig
	// dialer abstracts the network/TLS bringup so tests can inject a
	// pre-baked smtp.Client connected to a local listener.
	dialer func(context.Context, SMTPConfig) (smtpClient, error)
}

// smtpClient is the slice of *smtp.Client we actually use, kept
// behind an interface so tests can provide a no-network fake.
type smtpClient interface {
	Hello(localName string) error
	Extension(ext string) (bool, string)
	StartTLS(config *tls.Config) error
	Auth(a smtp.Auth) error
	Mail(from string) error
	Rcpt(to string) error
	Data() (writeCloser, error)
	Quit() error
	Close() error
}

// writeCloser is the subset of io.WriteCloser used by Data().
type writeCloser interface {
	Write(p []byte) (int, error)
	Close() error
}

// NewSMTPSender constructs an SMTPSender. Host/Port/From are required;
// the remaining fields default to safe values (10s timeout, STARTTLS
// enabled, certificate verification on).
func NewSMTPSender(cfg SMTPConfig) (*SMTPSender, error) {
	if cfg.Host == "" {
		return nil, errors.New("education: SMTP host is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	if cfg.From == "" {
		return nil, errors.New("education: SMTP from-address is required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &SMTPSender{cfg: cfg, dialer: defaultDial}, nil
}

// Send implements SimulationSender. The mailbox alias is the SMTP
// recipient — typically a per-tenant alias like
// "alice+camp-<hash>@tenant.example.com" — so the engine never has to
// surface raw PII to the simulation transport.
func (s *SMTPSender) Send(ctx context.Context, target SimulationTarget, rendered dto.RenderedSimulation) error {
	if target.MailboxAlias == "" {
		return errors.New("education: simulation target requires mailbox alias")
	}
	if rendered.Subject == "" {
		return errors.New("education: simulation requires subject")
	}
	if rendered.Body == "" {
		return errors.New("education: simulation requires body")
	}

	client, err := s.dialer(ctx, s.cfg)
	if err != nil {
		return fmt.Errorf("education: smtp dial: %w", err)
	}
	defer client.Close()

	if err := client.Hello(senderHostname(s.cfg.From)); err != nil {
		return fmt.Errorf("education: smtp HELO: %w", err)
	}

	// STARTTLS if the server advertises it and the caller asked for
	// it. InsecureSkipVerify is wired from SMTPConfig.SkipVerify —
	// see the comment on that field for the safety contract. When
	// the operator requested STARTTLS but the server does not
	// advertise the extension we warn rather than silently
	// downgrading to plaintext: a security-product simulation relay
	// quietly losing TLS would expose realistic phishing templates
	// to any network observer between us and the relay.
	//
	// Port 465 is the canonical implicit-TLS submission port
	// (RFC 8314): defaultDial already wrapped the connection in TLS
	// before handing the client over, so a STARTTLS upgrade is
	// neither possible (servers do not advertise STARTTLS on an
	// already-encrypted session) nor meaningful. Skip the entire
	// block so we do not emit the misleading "continuing in
	// plaintext" warning on a connection that is already encrypted.
	if s.cfg.StartTLS && s.cfg.Port != 465 {
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsCfg := &tls.Config{
				ServerName:         s.cfg.Host,
				InsecureSkipVerify: s.cfg.SkipVerify, //nolint:gosec // gated on opt-in SkipVerify config; see SMTPConfig.SkipVerify comment.
			}
			if err := client.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("education: smtp STARTTLS: %w", err)
			}
		} else {
			s.cfg.Logger.WarnContext(ctx,
				"education: SMTP STARTTLS requested but server did not advertise the extension; continuing in plaintext",
				slog.String("host", s.cfg.Host),
				slog.Int("port", s.cfg.Port))
		}
	}

	if s.cfg.User != "" {
		auth := smtp.PlainAuth("", s.cfg.User, s.cfg.Password, s.cfg.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("education: smtp AUTH: %w", err)
		}
	}

	// Pick the Content-Transfer-Encoding for the body based on
	// whether the server advertises 8BITMIME (RFC 6152). Without
	// that extension, non-ASCII octets in the body can be silently
	// mangled by the MTA — fall back to quoted-printable so all
	// templates survive intact on legacy relays. We log a warning
	// because losing 8BITMIME in production usually indicates a
	// misconfigured relay rather than an intentional choice.
	bodyEncoding := "8bit"
	if ok, _ := client.Extension("8BITMIME"); !ok {
		bodyEncoding = "quoted-printable"
		s.cfg.Logger.WarnContext(ctx,
			"education: SMTP relay does not advertise 8BITMIME; falling back to quoted-printable",
			slog.String("host", s.cfg.Host),
			slog.Int("port", s.cfg.Port))
	}
	msg := buildMessage(s.cfg.From, target, rendered, bodyEncoding)

	if err := client.Mail(s.cfg.From); err != nil {
		return fmt.Errorf("education: smtp MAIL FROM: %w", err)
	}
	if err := client.Rcpt(target.MailboxAlias); err != nil {
		return fmt.Errorf("education: smtp RCPT TO: %w", err)
	}
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("education: smtp DATA: %w", err)
	}
	if _, err := wc.Write(msg); err != nil {
		_ = wc.Close()
		return fmt.Errorf("education: smtp body: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("education: smtp body close: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("education: smtp QUIT: %w", err)
	}
	return nil
}

// defaultDial is the production dialer used by NewSMTPSender. It
// honours the context deadline by setting a corresponding TCP dial
// timeout.
func defaultDial(ctx context.Context, cfg SMTPConfig) (smtpClient, error) {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	d := &net.Dialer{Timeout: cfg.Timeout}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > 0 && remaining < d.Timeout {
			d.Timeout = remaining
		}
	}
	var (
		conn net.Conn
		err  error
	)
	// Port 465 = implicit TLS submission; everything else is
	// plain-text with optional STARTTLS upgrade.
	if cfg.Port == 465 {
		tlsCfg := &tls.Config{
			ServerName:         cfg.Host,
			InsecureSkipVerify: cfg.SkipVerify, //nolint:gosec // gated on opt-in SkipVerify config; see SMTPConfig.SkipVerify comment.
		}
		conn, err = tls.DialWithDialer(d, "tcp", addr, tlsCfg)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &smtpClientAdapter{c: client}, nil
}

// smtpClientAdapter bridges the concrete *smtp.Client to our
// smtpClient interface (specifically wrapping Data() to satisfy the
// narrower writeCloser type).
type smtpClientAdapter struct {
	c *smtp.Client
}

func (a *smtpClientAdapter) Hello(localName string) error        { return a.c.Hello(localName) }
func (a *smtpClientAdapter) Extension(ext string) (bool, string) { return a.c.Extension(ext) }
func (a *smtpClientAdapter) StartTLS(cfg *tls.Config) error      { return a.c.StartTLS(cfg) }
func (a *smtpClientAdapter) Auth(auth smtp.Auth) error           { return a.c.Auth(auth) }
func (a *smtpClientAdapter) Mail(from string) error              { return a.c.Mail(from) }
func (a *smtpClientAdapter) Rcpt(to string) error                { return a.c.Rcpt(to) }
func (a *smtpClientAdapter) Quit() error                         { return a.c.Quit() }
func (a *smtpClientAdapter) Close() error                        { return a.c.Close() }

func (a *smtpClientAdapter) Data() (writeCloser, error) {
	w, err := a.c.Data()
	if err != nil {
		return nil, err
	}
	return w, nil
}

// buildMessage assembles a minimal RFC-822 envelope: From, To,
// Subject, Date, MIME headers and the HTML body. Subject and display
// name are MIME-encoded so non-ASCII payloads (e.g. localized
// templates) survive the wire intact. Headers are written in a fixed
// order so the resulting bytes are deterministic across runs (helpful
// for tests and for downstream MTAs that rely on a stable Received
// chain).
//
// bodyEncoding selects the Content-Transfer-Encoding emitted with the
// body. Pass "8bit" when the receiving relay advertises 8BITMIME, or
// "quoted-printable" otherwise. Any other value is treated as 8bit
// (the relay-advertised default).
func buildMessage(from string, target SimulationTarget, rendered dto.RenderedSimulation, bodyEncoding string) []byte {
	if bodyEncoding == "" {
		bodyEncoding = "8bit"
	}
	var b bytes.Buffer
	type kv struct{ k, v string }
	headers := []kv{
		{"From", formatFromHeader(from, rendered.SenderDisplay)},
		{"To", formatToHeader(target)},
		{"Subject", mimeEncode(rendered.Subject)},
		{"Date", time.Now().UTC().Format(time.RFC1123Z)},
		{"MIME-Version", "1.0"},
		{"Content-Type", "text/html; charset=UTF-8"},
		{"Content-Transfer-Encoding", bodyEncoding},
		{"X-SN360-Simulation", "true"},
		{"X-SN360-Template", rendered.TemplateID},
	}
	for _, h := range headers {
		b.WriteString(h.k)
		b.WriteString(": ")
		b.WriteString(h.v)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	if bodyEncoding == "quoted-printable" {
		qp := quotedprintable.NewWriter(&b)
		// quotedprintable.Writer never returns errors for an
		// in-memory buffer; ignore them explicitly.
		_, _ = qp.Write([]byte(rendered.Body))
		_ = qp.Close()
	} else {
		b.WriteString(rendered.Body)
	}
	return b.Bytes()
}

// formatFromHeader prefers a display name when the rendered template
// supplies one and otherwise falls back to the raw From address.
func formatFromHeader(from, display string) string {
	display = strings.TrimSpace(display)
	if display == "" {
		return from
	}
	return fmt.Sprintf("%s <%s>", mimeEncode(display), from)
}

// formatToHeader uses the display-name from the target when set, or
// the alias alone. We never emit the user_hash here — that is a
// privacy-layer internal identifier.
func formatToHeader(target SimulationTarget) string {
	if d := strings.TrimSpace(target.DisplayName); d != "" {
		return fmt.Sprintf("%s <%s>", mimeEncode(d), target.MailboxAlias)
	}
	return target.MailboxAlias
}

// mimeEncode applies the encoded-word ("B" / base64) syntax from RFC
// 2047 only when the input contains non-ASCII or non-printable
// characters. ASCII strings are returned verbatim so test fixtures
// remain easy to read.
func mimeEncode(s string) string {
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			return mimeEncodeBase64UTF8(s)
		}
	}
	return s
}

func mimeEncodeBase64UTF8(s string) string {
	// We hand-roll the encoded-word to avoid an extra import for
	// mime.QEncoding when the input is short and rare.
	const prefix = "=?UTF-8?B?"
	const suffix = "?="
	return prefix + base64.StdEncoding.EncodeToString([]byte(s)) + suffix
}

// senderHostname extracts the right-hand side of from for HELO. Using
// the SMTP From's domain is a reasonable default that satisfies most
// relays' DNS/HELO sanity checks.
func senderHostname(from string) string {
	at := strings.LastIndex(from, "@")
	if at < 0 || at == len(from)-1 {
		return "localhost"
	}
	return from[at+1:]
}
