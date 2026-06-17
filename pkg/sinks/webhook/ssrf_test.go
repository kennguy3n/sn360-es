package webhook

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/repository"
)

// TestSSRFGuard_Control exercises the dial-time classification for
// every non-public address class the guard must refuse, plus the
// public addresses it must allow.
func TestSSRFGuard_Control(t *testing.T) {
	t.Parallel()
	g := NewSSRFGuard(false, nil)
	cases := []struct {
		name    string
		ip      string
		blocked bool
	}{
		{"ipv4 loopback", "127.0.0.1", true},
		{"ipv4 loopback range", "127.10.20.30", true},
		{"ipv6 loopback", "::1", true},
		{"unspecified v4", "0.0.0.0", true},
		{"unspecified v6", "::", true},
		{"rfc1918 10/8", "10.0.0.1", true},
		{"rfc1918 172.16/12", "172.16.5.4", true},
		{"rfc1918 192.168/16", "192.168.1.1", true},
		{"link-local metadata", "169.254.169.254", true},
		{"link-local v4", "169.254.1.1", true},
		{"link-local v6", "fe80::1", true},
		{"ipv6 ula", "fd00::1", true},
		{"ipv6 ula metadata", "fd00:ec2::254", true},
		{"cgnat low", "100.64.0.1", true},
		{"cgnat alibaba metadata", "100.100.100.200", true},
		{"multicast v4", "224.0.0.1", true},
		{"multicast v6", "ff02::1", true},
		{"ipv4-mapped loopback", "::ffff:127.0.0.1", true},
		{"rfc5737 test-net-1", "192.0.2.10", true},
		{"rfc5737 test-net-2", "198.51.100.10", true},
		{"rfc5737 test-net-3", "203.0.113.10", true},
		{"rfc2544 benchmarking", "198.18.5.6", true},
		{"public dns google", "8.8.8.8", false},
		{"public dns cloudflare", "1.1.1.1", false},
		{"public v6", "2606:4700:4700::1111", false},
		{"public edge of cgnat", "100.128.0.1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := g.Control("tcp", net.JoinHostPort(tc.ip, "443"), nil)
			if tc.blocked && err == nil {
				t.Errorf("Control(%s) = nil; want blocked", tc.ip)
			}
			// A blocked address must wrap ErrBlockedDestination so
			// Publish can classify the dispatch as a permanent failure
			// rather than retrying a deterministically-doomed dial.
			if tc.blocked && err != nil && !errors.Is(err, ErrBlockedDestination) {
				t.Errorf("Control(%s) err = %v; want errors.Is(ErrBlockedDestination)", tc.ip, err)
			}
			if !tc.blocked && err != nil {
				t.Errorf("Control(%s) = %v; want allowed", tc.ip, err)
			}
		})
	}
}

func TestSSRFGuard_RejectsNonTCP(t *testing.T) {
	t.Parallel()
	g := NewSSRFGuard(false, nil)
	if err := g.Control("udp", "8.8.8.8:53", nil); err == nil {
		t.Error("Control(udp) = nil; want non-tcp rejection")
	}
}

func TestSSRFGuard_AllowList(t *testing.T) {
	t.Parallel()
	// Keep the guard active but whitelist one internal /24.
	g := NewSSRFGuard(false, []netip.Prefix{netip.MustParsePrefix("10.1.2.0/24")})
	if err := g.Control("tcp", "10.1.2.50:443", nil); err != nil {
		t.Errorf("allow-listed 10.1.2.50 blocked: %v", err)
	}
	// A different private host outside the allow-list is still blocked.
	if err := g.Control("tcp", "10.9.9.9:443", nil); err == nil {
		t.Error("non-allow-listed 10.9.9.9 = nil; want blocked")
	}
	// Loopback is never allow-listed implicitly.
	if err := g.Control("tcp", "127.0.0.1:443", nil); err == nil {
		t.Error("loopback = nil; want blocked even with an allow-list set")
	}
}

func TestSSRFGuard_AllowPrivateDisablesGuard(t *testing.T) {
	t.Parallel()
	g := NewSSRFGuard(true, nil)
	for _, ip := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "::1"} {
		if err := g.Control("tcp", net.JoinHostPort(ip, "443"), nil); err != nil {
			t.Errorf("allowPrivate guard blocked %s: %v", ip, err)
		}
	}
}

func TestSSRFGuard_NilReceiverAllows(t *testing.T) {
	t.Parallel()
	var g *SSRFGuard
	if err := g.Control("tcp", "127.0.0.1:443", nil); err != nil {
		t.Errorf("nil guard should be a no-op; got %v", err)
	}
}

// TestNewHTTPPublisher_GuardBlocksLoopback proves the production
// constructor installs the dial guard: a Publish to a loopback HTTPS
// endpoint is refused at dial time, so the endpoint handler is never
// invoked and the outcome is a permanent failure (deterministic block).
func TestNewHTTPPublisher_GuardBlocksLoopback(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	// Production constructor, no custom client => guard active.
	p := NewHTTPPublisher(HTTPPublisherConfig{Timeout: 2 * time.Second})
	res, err := p.Publish(context.Background(), &Request{
		URL:       srv.URL, // 127.0.0.1:<port>
		Format:    repository.WebhookSinkFormatECS,
		Body:      []byte(`{"x":1}`),
		Signature: "sha256=abc",
		EventType: EventTypeEmailEvaluation,
	})
	if err != nil {
		t.Fatalf("Publish returned hard error: %v", err)
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("loopback endpoint was hit %d times; want 0 (guard must block the dial)", got)
	}
	// A guard-blocked dial is deterministic, so Publish classifies it
	// as a permanent failure (no DLQ retries) rather than retriable.
	if res.Outcome != OutcomePermanentFailure {
		t.Errorf("Outcome = %v; want OutcomePermanentFailure for a guard-blocked dial", res.Outcome)
	}
	// Assert the block came from the SSRF guard specifically, not
	// from the self-signed TLS cert the httptest server presents:
	// the guard refuses the dial before any TLS handshake, and its
	// reason string is surfaced (URL-redacted) into the audit Cause.
	if !strings.Contains(res.Cause, "refusing to dial non-public") {
		t.Errorf("Cause = %q; want the SSRF guard's dial-refusal reason", res.Cause)
	}
}

// TestNewHTTPPublisher_GuardDisablesProxy is a regression test for the
// proxy-env SSRF bypass: when the guard is active the production
// transport must NOT inherit http.ProxyFromEnvironment, otherwise a
// forward proxy set via HTTPS_PROXY would make the dialer connect to
// the (public) proxy IP and the Control hook would never see the
// private destination.
func TestNewHTTPPublisher_GuardDisablesProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://203.0.113.9:3128")
	t.Setenv("HTTP_PROXY", "http://203.0.113.9:3128")
	p := NewHTTPPublisher(HTTPPublisherConfig{Timeout: 2 * time.Second})
	tr, ok := p.Client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("guard-active publisher Transport = %T; want *http.Transport", p.Client.Transport)
	}
	if tr.Proxy != nil {
		req, _ := http.NewRequest(http.MethodPost, "https://198.51.100.7/x", nil)
		if u, err := tr.Proxy(req); err == nil && u != nil {
			t.Errorf("transport resolved a proxy %s while the guard is active; want direct dial", u)
		}
	}
}

// TestNewHTTPPublisher_AllowPrivateReachesLoopback is the inverse: with
// the operator escape hatch enabled the same loopback endpoint is
// reached. It uses a custom TLS-trusting transport layered on the
// production client so only the dial-guard difference is under test.
func TestNewHTTPPublisher_AllowPrivateReachesLoopback(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	p := NewHTTPPublisher(HTTPPublisherConfig{
		Timeout:                  2 * time.Second,
		AllowPrivateDestinations: true,
	})
	// Swap in the httptest client's TLS-trusting transport so the
	// self-signed cert is accepted; AllowPrivateDestinations left the
	// Transport at the default (no guard), so this only changes TLS.
	p.Client.Transport = srv.Client().Transport
	res, err := p.Publish(context.Background(), &Request{
		URL:       srv.URL,
		Format:    repository.WebhookSinkFormatECS,
		Body:      []byte(`{"x":1}`),
		Signature: "sha256=abc",
		EventType: EventTypeEmailEvaluation,
	})
	if err != nil {
		t.Fatalf("Publish returned hard error: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("endpoint hit %d times; want 1 (escape hatch should reach loopback)", got)
	}
	if res.Outcome != OutcomeSuccess {
		t.Errorf("Outcome = %v; want success", res.Outcome)
	}
}
