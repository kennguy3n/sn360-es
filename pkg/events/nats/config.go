// Package nats provides a NATS JetStream implementation of the
// SN360-ES events.EventService interface.
package nats

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/nats-io/nats.go"
)

// Config holds the NATS connection + JetStream configuration.
type Config struct {
	// URL is the NATS server URL (e.g. "nats://127.0.0.1:4222").
	URL string
	// Name identifies the connection on the server.
	Name string

	// Authentication (any one). Empty values are ignored.
	User      string
	Password  string
	Token     string
	CredsFile string

	// TLS. If TLSCAFile is set, server-cert verification uses that CA.
	TLSCAFile   string
	TLSCertFile string
	TLSKeyFile  string
	// TLSInsecure disables TLS verification (DEV ONLY).
	TLSInsecure bool

	// Reconnect behaviour.
	ReconnectWait time.Duration
	MaxReconnects int

	// JetStream request timeout (used by streams.go etc.).
	RequestTimeout time.Duration

	// PublishRetryAttempts / PublishRetryDelay control Publish retries.
	PublishRetryAttempts int
	PublishRetryDelay    time.Duration

	// DedupWindow is forwarded to stream creation. Set to 0 to disable.
	DedupWindow time.Duration

	// Replicas to use when creating streams (1 in dev, 3 in prod).
	Replicas int

	// Storage selects the JetStream storage backend ("file" or "memory").
	Storage string

	// FetchBatchSize / FetchMaxWait are the defaults for pull consumers.
	FetchBatchSize int
	FetchMaxWait   time.Duration

	// HomeRegion identifies the deployment's home region; used to
	// pick the home entry out of Supercluster when wiring
	// cross-region leaf-cluster connections. Empty in
	// single-region deployments (the default) and ignored when
	// Supercluster is also empty.
	HomeRegion string
	// Supercluster maps region name -> comma-separated NATS URL
	// list for that region's leaf cluster. When non-empty,
	// NewClient appends the URLs from Supercluster[HomeRegion]
	// to the primary URL so the binary fails over to home-region
	// leaf nodes when the primary URL is unreachable, and
	// surfaces the remote-region URLs to operators via the
	// boot log. Cross-region publish/subscribe is the same Subject
	// space — see docs/MULTI_REGION.md for the wiring.
	// Nil / empty: single-region behaviour (use URL only).
	Supercluster map[string]string
}

// DefaultConfig returns a Config populated with sensible defaults.
func DefaultConfig() Config {
	return Config{
		URL:                  "nats://127.0.0.1:4222",
		Name:                 "sn360-es",
		ReconnectWait:        2 * time.Second,
		MaxReconnects:        -1,
		RequestTimeout:       5 * time.Second,
		PublishRetryAttempts: 3,
		PublishRetryDelay:    200 * time.Millisecond,
		DedupWindow:          2 * time.Minute,
		Replicas:             1,
		Storage:              "file",
		FetchBatchSize:       50,
		FetchMaxWait:         200 * time.Millisecond,
	}
}

// natsOptions builds the nats.Option set from the config.
func (c Config) natsOptions() ([]nats.Option, error) {
	if c.URL == "" {
		return nil, errors.New("nats: URL is required")
	}
	opts := []nats.Option{
		nats.Name(c.Name),
		nats.ReconnectWait(orDefault(c.ReconnectWait, 2*time.Second)),
		nats.MaxReconnects(c.MaxReconnects),
	}

	if c.User != "" {
		opts = append(opts, nats.UserInfo(c.User, c.Password))
	}
	if c.Token != "" {
		opts = append(opts, nats.Token(c.Token))
	}
	if c.CredsFile != "" {
		opts = append(opts, nats.UserCredentials(c.CredsFile))
	}

	if tlsCfg, err := c.tlsConfig(); err != nil {
		return nil, err
	} else if tlsCfg != nil {
		opts = append(opts, nats.Secure(tlsCfg))
	}

	return opts, nil
}

func (c Config) tlsConfig() (*tls.Config, error) {
	if c.TLSCAFile == "" && c.TLSCertFile == "" && c.TLSKeyFile == "" && !c.TLSInsecure {
		return nil, nil
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: c.TLSInsecure} //nolint:gosec
	if c.TLSCAFile != "" {
		caBytes, err := os.ReadFile(c.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("nats: read TLS CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("nats: TLS CA %s has no valid certs", c.TLSCAFile)
		}
		tlsCfg.RootCAs = pool
	}
	if c.TLSCertFile != "" || c.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("nats: load client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return tlsCfg, nil
}

func orDefault[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}
