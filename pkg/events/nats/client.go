package nats

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Client wraps a *nats.Conn plus a JetStream context with reconnect awareness.
// It is safe for concurrent use; all exported methods may be called from any
// goroutine.
type Client struct {
	cfg    Config
	logger *slog.Logger

	mu sync.RWMutex
	nc *nats.Conn
	js jetstream.JetStream

	// observers receives connection state transitions for tests/metrics.
	observersMu sync.RWMutex
	observers   []func(State)
}

// State represents a connection state transition.
type State int

const (
	StateConnected State = iota
	StateDisconnected
	StateReconnected
	StateClosed
)

func (s State) String() string {
	switch s {
	case StateConnected:
		return "connected"
	case StateDisconnected:
		return "disconnected"
	case StateReconnected:
		return "reconnected"
	case StateClosed:
		return "closed"
	default:
		return fmt.Sprintf("state(%d)", s)
	}
}

// NewClient connects to NATS using cfg and creates a JetStream context.
//
// The returned client owns the underlying connection; call Close to release
// it.
func NewClient(ctx context.Context, cfg Config, logger *slog.Logger) (*Client, error) {
	if logger == nil {
		logger = slog.Default()
	}
	c := &Client{cfg: cfg, logger: logger}

	// WS-7a: when NATS_SUPERCLUSTER is configured, merge the
	// home-region URL list into the primary URL so nats.Connect
	// will fail over to the configured leaf-cluster URLs. The
	// helper returns cfg.URL unchanged when Supercluster is
	// empty (single-region default).
	connectURL, err := resolveSuperclusterServers(cfg)
	if err != nil {
		return nil, err
	}
	opts, err := cfg.natsOptions()
	if err != nil {
		return nil, err
	}
	opts = append(opts,
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			c.notify(StateDisconnected)
			c.logger.Warn("nats: disconnected", slog.Any("error", err))
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			c.notify(StateReconnected)
			c.logger.Info("nats: reconnected", slog.String("url", nc.ConnectedUrl()))
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			c.notify(StateClosed)
			c.logger.Info("nats: connection closed")
		}),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			c.logger.Error("nats: async error", slog.Any("error", err))
		}),
	)

	nc, err := nats.Connect(connectURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("nats: connect %s: %w", connectURL, err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("nats: jetstream context: %w", err)
	}

	c.mu.Lock()
	c.nc, c.js = nc, js
	c.mu.Unlock()
	c.notify(StateConnected)

	// Quick liveness probe to surface auth / TLS failures eagerly.
	pingCtx, cancel := context.WithTimeout(ctx, orDefault(cfg.RequestTimeout, 5*time.Second))
	defer cancel()
	if _, err := js.AccountInfo(pingCtx); err != nil {
		// AccountInfo can return errors that are still recoverable (e.g. when
		// JetStream is enabled but the user has no account permissions yet).
		// Log but don't fail — Stream operations will surface real issues.
		c.logger.Warn("nats: jetstream AccountInfo probe failed", slog.Any("error", err))
	}

	return c, nil
}

// Conn returns the raw nats connection. It is exposed so that helpers can
// craft headers/etc; prefer the higher-level methods.
func (c *Client) Conn() *nats.Conn {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nc
}

// JetStream returns the active JetStream context.
func (c *Client) JetStream() jetstream.JetStream {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.js
}

// IsConnected reports whether the underlying NATS connection is up.
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nc != nil && c.nc.IsConnected()
}

// Close drains and closes the underlying connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nc == nil {
		return nil
	}
	if err := c.nc.Drain(); err != nil && !errors.Is(err, nats.ErrConnectionClosed) {
		c.logger.Warn("nats: drain failed", slog.Any("error", err))
	}
	c.nc.Close()
	c.nc = nil
	c.js = nil
	return nil
}

// OnStateChange registers an observer invoked on each connection state
// transition. Observers are invoked synchronously from the NATS callback
// goroutine and must not block.
func (c *Client) OnStateChange(fn func(State)) {
	if fn == nil {
		return
	}
	c.observersMu.Lock()
	c.observers = append(c.observers, fn)
	c.observersMu.Unlock()
}

func (c *Client) notify(s State) {
	c.observersMu.RLock()
	defer c.observersMu.RUnlock()
	for _, fn := range c.observers {
		fn(s)
	}
}
