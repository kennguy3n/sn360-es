// Command sn360-es is the service entrypoint that boots configuration,
// connects to NATS / Redis / PostgreSQL, and runs the HTTP server alongside
// any configured event-bus listeners.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kennguy3n/sn360-es/internal/config"
	"github.com/kennguy3n/sn360-es/pkg/events/bus"
	natsbus "github.com/kennguy3n/sn360-es/pkg/events/nats"
	redisbus "github.com/kennguy3n/sn360-es/pkg/events/redis"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "sn360-es: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := config.MustLoad()
	logger := newLogger(&cfg)
	logger.Info("sn360-es: starting",
		slog.String("app", cfg.AppName),
		slog.String("env", string(cfg.Environment)),
		slog.String("event_bus", string(cfg.EventBus)))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	eventBus, err := bus.New(ctx, factoryConfigFromAppConfig(&cfg), logger)
	if err != nil {
		return fmt.Errorf("event bus: %w", err)
	}
	defer func() {
		if cerr := bus.CloseWithTimeout(eventBus, 5*time.Second); cerr != nil {
			logger.Warn("sn360-es: event bus close error", slog.Any("error", cerr))
		}
	}()
	_ = eventBus // future: register subscriptions before serving HTTP

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.HTTP.Port),
		Handler:           buildMux(&cfg, logger),
		ReadHeaderTimeout: cfg.HTTP.ReadTimeout,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
	}

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("sn360-es: http server listening", slog.Int("port", cfg.HTTP.Port))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("sn360-es: shutdown signal received")
	case err := <-serveErr:
		return fmt.Errorf("http server: %w", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("sn360-es: http shutdown error", slog.Any("error", err))
	}
	return nil
}

// buildMux constructs the HTTP routing tree. Handlers from internal/handler
// are wired here so future routes have one obvious place to register.
func buildMux(cfg *config.Config, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("http: unmatched route", slog.String("path", r.URL.Path))
		w.WriteHeader(http.StatusNotFound)
	})
	_ = cfg // future wiring will use cfg
	return mux
}

func factoryConfigFromAppConfig(cfg *config.Config) bus.Config {
	return bus.Config{
		Type:   bus.Type(cfg.EventBus),
		Source: cfg.AppName,
		NATS: natsbus.Config{
			URL:                  cfg.NATS.URL,
			Name:                 cfg.AppName,
			User:                 cfg.NATS.User,
			Password:             cfg.NATS.Password,
			Token:                cfg.NATS.Token,
			CredsFile:            cfg.NATS.CredsFile,
			TLSCAFile:            cfg.NATS.TLSCAFile,
			TLSCertFile:          cfg.NATS.TLSCertFile,
			TLSKeyFile:           cfg.NATS.TLSKeyFile,
			TLSInsecure:          cfg.NATS.TLSInsecure,
			ReconnectWait:        cfg.NATS.ReconnectWait,
			MaxReconnects:        cfg.NATS.MaxReconnects,
			RequestTimeout:       cfg.NATS.RequestTimeout,
			PublishRetryAttempts: cfg.NATS.PublishRetryAttempts,
			PublishRetryDelay:    cfg.NATS.PublishRetryDelay,
			DedupWindow:          cfg.NATS.DedupWindow,
			Replicas:             cfg.NATS.Replicas,
			Storage:              cfg.NATS.Storage,
			FetchBatchSize:       cfg.NATS.FetchBatchSize,
			FetchMaxWait:         cfg.NATS.FetchMaxWait,
		},
		Redis: redisbus.Config{
			Addr:           cfg.Redis.Addr,
			DB:             cfg.Redis.DB,
			Password:       cfg.Redis.Password,
			PoolSize:       cfg.Redis.PoolSize,
			ReadBlock:      cfg.Redis.ConsumerBlock,
			FetchBatchSize: cfg.NATS.FetchBatchSize,
		},
	}
}

func newLogger(cfg *config.Config) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.Log.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	var handler slog.Handler
	if cfg.Log.Format == "text" {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	} else {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}
	return slog.New(handler)
}
