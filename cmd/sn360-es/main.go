// Command sn360-es is the service entrypoint that boots configuration,
// connects to NATS / Redis / PostgreSQL, and runs the HTTP server alongside
// any configured event-bus listeners.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kennguy3n/sn360-es/internal/config"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "sn360-es: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// --role overrides SN360_ROLE. Operators set the flag at the
	// container entrypoint via different `args:` values per
	// per-role Deployment (api / consumers / workers); single-binary
	// installs leave the flag empty and inherit RoleAll from config.
	// Defining the flagset locally (rather than using flag.CommandLine)
	// keeps repeated test invocations idempotent — `flag.Parse()` on
	// the global flagset panics on a second registration.
	fs := flag.NewFlagSet("sn360-es", flag.ContinueOnError)
	roleFlag := fs.String("role", "", "process role: all | api | consumers | workers (overrides SN360_ROLE)")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	cfg := config.MustLoad()
	if *roleFlag != "" {
		cfg.Role = config.Role(*roleFlag)
		if !cfg.Role.Valid() {
			return fmt.Errorf("--role: invalid value %q (expected one of: all, api, consumers, workers)", *roleFlag)
		}
	}
	logger := newLogger(&cfg)
	logger.Info("sn360-es: starting",
		slog.String("app", cfg.AppName),
		slog.String("env", string(cfg.Environment)),
		slog.String("role", string(cfg.Role)),
		slog.String("event_bus", string(cfg.EventBus)))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	app, err := newApplication(ctx, &cfg, logger)
	if err != nil {
		return err
	}
	defer app.Close(logger)

	mux, err := buildMux(app)
	if err != nil {
		return fmt.Errorf("build mux: %w", err)
	}

	httpHandler, err := wrapMiddleware(mux, app)
	if err != nil {
		return fmt.Errorf("middleware: %w", err)
	}

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.HTTP.Port),
		Handler:           httpHandler,
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
	}

	if cfg.Role.RunsConsumers() {
		if cerr := app.StartConsumers(ctx); cerr != nil {
			app.StopConsumers(logger)
			return fmt.Errorf("start consumers: %w", cerr)
		}
	} else {
		logger.Info("sn360-es: consumers disabled by role", slog.String("role", string(cfg.Role)))
	}

	app.StartBackground(ctx)

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

	app.draining.Store(true)
	app.StopConsumers(logger)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("sn360-es: http shutdown error", slog.Any("error", err))
	}

	app.WaitBackground()

	return nil
}
