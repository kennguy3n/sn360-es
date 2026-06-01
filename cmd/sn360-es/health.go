package main

import (
	"context"
	"errors"

	"github.com/kennguy3n/sn360-es/internal/handler"
)

// buildHealthCheckers returns the set of health checkers wired from
// the application's dependencies. Each checker is optional — a nil
// component is simply skipped — so the binary gracefully degrades
// when dependencies are absent.
func buildHealthCheckers(app *application) []handler.HealthChecker {
	logger := app.logger

	checkers := []handler.HealthChecker{
		handler.HealthCheckerFunc{N: "event_bus", F: func(ctx context.Context) error {
			if app.eventBus == nil {
				return errors.New("event bus not configured")
			}
			return app.eventBus.Health(ctx)
		}},
	}
	if app.pgDB != nil {
		pg := app.pgDB
		checkers = append(checkers, handler.HealthCheckerFunc{N: "postgres", F: func(ctx context.Context) error {
			return pg.PingContext(ctx)
		}})
	}
	if app.redis != nil {
		raw := app.redis.Raw()
		checkers = append(checkers, handler.HealthCheckerFunc{N: "redis", F: func(ctx context.Context) error {
			return raw.Ping(ctx).Err()
		}})
	}
	if app.tier1Raw != nil {
		t1 := app.tier1Raw
		checkers = append(checkers, handler.HealthCheckerFunc{N: "tier1_encoder", F: func(ctx context.Context) error {
			return t1.Health(ctx)
		}})
	}
	// Informational checkers for the components wired by the
	// 2026-05-18 plan. These never error (they never fail readiness)
	// — they exist so operators can see whether the provider
	// registry, the poller, and the periodic workers were
	// constructed when they look at /readyz.
	if app.providers != nil {
		reg := app.providers
		checkers = append(checkers, handler.HealthCheckerFunc{N: "provider_registry", F: func(_ context.Context) error {
			if !reg.hasAny() {
				logger.Debug("readyz: provider registry has no tenants registered")
			}
			return nil
		}})
	}
	if app.poller != nil {
		checkers = append(checkers, handler.HealthCheckerFunc{N: "ingestion_poller", F: func(_ context.Context) error {
			return nil
		}})
	}
	if app.pushManager != nil {
		checkers = append(checkers, handler.HealthCheckerFunc{N: "ingestion_push", F: func(_ context.Context) error {
			return nil
		}})
	}
	if app.relationshipRunner != nil {
		checkers = append(checkers, handler.HealthCheckerFunc{N: "worker_relationship", F: func(_ context.Context) error {
			return nil
		}})
	}
	if app.vendorRunner != nil {
		checkers = append(checkers, handler.HealthCheckerFunc{N: "worker_vendor", F: func(_ context.Context) error {
			return nil
		}})
	}
	if app.cleanupRunner != nil {
		checkers = append(checkers, handler.HealthCheckerFunc{N: "worker_cleanup", F: func(_ context.Context) error {
			return nil
		}})
	}
	if app.directorySyncRunner != nil {
		checkers = append(checkers, handler.HealthCheckerFunc{N: "worker_directory_sync", F: func(_ context.Context) error {
			return nil
		}})
	}
	if app.tuningAgent != nil {
		checkers = append(checkers, handler.HealthCheckerFunc{N: "agent_tuning", F: func(_ context.Context) error {
			return nil
		}})
	}
	// WS-5A.6: advisory probe for the cross-repo SOC
	// resolution durable consumer. Reports the boot
	// subscribe error (if any) on /readyz without 503-ing
	// the endpoint. Operators monitoring readiness
	// dashboards see the dark loop immediately instead of
	// having to grep boot logs for a one-shot WARN; the
	// hot path (everything outside the cross-repo
	// reconciliation loop) keeps serving normally.
	checkers = append(checkers, handler.HealthCheckerFunc{
		N:   "escalation_sync",
		Adv: true,
		F: func(_ context.Context) error {
			if errp := app.socResolutionSubErr.Load(); errp != nil && *errp != nil {
				return *errp
			}
			return nil
		},
	})
	return checkers
}
