package config

// Environment is the deployment stage the service is running in.
type Environment string

const (
	EnvironmentLocal Environment = "local"
	EnvironmentDev   Environment = "dev"
	EnvironmentQA    Environment = "qa"
	EnvironmentUAT   Environment = "uat"
	EnvironmentProd  Environment = "prod"
)

// IsDevelopment reports whether the environment is local or dev.
func (e Environment) IsDevelopment() bool {
	return e == EnvironmentLocal || e == EnvironmentDev
}

// IsProduction reports whether the environment requires production-grade
// security controls. Returns true for UAT and prod; QA, test, dev, and
// local are exempt (they may legitimately use mock KMS or weak secrets).
func (e Environment) IsProduction() bool {
	return e == EnvironmentUAT || e == EnvironmentProd
}

// String implements fmt.Stringer.
func (e Environment) String() string { return string(e) }

// EventBusType selects the event-bus implementation (`pkg/events`).
type EventBusType string

const (
	EventBusNATS  EventBusType = "nats"
	EventBusRedis EventBusType = "redis"
)

// Valid reports whether the value is a recognised event bus.
func (t EventBusType) Valid() bool {
	switch t {
	case EventBusNATS, EventBusRedis:
		return true
	default:
		return false
	}
}

// Role selects which subset of the binary's responsibilities the
// process runs. Splitting the monolith by role lets a deployment
// scale each subsystem independently (e.g. API on CPU, consumers on
// NATS lag) and prevents a slow Tier-2 SLM call from stalling
// HTTP request handling — the classic noisy-neighbour problem the
// review identified.
//
//   - RoleAll: the current behaviour. HTTP API + NATS consumers +
//     periodic workers all run in one process. Default for
//     single-replica / dev / local installs.
//   - RoleAPI: HTTP listener and request-time handlers only. No
//     NATS consumers, no periodic workers. Behind an HPA on
//     request CPU.
//   - RoleConsumers: NATS consumer loops only. No HTTP routes
//     beyond health + metrics. Scales on
//     `event_lag_seconds` via KEDA.
//   - RoleWorkers: periodic workers (relationship, vendor,
//     cleanup, directory-sync, partition-maintenance). Singleton
//     or low-replica; relies on the Redis distributed lock for
//     leader election when replicaCount > 1.
//
// Selected via SN360_ROLE env var or the --role command-line flag
// (flag wins). Unknown roles fail boot fast.
type Role string

const (
	RoleAll       Role = "all"
	RoleAPI       Role = "api"
	RoleConsumers Role = "consumers"
	RoleWorkers   Role = "workers"
)

// Valid reports whether the value is a recognised role.
func (r Role) Valid() bool {
	switch r {
	case RoleAll, RoleAPI, RoleConsumers, RoleWorkers:
		return true
	default:
		return false
	}
}

// ServesAPI reports whether this process should mount business
// HTTP routes (/v1/...). All roles still mount /healthz, /readyz,
// /metrics — those are infrastructural rather than business routes.
func (r Role) ServesAPI() bool { return r == RoleAll || r == RoleAPI }

// RunsConsumers reports whether this process should subscribe to
// NATS / Redis consumer subjects.
func (r Role) RunsConsumers() bool { return r == RoleAll || r == RoleConsumers }

// RunsWorkers reports whether this process should run the periodic
// background workers (relationship, vendor, cleanup, directory
// sync, partition maintenance).
func (r Role) RunsWorkers() bool { return r == RoleAll || r == RoleWorkers }

// String implements fmt.Stringer.
func (r Role) String() string { return string(r) }
