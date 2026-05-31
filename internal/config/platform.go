package config

import "time"

// Platform carries the sn360-security-platform integration settings,
// in particular the WS-5A.1 NATS event-bridge wiring that lets
// sn360-es publish HighRisk+/Blocked verdicts, quarantine actions,
// and escalation events to the platform's `sn360-events` JetStream
// stream for SOC correlation, playbook execution, and OpenSearch
// indexing.
//
// All bridge settings are gated behind PLATFORM_NATS_ENABLED so a
// standalone sn360-es deployment that is not paired with the
// platform keeps its existing behaviour with no extra config and no
// new infrastructure dependency.
type Platform struct {
	// NATSEnabled gates the bridge. Defaults to false so a fresh
	// deployment cannot accidentally publish to a non-existent
	// platform cluster.
	NATSEnabled bool

	// NATSURLs is the comma-separated list of NATS server URLs for
	// the platform cluster. Required when NATSEnabled is true.
	NATSURLs string

	// NATSCredsFile is an optional path to a NATS user credentials
	// file (.creds) issued by the platform's account JWT.
	NATSCredsFile string

	// NATSToken is a lower-priority auth fallback for environments
	// that haven't migrated to credentials files yet.
	NATSToken string

	// NATSName is the connection name advertised on the platform
	// NATS for observability. Defaults to "sn360-es-bridge".
	NATSName string

	// NATSStream is the platform JetStream stream the bridge
	// publishes against. Must match the stream the platform's
	// alert-forwarder binds its consumer to (default
	// `sn360-events`).
	NATSStream string

	// ClusterID identifies this sn360-es deployment to the platform
	// SOC. Mirrored into `cluster_id` and
	// `agent.labels.sn360.cluster_id` on each event so multi-region
	// fleets can attribute alerts back to the originating cluster.
	// Defaults to AppName when unset.
	ClusterID string

	// NATSTLSCAFile / NATSTLSCertFile / NATSTLSKeyFile configure
	// TLS for the platform connection. Mutually compatible with
	// the creds-file auth path.
	NATSTLSCAFile   string
	NATSTLSCertFile string
	NATSTLSKeyFile  string
	NATSTLSInsecure bool

	// Reconnect / publish timing knobs. Defaults are applied in
	// the bridge package when these are zero.
	NATSReconnectWait  time.Duration
	NATSMaxReconnects  int
	NATSPublishTimeout time.Duration
	NATSPublishRetries int
}

func loadPlatform() Platform {
	return Platform{
		NATSEnabled:        getBool("PLATFORM_NATS_ENABLED", false),
		NATSURLs:           getStr("PLATFORM_NATS_URLS", ""),
		NATSCredsFile:      getStr("PLATFORM_NATS_CREDS_FILE", ""),
		NATSToken:          getStr("PLATFORM_NATS_TOKEN", ""),
		NATSName:           getStr("PLATFORM_NATS_NAME", "sn360-es-bridge"),
		NATSStream:         getStr("PLATFORM_NATS_STREAM", "sn360-events"),
		ClusterID:          getStr("PLATFORM_CLUSTER_ID", ""),
		NATSTLSCAFile:      getStr("PLATFORM_NATS_TLS_CA", ""),
		NATSTLSCertFile:    getStr("PLATFORM_NATS_TLS_CERT", ""),
		NATSTLSKeyFile:     getStr("PLATFORM_NATS_TLS_KEY", ""),
		NATSTLSInsecure:    getBool("PLATFORM_NATS_TLS_INSECURE", false),
		NATSReconnectWait:  getDuration("PLATFORM_NATS_RECONNECT_WAIT", 2*time.Second),
		NATSMaxReconnects:  getInt("PLATFORM_NATS_MAX_RECONNECTS", -1),
		NATSPublishTimeout: getDuration("PLATFORM_NATS_PUBLISH_TIMEOUT", 3*time.Second),
		NATSPublishRetries: getInt("PLATFORM_NATS_PUBLISH_RETRIES", 3),
	}
}
