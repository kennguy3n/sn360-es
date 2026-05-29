package config

import (
	"fmt"
	"time"
)

// Telemetry carries OTel SDK bridge configuration. Wiring is
// centralised here (rather than read straight from os.Getenv in
// the bridge constructor) so that startup config is fully
// inspectable from one place — useful for `sn360-es validate`,
// for snapshot tests of the resolved configuration, and for any
// future operator who has to debug a misconfigured deploy.
type Telemetry struct {
	// OTLPEndpoint is the OTLP/HTTP collector endpoint. When empty
	// the OTel SDK bridge is disabled and the in-process tracer
	// falls back to the no-op exporter — spans are still recorded
	// for W3C traceparent propagation but never leave the process.
	OTLPEndpoint string
	// ServiceVersion populates the OTel resource attribute
	// service.version. Typically the release tag or git SHA.
	ServiceVersion string
}

func loadTelemetry() Telemetry {
	return Telemetry{
		OTLPEndpoint:   getStr("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
		ServiceVersion: getStr("SERVICE_VERSION", ""),
	}
}

// Log carries structured-logging configuration.
type Log struct {
	Level  string
	Format string // "json" or "text"
}

func loadLog() Log {
	return Log{
		Level:  getStr("LOG_LEVEL", "info"),
		Format: getStr("LOG_FORMAT", "json"),
	}
}

// HTTP holds the HTTP server config.
type HTTP struct {
	Host string
	Port int
	// ReadTimeout caps the total time the server spends reading
	// each request, including its body. Mapped to http.Server.ReadTimeout.
	ReadTimeout time.Duration
	// ReadHeaderTimeout caps the time the server spends reading
	// just the request headers, defending against Slowloris-style
	// header-stuffing attacks independent of body upload speed.
	// Mapped to http.Server.ReadHeaderTimeout. Typically shorter
	// than ReadTimeout.
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
}

// Addr returns the listen address (host:port).
func (h HTTP) Addr() string {
	return fmt.Sprintf("%s:%d", h.Host, h.Port)
}

func loadHTTP() HTTP {
	return HTTP{
		Host:              getStr("HTTP_HOST", "0.0.0.0"),
		Port:              getInt("HTTP_PORT", 8080),
		ReadTimeout:       getDuration("HTTP_READ_TIMEOUT", 15*time.Second),
		ReadHeaderTimeout: getDuration("HTTP_READ_HEADER_TIMEOUT", 5*time.Second),
		WriteTimeout:      getDuration("HTTP_WRITE_TIMEOUT", 30*time.Second),
	}
}
