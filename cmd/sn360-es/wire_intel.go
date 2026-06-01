package main

// wire_intel.go registers the four built-in threat-intel providers
// (urlhaus, misp, stix-taxii, csv) by anonymously importing each
// sub-package for the side-effect of its init() block.
//
// Each provider lives in its own pkg/intel/<provider> package and
// calls intel.DefaultRegistry.MustRegister(Provider, New) from an
// init() function. Go only runs those init() blocks when the
// package is loaded, so the binary must import every provider it
// wants to be able to construct — otherwise intel.DefaultRegistry
// stays empty at runtime and every feed Poll() returns
// ErrUnknownProvider.
//
// The pkg/intel/registry.go documentation already names this file
// explicitly:
//
//	// DefaultRegistry holds the four built-in providers. The sub-
//	// packages call DefaultRegistry.MustRegister in their init()
//	// functions so the wiring layer only needs to import the
//	// sub-packages for their side effects (anonymous imports in
//	// cmd/sn360-es/wire_intel.go).
//
// Keep this list aligned with the OpenAPI `provider` enum and the
// migration's `CHECK (provider IN (...))` constraint:
//   - api/openapi.yaml (provider enum on createFeedRequest)
//   - migrations/0023_threat_intel_feeds.up.sql:83
//
// To add a new provider, write the package under pkg/intel/<key>
// with an init() that registers itself, then add the blank import
// here AND extend the OpenAPI enum + the migration's CHECK clause
// in a new up/down migration pair.

import (
	_ "github.com/kennguy3n/sn360-es/pkg/intel/csv"
	_ "github.com/kennguy3n/sn360-es/pkg/intel/misp"
	_ "github.com/kennguy3n/sn360-es/pkg/intel/stixtaxii"
	_ "github.com/kennguy3n/sn360-es/pkg/intel/urlhaus"
)
