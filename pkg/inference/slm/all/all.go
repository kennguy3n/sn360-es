// Package all is a blank-import aggregator that registers every
// built-in Tier 2 SLM provider via its package init().
//
// Importing this package from the binary's composition root (see
// cmd/sn360-es/app.go) ensures slm.Registered() returns every
// supported provider at boot. Add a new provider by adding a blank
// import here — no other wiring required.
//
// Keep the import set in lexical order so a quick eyeball check
// confirms parity with pkg/inference/slm/providers/*.
package all

import (
	// llamaserver registers as "llamaserver".
	_ "github.com/kennguy3n/sn360-es/pkg/inference/slm/providers/llamaserver"
	// openai registers as "openai".
	_ "github.com/kennguy3n/sn360-es/pkg/inference/slm/providers/openai"
	// ternarybonsai registers as "ternarybonsai" (deployment default).
	_ "github.com/kennguy3n/sn360-es/pkg/inference/slm/providers/ternarybonsai"
)
