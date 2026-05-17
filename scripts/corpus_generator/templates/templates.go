// Package templates contains per-category synthetic email generators
// used by the SN360-ES corpus tool. Each category file (e.g.
// likely_phishing.go) exports a Generate function that produces one
// TestEmail-shaped Payload + signals tuple. The top-level generator
// (scripts/corpus_generator) wires those Payloads into the canonical
// TestEmail struct documented in scripts/corpus_schema.json.
//
// All randomness is drawn from a *rand.Rand passed in via Options so
// the entire corpus is reproducible for a given --seed.
package templates

import (
	"math/rand"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// Level expresses signal density. easy = obvious, medium = mixed,
// hard = adversarial / subtle.
type Level string

const (
	LevelEasy   Level = "easy"
	LevelMedium Level = "medium"
	LevelHard   Level = "hard"
)

// Locale is an ISO 639-1 code for the email's primary natural-language
// content. The supported set matches the SN360-ES i18n catalogs.
type Locale string

const (
	LocaleEN Locale = "en"
	LocaleTH Locale = "th"
	LocaleJA Locale = "ja"
	LocaleKO Locale = "ko"
	LocaleZH Locale = "zh"
	LocaleVI Locale = "vi"
)

// Attachment is a JSON-serialisable attachment descriptor matching the
// payload.attachments items in scripts/corpus_schema.json.
type Attachment struct {
	Filename       string `json:"filename"`
	ContentType    string `json:"content_type"`
	SizeBytes      int    `json:"size_bytes,omitempty"`
	SHA256         string `json:"sha256,omitempty"`
	DecoyExtension bool   `json:"decoy_extension,omitempty"`
	MacroEnabled   bool   `json:"macro_enabled,omitempty"`
	QRTargetURL    string `json:"qr_target_url,omitempty"`
}

// Payload mirrors the `payload` object in scripts/corpus_schema.json.
type Payload struct {
	From        string            `json:"from"`
	FromDisplay string            `json:"from_display,omitempty"`
	To          string            `json:"to"`
	Subject     string            `json:"subject"`
	BodyText    string            `json:"body_text"`
	BodyHTML    string            `json:"body_html,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Attachments []Attachment      `json:"attachments,omitempty"`
}

// Options is the per-email input handed to every Generator.
type Options struct {
	// Rand is the deterministic PRNG. Templates MUST NOT use the
	// global rand source — all variation must come from r so corpus
	// runs are reproducible.
	Rand *rand.Rand
	// IsThreat true means produce a malicious variant; false means
	// produce a benign look-alike.
	IsThreat bool
	// Difficulty controls signal density (easy/medium/hard).
	Difficulty Level
	// Locale is the natural language for subject/body.
	Locale Locale
	// Index is the per-category sequence number, useful for stable
	// recipient / sender enumeration.
	Index int
	// Tenant is the recipient's tenant identity used to seed internal
	// addresses (e.g. "acme.example").
	Tenant string
}

// Result is the output of a template. The top-level generator merges
// these fields into a TestEmail, adding category/tier/score metadata.
type Result struct {
	Payload         Payload
	AttackType      string
	Description     string
	ExpectedSignals []string
}

// Generator is the per-category synthetic email builder.
type Generator interface {
	// Category returns the constant.Category this generator produces.
	Category() constant.Category
	// Generate produces a single email variant.
	Generate(opts Options) Result
}

// Registry maps categories to generators. Use DefaultRegistry to get
// the canonical set wired up.
type Registry struct {
	gens map[constant.Category]Generator
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{gens: make(map[constant.Category]Generator)}
}

// Register installs g for g.Category(). Panics on duplicate
// registration; this is a build-time invariant.
func (r *Registry) Register(g Generator) {
	if _, ok := r.gens[g.Category()]; ok {
		panic("templates: duplicate generator for " + string(g.Category()))
	}
	r.gens[g.Category()] = g
}

// Get returns the generator for cat, or ok=false if none is registered.
func (r *Registry) Get(cat constant.Category) (Generator, bool) {
	g, ok := r.gens[cat]
	return g, ok
}

// Categories returns the set of registered categories in stable order
// (matching constant.AllCategories).
func (r *Registry) Categories() []constant.Category {
	out := make([]constant.Category, 0, len(r.gens))
	for _, c := range constant.AllCategories {
		if _, ok := r.gens[c]; ok {
			out = append(out, c)
		}
	}
	return out
}

// DefaultRegistry returns a registry pre-populated with one generator
// per category in constant.AllCategories.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(NewLikelyPhishing())
	r.Register(NewBECImpersonation())
	r.Register(NewLookalikeDomain())
	r.Register(NewSuspiciousURL())
	r.Register(NewSuspiciousAttachment())
	r.Register(NewFirstContactExternal())
	r.Register(NewAccountTakeoverSuspected())
	r.Register(NewVendorCompromise())
	r.Register(NewCredentialHarvesting())
	r.Register(NewInvoiceFraud())
	r.Register(NewQRPhishing())
	r.Register(NewScamFraud())
	r.Register(NewAuthFailed())
	r.Register(NewInternalTrusted())
	r.Register(NewVendorTrusted())
	r.Register(NewNewsletter())
	return r
}

// pick returns one element from xs chosen by r.
func pick[T any](r *rand.Rand, xs []T) T {
	return xs[r.Intn(len(xs))]
}
