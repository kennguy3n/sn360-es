// Package education implements the resilience-building services
// described in PROPOSAL.md §5: contextual micro-lessons, phishing
// simulations, resilience scoring, and adaptive difficulty.
//
// The package is wire-compatible with the rest of SN360-ES — services
// expose small constructors that take typed config structs, use slog
// for logging, and publish events through the events.EventService
// surface.
package education

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// MicroLesson is a single 30-second, plain-language explainer wired to a
// specific threat category. Lessons are embedded HTML — same convention
// as the inline banners (no remote assets, inline CSS).
type MicroLesson struct {
	LessonID         string            `json:"lesson_id"`
	Category         constant.Category `json:"category"`
	Title            string            `json:"title"`
	BodyHTML         string            `json:"body_html"`
	EstimatedSeconds int               `json:"estimated_seconds"`
	// Source records how the body was produced: "catalog" for the
	// deterministic embedded lesson, "llm" when the LLM generation path
	// (4C.1) contextualised it. Omitted (empty) on catalog rows loaded
	// from JSON; the service stamps it when serving.
	Source string `json:"source,omitempty"`
}

// Validate returns an error if l is missing required fields.
func (l MicroLesson) Validate() error {
	switch {
	case l.LessonID == "":
		return errors.New("education: lesson_id is required")
	case !l.Category.Valid():
		return fmt.Errorf("education: invalid category %q", l.Category)
	case l.Title == "":
		return errors.New("education: title is required")
	case l.BodyHTML == "":
		return errors.New("education: body_html is required")
	case l.EstimatedSeconds <= 0:
		return errors.New("education: estimated_seconds must be > 0")
	}
	return nil
}

// LessonStore is implemented by callers that want to substitute the
// embedded catalogs at test time. The default loader satisfies it via
// the package-level embed.FS.
type LessonStore interface {
	// Lookup returns the lesson catalog for the requested locale, or
	// false if the locale is not registered.
	Lookup(locale string) (map[constant.Category]MicroLesson, bool)
	// Locales returns the registered locales, sorted.
	Locales() []string
}

// MicroLessonConfig wires the service.
type MicroLessonConfig struct {
	Store          LessonStore
	Publisher      events.EventService
	TriggerSubject string // default "es.education.lesson.trigger"
	FallbackLocale string // default "en"
	Logger         *slog.Logger
	// Generator, when set, contextualises the catalog lesson to the
	// tenant/recipient (4C.1) on Serve calls that carry a non-empty
	// LessonContext. When nil, Serve always returns the deterministic
	// catalog lesson (current behaviour). Wire a FallbackLessonGenerator
	// so a model outage degrades to the catalog rather than failing.
	Generator LessonGenerator
}

// MicroLessonService serves contextual lessons to clients and publishes
// a trigger event each time a lesson is served (so the resilience
// scorer can credit engagement).
type MicroLessonService struct {
	store    LessonStore
	pub      events.EventService
	subject  string
	fallback string
	log      *slog.Logger
	gen      LessonGenerator
}

// NewMicroLessonService constructs the service. Store is required.
// Publisher may be nil; in that case GetLesson is a pure read.
func NewMicroLessonService(cfg MicroLessonConfig) (*MicroLessonService, error) {
	if cfg.Store == nil {
		return nil, errors.New("education: lesson store is required")
	}
	if cfg.TriggerSubject == "" {
		cfg.TriggerSubject = "es.education.lesson.trigger"
	}
	if cfg.FallbackLocale == "" {
		cfg.FallbackLocale = "en"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if _, ok := cfg.Store.Lookup(cfg.FallbackLocale); !ok {
		return nil, fmt.Errorf("education: fallback locale %q not in store", cfg.FallbackLocale)
	}
	return &MicroLessonService{
		store:    cfg.Store,
		pub:      cfg.Publisher,
		subject:  cfg.TriggerSubject,
		fallback: cfg.FallbackLocale,
		log:      cfg.Logger,
		gen:      cfg.Generator,
	}, nil
}

// GetLesson returns the lesson registered for category in locale. If
// the locale is missing or the category has no entry in that locale,
// the fallback locale is consulted. Returns (zero, false) when no
// lesson exists in any locale (this is treated as a configuration bug
// and not silently swallowed).
func (s *MicroLessonService) GetLesson(_ context.Context, category constant.Category, locale string) (MicroLesson, bool) {
	if !category.Valid() {
		return MicroLesson{}, false
	}
	if l, ok := s.tryLocale(locale, category); ok {
		return l, true
	}
	// Try language-only form (e.g. "en-US" -> "en").
	if dash := strings.IndexByte(locale, '-'); dash > 0 {
		if l, ok := s.tryLocale(locale[:dash], category); ok {
			return l, true
		}
	}
	if l, ok := s.tryLocale(s.fallback, category); ok {
		return l, true
	}
	return MicroLesson{}, false
}

func (s *MicroLessonService) tryLocale(locale string, category constant.Category) (MicroLesson, bool) {
	if locale == "" {
		return MicroLesson{}, false
	}
	cat, ok := s.store.Lookup(locale)
	if !ok {
		return MicroLesson{}, false
	}
	l, ok := cat[category]
	return l, ok
}

// Serve fetches the lesson and (if a publisher is wired) emits a
// trigger event. The event payload carries only the lesson_id, category,
// locale, tenant, and pseudonymised user hash — never PII.
func (s *MicroLessonService) Serve(ctx context.Context, req ServeRequest) (MicroLesson, error) {
	if err := req.Validate(); err != nil {
		return MicroLesson{}, err
	}
	l, ok := s.GetLesson(ctx, req.Category, req.Locale)
	if !ok {
		return MicroLesson{}, fmt.Errorf("education: no lesson for category %q", req.Category)
	}
	l.Source = LessonSourceCatalog
	// Contextualise via the LLM path (4C.1) only when a generator is
	// wired AND the caller supplied contextual signal. The generator is
	// expected to be a FallbackLessonGenerator, so any model failure
	// already degrades to the catalog lesson; we still guard here so a
	// misconfigured bare generator can never fail the Serve call.
	if s.gen != nil && !req.Context.IsZero() {
		gen, gerr := s.gen.Generate(ctx, l, req.Context, req.Locale)
		switch {
		case gerr != nil:
			s.log.WarnContext(ctx, "education: lesson generation failed, serving catalog",
				slog.String("tenant_id", req.TenantID),
				slog.String("lesson_id", l.LessonID),
				slog.Any("error", gerr),
			)
		case gen.BodyHTML == "":
			// nil-error but empty body. With the standard
			// FallbackLessonGenerator this branch is unreachable
			// (Tier2 errors on empty content, Deterministic always
			// returns the catalog HTML); a custom generator could hit
			// it, so log at debug level for observability rather than
			// degrading silently.
			s.log.DebugContext(ctx, "education: generator returned empty lesson body, serving catalog",
				slog.String("tenant_id", req.TenantID),
				slog.String("lesson_id", l.LessonID),
			)
		default:
			l = gen
		}
	}
	if s.pub != nil {
		envelope := struct {
			TenantID  string `json:"tenant_id"`
			UserHash  string `json:"user_hash,omitempty"`
			LessonID  string `json:"lesson_id"`
			Category  string `json:"category"`
			Locale    string `json:"locale"`
			Source    string `json:"source"`
			ServedAt  string `json:"served_at"`
			MessageID string `json:"pseudo_message_id,omitempty"`
		}{
			TenantID:  req.TenantID,
			UserHash:  req.UserHash,
			LessonID:  l.LessonID,
			Category:  string(req.Category),
			Locale:    req.Locale,
			Source:    l.Source,
			ServedAt:  time.Now().UTC().Format(time.RFC3339),
			MessageID: req.PseudoMessageID,
		}
		data, err := json.Marshal(envelope)
		if err != nil {
			return MicroLesson{}, fmt.Errorf("education: marshal trigger: %w", err)
		}
		if err := s.pub.Publish(ctx, s.subject, data,
			events.WithTenantID(req.TenantID),
			events.WithEventType("education.lesson.trigger"),
		); err != nil {
			// Publishing the trigger is best-effort; we still serve the
			// lesson but log the failure so ops can find it.
			s.log.WarnContext(ctx, "education: publish trigger failed",
				slog.String("tenant_id", req.TenantID),
				slog.String("lesson_id", l.LessonID),
				slog.Any("error", err),
			)
		}
	}
	return l, nil
}

// ServeRequest carries the inputs needed to serve a lesson.
type ServeRequest struct {
	TenantID        string
	UserHash        string
	Category        constant.Category
	Locale          string
	PseudoMessageID string
	// Context carries optional contextualisation signals (industry,
	// role, threat profile). When non-empty and a Generator is wired,
	// the served lesson is contextualised via the LLM path (4C.1).
	Context LessonContext
}

// Validate returns an error if the request is missing required fields.
func (r ServeRequest) Validate() error {
	switch {
	case r.TenantID == "":
		return errors.New("education: tenant_id is required")
	case !r.Category.Valid():
		return fmt.Errorf("education: invalid category %q", r.Category)
	}
	return nil
}

// --- Embedded catalog implementation ----------------------------------------

//go:embed lessons/*.json
var embeddedLessons embed.FS

// embeddedStore loads lessons from embedded JSON files. Lessons are
// parsed once at construction time so subsequent lookups are pure
// in-memory map reads.
type embeddedStore struct {
	mu    sync.RWMutex
	byLoc map[string]map[constant.Category]MicroLesson
}

func (e *embeddedStore) Lookup(locale string) (map[constant.Category]MicroLesson, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	cat, ok := e.byLoc[locale]
	return cat, ok
}

func (e *embeddedStore) Locales() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]string, 0, len(e.byLoc))
	for k := range e.byLoc {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// DefaultLessonStore loads the embedded en.json (and any future locale
// catalogs) into an in-memory store.
func DefaultLessonStore() (LessonStore, error) {
	return loadEmbeddedStore(embeddedLessons, "lessons")
}

func loadEmbeddedStore(fsys fs.FS, root string) (LessonStore, error) {
	entries, err := fs.ReadDir(fsys, root)
	if err != nil {
		return nil, fmt.Errorf("education: read dir %s: %w", root, err)
	}
	out := &embeddedStore{byLoc: map[string]map[constant.Category]MicroLesson{}}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		locale := strings.TrimSuffix(e.Name(), ".json")
		blob, err := fs.ReadFile(fsys, path.Join(root, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("education: read %s: %w", e.Name(), err)
		}
		raw := map[string]MicroLesson{}
		if err := json.Unmarshal(blob, &raw); err != nil {
			return nil, fmt.Errorf("education: parse %s: %w", e.Name(), err)
		}
		byCat := make(map[constant.Category]MicroLesson, len(raw))
		for key, lesson := range raw {
			cat := constant.Category(key)
			if !cat.Valid() {
				return nil, fmt.Errorf("education: %s: unknown category %q", e.Name(), key)
			}
			if lesson.Category == "" {
				lesson.Category = cat
			}
			if err := lesson.Validate(); err != nil {
				return nil, fmt.Errorf("education: %s: %s: %w", e.Name(), key, err)
			}
			byCat[cat] = lesson
		}
		out.byLoc[locale] = byCat
	}
	if len(out.byLoc) == 0 {
		return nil, errors.New("education: no lesson catalogs found")
	}
	return out, nil
}

// StaticLessonStore is a convenience wrapper for tests that want to
// build an in-memory store from literals without round-tripping JSON.
type StaticLessonStore struct {
	mu    sync.RWMutex
	byLoc map[string]map[constant.Category]MicroLesson
}

// NewStaticLessonStore returns a store seeded from the supplied map.
func NewStaticLessonStore(byLoc map[string]map[constant.Category]MicroLesson) *StaticLessonStore {
	cp := make(map[string]map[constant.Category]MicroLesson, len(byLoc))
	for loc, cat := range byLoc {
		inner := make(map[constant.Category]MicroLesson, len(cat))
		for k, v := range cat {
			inner[k] = v
		}
		cp[loc] = inner
	}
	return &StaticLessonStore{byLoc: cp}
}

// Lookup implements LessonStore.
func (s *StaticLessonStore) Lookup(locale string) (map[constant.Category]MicroLesson, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cat, ok := s.byLoc[locale]
	return cat, ok
}

// Locales implements LessonStore.
func (s *StaticLessonStore) Locales() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.byLoc))
	for k := range s.byLoc {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
