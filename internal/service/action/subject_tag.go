package action

import (
	"errors"
	"fmt"
	"strings"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// SubjectTagger prepends an optional, configurable subject-line tag
// (e.g. "[SN360: WARN]") to the Subject of an email at Warning+ tiers.
//
// Per PROPOSAL.md §6, the tag is OFF by default; tenants opt in when
// they want a coarse client-side filter that does not depend on
// downstream banner rendering. The tagger never modifies subjects for
// tiers below the configured floor and is idempotent: re-tagging an
// already-tagged subject is a no-op.
type SubjectTagger struct {
	cfg SubjectTagConfig
}

// SubjectTagConfig configures SubjectTagger.
type SubjectTagConfig struct {
	// Enabled toggles the tagger at runtime. When false, Tag returns
	// the input subject unchanged for every tier. Default: false.
	Enabled bool

	// MinTier is the lowest tier that triggers tagging. Tiers below
	// this severity are passed through untouched. Default: Warning.
	MinTier constant.Tier

	// Labels maps a tier to its tag text (e.g. {Warning: "WARN"}). The
	// rendered tag is "[{Prefix}: {Label}] " (note the trailing space).
	// Tiers absent from the map use DefaultSubjectTagLabels. The map
	// is consulted with tier as key.
	Labels map[constant.Tier]string

	// Prefix is the literal prepended to the tag (default "SN360").
	// Useful for tenants that want a custom brand prefix.
	Prefix string
}

// DefaultSubjectTagLabels are the conventional short labels used for
// each tier. Stored on the package so callers can extend the defaults
// without redeclaring everything.
var DefaultSubjectTagLabels = map[constant.Tier]string{
	constant.TierWarning:  "WARN",
	constant.TierHighRisk: "RISK",
	constant.TierBlocked:  "BLOCK",
}

// NewSubjectTagger constructs a SubjectTagger. An error is returned for
// pathological config (e.g. Enabled with no labels at any qualifying
// tier). When MinTier or Prefix are zero values, sensible defaults are
// applied.
func NewSubjectTagger(cfg SubjectTagConfig) (*SubjectTagger, error) {
	if cfg.MinTier == "" {
		cfg.MinTier = constant.TierWarning
	}
	if !cfg.MinTier.Valid() {
		return nil, fmt.Errorf("subject_tag: invalid min tier %q", cfg.MinTier)
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "SN360"
	}
	if len(cfg.Labels) == 0 {
		// Copy DefaultSubjectTagLabels so the tagger owns its map; the
		// package-level default must not be aliased into every instance
		// (later mutations would race with Tag/Untag readers).
		cfg.Labels = make(map[constant.Tier]string, len(DefaultSubjectTagLabels))
		for k, v := range DefaultSubjectTagLabels {
			cfg.Labels[k] = v
		}
	}
	if cfg.Enabled {
		// At least one tier at or above MinTier must have a label.
		var hasMatch bool
		for t, label := range cfg.Labels {
			if !t.Valid() {
				return nil, fmt.Errorf("subject_tag: invalid label tier %q", t)
			}
			if strings.TrimSpace(label) == "" {
				return nil, fmt.Errorf("subject_tag: empty label for tier %q", t)
			}
			if t.Severity() >= cfg.MinTier.Severity() {
				hasMatch = true
			}
		}
		if !hasMatch {
			return nil, errors.New("subject_tag: no label defined at or above min tier")
		}
	}
	return &SubjectTagger{cfg: cfg}, nil
}

// Tag returns subject with the appropriate SN360 tag prefix applied or
// the original subject unchanged if tagging does not apply. The bool
// indicates whether a tag was added in this call (false for already-
// tagged subjects, sub-floor tiers, or when the tagger is disabled).
func (s *SubjectTagger) Tag(subject string, tier constant.Tier) (string, bool) {
	if !s.cfg.Enabled {
		return subject, false
	}
	if !tier.Valid() || tier.Severity() < s.cfg.MinTier.Severity() {
		return subject, false
	}
	label, ok := s.cfg.Labels[tier]
	if !ok || strings.TrimSpace(label) == "" {
		return subject, false
	}
	tag := s.renderTag(label)
	if s.alreadyTagged(subject) {
		return subject, false
	}
	if subject == "" {
		return tag, true
	}
	return tag + subject, true
}

// Untag removes a leading SN360 tag from subject (any tier, any label
// that uses the configured prefix). Returns the cleaned subject and
// true when a tag was stripped. Useful for forwarding flows that want
// the original subject without the marker.
func (s *SubjectTagger) Untag(subject string) (string, bool) {
	open := "[" + s.cfg.Prefix + ":"
	if !strings.HasPrefix(subject, open) {
		return subject, false
	}
	end := strings.Index(subject, "]")
	if end < 0 {
		return subject, false
	}
	rest := subject[end+1:]
	// Skip exactly one space if present (renderTag emits trailing space).
	rest = strings.TrimPrefix(rest, " ")
	return rest, true
}

// Enabled reports whether the tagger will actually modify subjects.
func (s *SubjectTagger) Enabled() bool { return s.cfg.Enabled }

// MinTier returns the configured floor tier.
func (s *SubjectTagger) MinTier() constant.Tier { return s.cfg.MinTier }

func (s *SubjectTagger) renderTag(label string) string {
	return "[" + s.cfg.Prefix + ": " + label + "] "
}

func (s *SubjectTagger) alreadyTagged(subject string) bool {
	return strings.HasPrefix(subject, "["+s.cfg.Prefix+":")
}
