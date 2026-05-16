// Package relationship implements the enriched relationship-intelligence
// services described in PROPOSAL.md §7:
//
//   - categories.go: classify the sender-recipient relationship from
//     30-day communication patterns.
//   - vulnerability.go: per-employee vulnerability scoring.
//   - vendor_discovery.go: weekly job that proposes new vendors from
//     recurring external senders.
//   - timing.go: per-sender timing-anomaly detector.
//
// All services are pure-Go, stateless on the hot path, and use the
// in-memory caches provided by the events / cache packages so tests can
// substitute deterministic stores.
package relationship

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// CommunicationSummary is the per-sender / per-recipient aggregate the
// classifier needs. Implementations usually compute it from the tenant
// directory + the last 30 days of message history.
type CommunicationSummary struct {
	SenderDomain     string
	RecipientDomain  string
	InboundCount     int
	OutboundCount    int
	FirstSeen        time.Time
	LastSeen         time.Time
	UniqueRecipients int
	UniqueSenders    int
}

// Validate returns an error if the summary is unusable.
func (c CommunicationSummary) Validate() error {
	if strings.TrimSpace(c.SenderDomain) == "" {
		return errors.New("relationship: sender_domain is required")
	}
	if c.InboundCount < 0 || c.OutboundCount < 0 {
		return errors.New("relationship: counts must be >= 0")
	}
	return nil
}

// ClassifyConfig tweaks the thresholds used by Classify.
type ClassifyConfig struct {
	// PartnerMinInbound and PartnerMinOutbound are the minimum counts in
	// each direction for a partner relationship.
	PartnerMinInbound  int
	PartnerMinOutbound int
	// CustomerInboundRatio is the minimum InboundCount / (InboundCount +
	// OutboundCount) ratio to classify as a customer.
	CustomerInboundRatio float64
	// LapsedAfter is the inactivity duration after which a previously
	// active sender becomes "lapsed".
	LapsedAfter time.Duration
	// RecurringPrefixes is the set of local-parts (case-insensitive)
	// that mark a recurring-service mailbox.
	RecurringPrefixes []string
}

// DefaultClassifyConfig returns the defaults from PROPOSAL.md §7.
func DefaultClassifyConfig() ClassifyConfig {
	return ClassifyConfig{
		PartnerMinInbound:    5,
		PartnerMinOutbound:   5,
		CustomerInboundRatio: 0.8,
		LapsedAfter:          30 * 24 * time.Hour,
		RecurringPrefixes:    []string{"noreply", "no-reply", "donotreply", "do-not-reply", "mailer-daemon", "postmaster", "notifications"},
	}
}

// Classifier maps CommunicationSummaries to RelationshipCategory values.
type Classifier struct {
	cfg ClassifyConfig
	now func() time.Time
}

// NewClassifier constructs a classifier with the supplied config. A zero
// config falls back to DefaultClassifyConfig.
func NewClassifier(cfg ClassifyConfig) *Classifier {
	if cfg.PartnerMinInbound == 0 && cfg.PartnerMinOutbound == 0 && cfg.CustomerInboundRatio == 0 {
		cfg = DefaultClassifyConfig()
	}
	if cfg.LapsedAfter == 0 {
		cfg.LapsedAfter = 30 * 24 * time.Hour
	}
	if len(cfg.RecurringPrefixes) == 0 {
		cfg.RecurringPrefixes = DefaultClassifyConfig().RecurringPrefixes
	}
	return &Classifier{cfg: cfg, now: func() time.Time { return time.Now().UTC() }}
}

// WithClock overrides the time source (mainly for tests).
func (c *Classifier) WithClock(clock func() time.Time) *Classifier {
	c.now = clock
	return c
}

// Classify returns the relationship category for the supplied summary.
// senderLocalPart is the local-part of the sender mailbox (before @).
func (c *Classifier) Classify(_ context.Context, senderLocalPart string, sum CommunicationSummary) (dto.RelationshipCategory, error) {
	if err := sum.Validate(); err != nil {
		return dto.RelationshipUnknown, err
	}
	// Recurring-service mailboxes always win — they are
	// machine-generated, regardless of volume.
	if isRecurring(senderLocalPart, c.cfg.RecurringPrefixes) {
		return dto.RelationshipRecurringService, nil
	}
	// No prior history → first-time external sender.
	if sum.InboundCount == 0 && sum.OutboundCount == 0 {
		return dto.RelationshipFirstTimeExternal, nil
	}
	// Lapsed contact: had history, but the last contact was long ago.
	if !sum.LastSeen.IsZero() && c.now().Sub(sum.LastSeen) >= c.cfg.LapsedAfter {
		return dto.RelationshipLapsedContact, nil
	}
	// Partner: bidirectional traffic above both thresholds.
	if sum.InboundCount >= c.cfg.PartnerMinInbound && sum.OutboundCount >= c.cfg.PartnerMinOutbound {
		return dto.RelationshipPartner, nil
	}
	// Customer: inbound-heavy. Avoid div-by-zero.
	total := sum.InboundCount + sum.OutboundCount
	if total > 0 {
		ratio := float64(sum.InboundCount) / float64(total)
		if ratio >= c.cfg.CustomerInboundRatio && sum.InboundCount > 0 {
			return dto.RelationshipCustomer, nil
		}
	}
	return dto.RelationshipUnknown, nil
}

// Tier1ThresholdModifier returns the absolute threshold delta to apply
// to the Tier 1 PASS threshold for a given relationship category. A
// negative value means "lower the bar (more permissive)" and a positive
// value means "raise the bar (stricter)".
//
// These deltas mirror the defaults from PROPOSAL.md §7:
//
//	Partner             → -10  (lower threshold; relaxed)
//	Customer            → -10  (lower threshold; relaxed)
//	FirstTimeExternal   → +10  (stricter; always escalate to Tier 2)
//	LapsedContact       → +15  (stricter; account-takeover vector)
//	RecurringService    → -20  (relaxed; machine traffic)
func Tier1ThresholdModifier(cat dto.RelationshipCategory) int {
	switch cat {
	case dto.RelationshipPartner, dto.RelationshipCustomer:
		return -10
	case dto.RelationshipFirstTimeExternal:
		return +10
	case dto.RelationshipLapsedContact:
		return +15
	case dto.RelationshipRecurringService:
		return -20
	}
	return 0
}

func isRecurring(localPart string, prefixes []string) bool {
	if localPart == "" {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(localPart))
	for _, p := range prefixes {
		if lower == strings.ToLower(p) {
			return true
		}
		if strings.HasPrefix(lower, strings.ToLower(p)+"-") {
			return true
		}
	}
	return false
}
