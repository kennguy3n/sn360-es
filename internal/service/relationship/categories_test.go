package relationship

import (
	"context"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestClassifier_RecurringWinsRegardlessOfVolume(t *testing.T) {
	c := NewClassifier(ClassifyConfig{})
	got, err := c.Classify(context.Background(), "noreply", CommunicationSummary{
		SenderDomain: "acme.com", InboundCount: 100, OutboundCount: 100,
	})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got != dto.RelationshipRecurringService {
		t.Fatalf("got %q want recurring", got)
	}
}

func TestClassifier_FirstTimeExternal(t *testing.T) {
	c := NewClassifier(ClassifyConfig{})
	got, _ := c.Classify(context.Background(), "alice", CommunicationSummary{SenderDomain: "new.com"})
	if got != dto.RelationshipFirstTimeExternal {
		t.Fatalf("got %q want first-time", got)
	}
}

func TestClassifier_Lapsed(t *testing.T) {
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	c := NewClassifier(ClassifyConfig{}).WithClock(fixedClock(now))
	got, _ := c.Classify(context.Background(), "alice", CommunicationSummary{
		SenderDomain: "old.com", InboundCount: 10, OutboundCount: 10,
		LastSeen: now.Add(-45 * 24 * time.Hour),
	})
	if got != dto.RelationshipLapsedContact {
		t.Fatalf("got %q want lapsed", got)
	}
}

func TestClassifier_Partner(t *testing.T) {
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	c := NewClassifier(ClassifyConfig{}).WithClock(fixedClock(now))
	got, _ := c.Classify(context.Background(), "ops", CommunicationSummary{
		SenderDomain: "partner.com", InboundCount: 20, OutboundCount: 15,
		LastSeen: now.Add(-3 * 24 * time.Hour),
	})
	if got != dto.RelationshipPartner {
		t.Fatalf("got %q want partner", got)
	}
}

func TestClassifier_Customer(t *testing.T) {
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	c := NewClassifier(ClassifyConfig{}).WithClock(fixedClock(now))
	got, _ := c.Classify(context.Background(), "bob", CommunicationSummary{
		SenderDomain: "customer.com", InboundCount: 30, OutboundCount: 2,
		LastSeen: now.Add(-1 * 24 * time.Hour),
	})
	if got != dto.RelationshipCustomer {
		t.Fatalf("got %q want customer", got)
	}
}

func TestClassifier_Unknown(t *testing.T) {
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	c := NewClassifier(ClassifyConfig{}).WithClock(fixedClock(now))
	got, _ := c.Classify(context.Background(), "charlie", CommunicationSummary{
		SenderDomain: "occasional.com", InboundCount: 2, OutboundCount: 2,
		LastSeen: now.Add(-5 * 24 * time.Hour),
	})
	if got != dto.RelationshipUnknown {
		t.Fatalf("got %q want unknown", got)
	}
}

func TestClassifier_ValidatesInput(t *testing.T) {
	c := NewClassifier(ClassifyConfig{})
	if _, err := c.Classify(context.Background(), "x", CommunicationSummary{}); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestTier1ThresholdModifier(t *testing.T) {
	cases := []struct {
		in   dto.RelationshipCategory
		want int
	}{
		{dto.RelationshipPartner, -10},
		{dto.RelationshipCustomer, -10},
		{dto.RelationshipFirstTimeExternal, 10},
		{dto.RelationshipLapsedContact, 15},
		{dto.RelationshipRecurringService, -20},
		{dto.RelationshipUnknown, 0},
	}
	for _, c := range cases {
		if got := Tier1ThresholdModifier(c.in); got != c.want {
			t.Fatalf("Tier1ThresholdModifier(%q) = %d; want %d", c.in, got, c.want)
		}
	}
}
