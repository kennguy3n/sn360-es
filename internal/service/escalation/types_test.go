// Copyright 2024-2026 SN360. All rights reserved.
// Use of this source code is governed by the proprietary license
// that can be found in the LICENSE file.

package escalation_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/escalation"
)

// -- JSON round-trip: producer-side bytes from
// services/soc-triage/internal/events.IncidentResolved must
// deserialise into the consumer-side
// escalation.IncidentResolved with all fields preserved. This
// pins the cross-repo wire contract on the consumer side; the
// producer side has a parallel test that pins it from its
// view.
func TestIncidentResolved_RoundTrip(t *testing.T) {
	want := escalation.IncidentResolved{
		IncidentID:   "inc-rt-1",
		TenantID:     "tenant-rt",
		Resolution:   escalation.ResolutionConfirmedThreat,
		ResolvedAt:   time.Date(2025, 2, 1, 14, 30, 45, 123_000_000, time.UTC),
		ResolvedBy:   "analyst-pseudo-7f3e",
		AnalystNotes: "Confirmed via VirusTotal hash match.",
		RelatedEmail: &escalation.EmailLink{
			PseudoMessageID: "pmid-abc",
			SenderHash:      "shash-def",
			CorrelationID:   "corr-xyz",
		},
		DedupID: "dd-aaaa-bbbb",
	}
	body, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got escalation.IncidentResolved
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	// time.Time equality must use Equal (different wall/mono
	// clocks compare unequal otherwise).
	if !got.ResolvedAt.Equal(want.ResolvedAt) {
		t.Errorf("ResolvedAt = %v; want %v", got.ResolvedAt, want.ResolvedAt)
	}
	got.ResolvedAt = want.ResolvedAt
	if got.IncidentID != want.IncidentID ||
		got.TenantID != want.TenantID ||
		got.Resolution != want.Resolution ||
		got.ResolvedBy != want.ResolvedBy ||
		got.AnalystNotes != want.AnalystNotes ||
		got.DedupID != want.DedupID {
		t.Errorf("scalar mismatch: got %+v want %+v", got, want)
	}
	if got.RelatedEmail == nil {
		t.Fatalf("RelatedEmail decoded as nil")
	}
	if *got.RelatedEmail != *want.RelatedEmail {
		t.Errorf("RelatedEmail = %+v; want %+v", got.RelatedEmail, want.RelatedEmail)
	}
}

// -- omitempty contract: an IncidentResolved with no
// RelatedEmail / AnalystNotes must encode without those keys
// at all, not with empty values. Consumer parsers should not
// see "related_email": null in the wire.
func TestIncidentResolved_OmitEmpty(t *testing.T) {
	ev := escalation.IncidentResolved{
		IncidentID: "x",
		TenantID:   "t",
		Resolution: escalation.ResolutionInconclusive,
		ResolvedAt: time.Now().UTC(),
		ResolvedBy: "a",
		DedupID:    "d",
	}
	body, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(body)
	for _, banned := range []string{`"analyst_notes"`, `"related_email"`} {
		if containsString(s, banned) {
			t.Errorf("wire = %s; want %s key suppressed by omitempty", s, banned)
		}
	}
}

// containsString is a one-line strings.Contains stand-in to
// avoid importing strings just for one test.
func containsString(s, needle string) bool {
	for i := 0; i+len(needle) <= len(s); i++ {
		if s[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// -- EmailLink.HasIdentifier covers nil, all-empty, and the
// two single-identifier paths. Pin the consumer-side gate so
// resolver tests don't have to re-implement the predicate.
func TestEmailLink_HasIdentifier(t *testing.T) {
	cases := []struct {
		name string
		link *escalation.EmailLink
		want bool
	}{
		{name: "nil", link: nil, want: false},
		{name: "all empty", link: &escalation.EmailLink{}, want: false},
		{name: "only sender_hash", link: &escalation.EmailLink{SenderHash: "h"}, want: false},
		{name: "pseudo only", link: &escalation.EmailLink{PseudoMessageID: "p"}, want: true},
		{name: "correlation only", link: &escalation.EmailLink{CorrelationID: "c"}, want: true},
		{name: "both", link: &escalation.EmailLink{PseudoMessageID: "p", CorrelationID: "c"}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.link.HasIdentifier(); got != tc.want {
				t.Errorf("HasIdentifier() = %v; want %v", got, tc.want)
			}
		})
	}
}

// -- OutcomeKind constants are exported as their wire-stable
// strings. Lock the values so downstream telemetry consumers
// can switch on them without binding to internal numeric
// codes.
func TestOutcomeKind_Values(t *testing.T) {
	cases := []struct {
		k    escalation.OutcomeKind
		want string
	}{
		{escalation.OutcomeFlipped, "flipped"},
		{escalation.OutcomeNoop, "noop"},
		{escalation.OutcomeSkipped, "skipped"},
		{escalation.OutcomeDuplicate, "duplicate"},
	}
	for _, tc := range cases {
		if string(tc.k) != tc.want {
			t.Errorf("OutcomeKind = %q; want %q", tc.k, tc.want)
		}
	}
}
