package dto

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func validCommHistoryUpdate() CommHistoryUpdate {
	return CommHistoryUpdate{
		TenantID:      "tenant-1",
		MessageID:     "pseudo-msg-1",
		SenderHash:    []byte{0x01, 0x02, 0x03},
		RecipientHash: []byte{0x04, 0x05, 0x06},
		SenderDomain:  "example.com",
		SentAt:        time.Date(2026, 5, 31, 13, 34, 0, 0, time.UTC),
	}
}

func TestCommHistoryUpdate_Validate_AcceptsCompleteEvent(t *testing.T) {
	if err := validCommHistoryUpdate().Validate(); err != nil {
		t.Fatalf("Validate on a complete event returned %v", err)
	}
}

func TestCommHistoryUpdate_Validate_RejectsMissingFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*CommHistoryUpdate)
	}{
		{"missing TenantID", func(u *CommHistoryUpdate) { u.TenantID = "" }},
		{"missing MessageID", func(u *CommHistoryUpdate) { u.MessageID = "" }},
		{"missing SenderHash", func(u *CommHistoryUpdate) { u.SenderHash = nil }},
		{"empty SenderHash", func(u *CommHistoryUpdate) { u.SenderHash = []byte{} }},
		{"missing RecipientHash", func(u *CommHistoryUpdate) { u.RecipientHash = nil }},
		{"empty RecipientHash", func(u *CommHistoryUpdate) { u.RecipientHash = []byte{} }},
		{"zero SentAt", func(u *CommHistoryUpdate) { u.SentAt = time.Time{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := validCommHistoryUpdate()
			tc.mutate(&u)
			err := u.Validate()
			if !errors.Is(err, ErrCommHistoryUpdateIncomplete) {
				t.Fatalf("Validate returned %v; want ErrCommHistoryUpdateIncomplete", err)
			}
		})
	}
}

func TestCommHistoryUpdate_Validate_AllowsEmptySenderDomain(t *testing.T) {
	u := validCommHistoryUpdate()
	u.SenderDomain = ""
	u.SenderDomainHash = nil
	if err := u.Validate(); err != nil {
		t.Fatalf("Validate rejected an event with empty sender_domain: %v", err)
	}
}

func TestCommHistoryUpdate_DedupID_IsDeterministic(t *testing.T) {
	a := validCommHistoryUpdate().DedupID()
	b := validCommHistoryUpdate().DedupID()
	if a != b {
		t.Fatalf("DedupID drifted across two calls on the same input: %s vs %s", a, b)
	}
}

func TestCommHistoryUpdate_DedupID_IgnoresSentAtAndDomain(t *testing.T) {
	// Same tenant / sender / recipient / message-id pair must
	// produce the same dedup id even if SentAt, SenderDomain, or
	// SenderDomainHash drifted between two retries (e.g. clock skew
	// on the publisher, late-binding domain extraction). This is
	// the property that keeps at-least-once semantics from
	// double-counting on the broker side.
	base := validCommHistoryUpdate()
	alt := base
	alt.SentAt = base.SentAt.Add(7 * time.Second)
	alt.SenderDomain = "different.example"
	alt.SenderDomainHash = []byte{0x99, 0x99}

	if base.DedupID() != alt.DedupID() {
		t.Fatalf("DedupID changed when only non-key fields drifted: base=%s alt=%s",
			base.DedupID(), alt.DedupID())
	}
}

func TestCommHistoryUpdate_DedupID_DistinguishesEveryKeyField(t *testing.T) {
	base := validCommHistoryUpdate()
	mutations := []struct {
		name   string
		mutate func(*CommHistoryUpdate)
	}{
		{"different tenant", func(u *CommHistoryUpdate) { u.TenantID = "tenant-2" }},
		{"different message_id", func(u *CommHistoryUpdate) { u.MessageID = "pseudo-msg-2" }},
		{"different sender_hash", func(u *CommHistoryUpdate) { u.SenderHash = []byte{0xff, 0xff, 0xff} }},
		{"different recipient_hash", func(u *CommHistoryUpdate) { u.RecipientHash = []byte{0xee, 0xee, 0xee} }},
	}
	baseID := base.DedupID()
	seen := map[string]string{"base": baseID}
	for _, m := range mutations {
		u := validCommHistoryUpdate()
		m.mutate(&u)
		got := u.DedupID()
		for label, prev := range seen {
			if prev == got {
				t.Fatalf("DedupID collision: %q produced same id as %q (%s)", m.name, label, got)
			}
		}
		seen[m.name] = got
	}
}

// TestCommHistoryUpdate_DedupID_LengthPrefixingDefeatsBoundaryCollision verifies
// that adjacent byte-slice fields with the same concatenated bytes but
// different boundaries produce different dedup ids. Without length
// prefixing, an attacker (or accidental hash collision) could engineer
// two distinct (sender, recipient) pairs whose concatenated bytes are
// identical — collapsing them into one row at the broker dedup layer.
func TestCommHistoryUpdate_DedupID_LengthPrefixingDefeatsBoundaryCollision(t *testing.T) {
	a := CommHistoryUpdate{
		TenantID:      "tenant-1",
		MessageID:     "msg-1",
		SenderHash:    []byte{0x01, 0x02},
		RecipientHash: []byte{0x03, 0x04},
		SentAt:        time.Now().UTC(),
	}
	b := a
	b.SenderHash = []byte{0x01, 0x02, 0x03}
	b.RecipientHash = []byte{0x04}
	if a.DedupID() == b.DedupID() {
		t.Fatalf("DedupID collapsed two distinct (sender, recipient) byte-slice pairs onto the same id: %s",
			a.DedupID())
	}
}

func TestCommHistoryUpdate_JSON_RoundTrip(t *testing.T) {
	src := validCommHistoryUpdate()
	src.SenderDomainHash = []byte{0xaa, 0xbb, 0xcc}
	payload, err := json.Marshal(src)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var dst CommHistoryUpdate
	if err := json.Unmarshal(payload, &dst); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if dst.TenantID != src.TenantID ||
		dst.MessageID != src.MessageID ||
		string(dst.SenderHash) != string(src.SenderHash) ||
		string(dst.RecipientHash) != string(src.RecipientHash) ||
		string(dst.SenderDomainHash) != string(src.SenderDomainHash) ||
		dst.SenderDomain != src.SenderDomain ||
		!dst.SentAt.Equal(src.SentAt) {
		t.Fatalf("round-trip drift\n src=%+v\n dst=%+v", src, dst)
	}
}

func TestCommHistoryUpdateSubject_IsCanonical(t *testing.T) {
	// Pin the subject string so any silent rename in the const
	// declaration breaks this test. Publishers, consumers, and
	// stream specs all reference this exact string.
	if CommHistoryUpdateSubject != "es.management.comm_history.update" {
		t.Fatalf("CommHistoryUpdateSubject drifted: %q", CommHistoryUpdateSubject)
	}
}
