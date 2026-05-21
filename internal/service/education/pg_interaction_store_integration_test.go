//go:build integration
// +build integration

package education_test

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

func TestPostgresInteractionStore_AppendAndList(t *testing.T) {
	_, _, interactions := openEducationDB(t)
	ctx := context.Background()

	t0 := time.Date(2025, 4, 1, 9, 0, 0, 0, time.UTC)
	seed := []dto.UserInteraction{
		{CampaignID: "camp-x", UserHash: "u-1", Action: dto.InteractionDelivered, OccurredAt: t0},
		{CampaignID: "camp-x", UserHash: "u-1", Action: dto.InteractionOpened, OccurredAt: t0.Add(time.Minute)},
		{CampaignID: "camp-x", UserHash: "u-2", Action: dto.InteractionClickedLink, OccurredAt: t0.Add(2 * time.Minute)},
		{CampaignID: "camp-x", UserHash: "u-3", Action: dto.InteractionReportedPhishing, OccurredAt: t0.Add(3 * time.Minute)},
		// camp-y is isolated — must not bleed into camp-x results.
		{CampaignID: "camp-y", UserHash: "u-9", Action: dto.InteractionSubmittedCredentials, OccurredAt: t0},
	}
	for _, i := range seed {
		if err := interactions.Append(ctx, i); err != nil {
			t.Fatalf("Append %s/%s: %v", i.CampaignID, i.Action, err)
		}
	}
	got, err := interactions.ListByCampaign(ctx, "camp-x")
	if err != nil {
		t.Fatalf("ListByCampaign: %v", err)
	}
	// 3 users on camp-x — u-1 with two flags (delivered + opened),
	// u-2 with one (clicked), u-3 with one (reported). That's 4
	// emitted UserInteractions.
	if len(got) != 4 {
		t.Fatalf("expected 4 interactions, got %d (%+v)", len(got), summarise(got))
	}
	counts := map[dto.UserInteractionType]int{}
	for _, i := range got {
		counts[i.Action]++
	}
	want := map[dto.UserInteractionType]int{
		dto.InteractionDelivered:        1,
		dto.InteractionOpened:           1,
		dto.InteractionClickedLink:      1,
		dto.InteractionReportedPhishing: 1,
	}
	for k, v := range want {
		if counts[k] != v {
			t.Fatalf("counts[%s]=%d, want %d (all: %+v)", k, counts[k], v, counts)
		}
	}
}

func TestPostgresInteractionStore_UpsertSemanticsDoNotDuplicate(t *testing.T) {
	_, _, interactions := openEducationDB(t)
	ctx := context.Background()

	t0 := time.Date(2025, 4, 1, 9, 0, 0, 0, time.UTC)
	// Same user, same campaign, same action recorded three times.
	// Without upsert semantics this produces three rows and triple-
	// counts the open in any aggregation downstream.
	for i := 0; i < 3; i++ {
		if err := interactions.Append(ctx, dto.UserInteraction{
			CampaignID: "camp-dedup",
			UserHash:   "u-1",
			Action:     dto.InteractionOpened,
			OccurredAt: t0.Add(time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	got, err := interactions.ListByCampaign(ctx, "camp-dedup")
	if err != nil {
		t.Fatalf("ListByCampaign: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 deduped interaction, got %d (%+v)", len(got), summarise(got))
	}
	if got[0].Action != dto.InteractionOpened || got[0].UserHash != "u-1" {
		t.Fatalf("unexpected payload after dedup: %+v", got[0])
	}
}

func TestPostgresInteractionStore_MultipleActionsPerUserAccumulate(t *testing.T) {
	_, _, interactions := openEducationDB(t)
	ctx := context.Background()

	t0 := time.Date(2025, 4, 1, 9, 0, 0, 0, time.UTC)
	// A real campaign target opens, clicks, and submits creds —
	// each action should be retained as a distinct boolean column
	// on the SAME row (no row fan-out).
	actions := []dto.UserInteractionType{
		dto.InteractionOpened,
		dto.InteractionClickedLink,
		dto.InteractionSubmittedCredentials,
	}
	timestamps := map[dto.UserInteractionType]time.Time{}
	for i, a := range actions {
		ts := t0.Add(time.Duration(i) * time.Minute)
		timestamps[a] = ts
		if err := interactions.Append(ctx, dto.UserInteraction{
			CampaignID: "camp-merge",
			UserHash:   "u-1",
			Action:     a,
			OccurredAt: ts,
		}); err != nil {
			t.Fatalf("Append %s: %v", a, err)
		}
	}
	got, err := interactions.ListByCampaign(ctx, "camp-merge")
	if err != nil {
		t.Fatalf("ListByCampaign: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 emitted actions for one user, got %d (%+v)", len(got), summarise(got))
	}
	seen := map[dto.UserInteractionType]bool{}
	for _, i := range got {
		if i.UserHash != "u-1" {
			t.Fatalf("unexpected user_hash %q", i.UserHash)
		}
		seen[i.Action] = true
		// Per-action timestamp must come back as the moment that
		// specific action was first observed, NOT a single shared
		// updated_at value for the row. This is the semantic that
		// makes Postgres-backed installs match the memory store's
		// per-event timeline.
		want, ok := timestamps[i.Action]
		if !ok {
			t.Fatalf("unexpected action returned: %s", i.Action)
		}
		if !i.OccurredAt.Equal(want) {
			t.Fatalf("OccurredAt for %s = %s, want %s", i.Action, i.OccurredAt, want)
		}
	}
	for _, a := range actions {
		if !seen[a] {
			t.Fatalf("missing action %s in %+v", a, seen)
		}
	}
}

// TestPostgresInteractionStore_PerActionTimestampStable verifies the
// COALESCE-on-upsert semantics: when the same action is re-recorded
// for a target, the per-action timestamp must stick to the FIRST
// observation rather than drifting forward on every replay. updated_at
// is allowed to drift; only the per-action <action>_at columns are
// pinned. This guarantees that downstream timeline analysis sees a
// monotonic record of when each phase of the user journey first
// happened, even under at-least-once event delivery.
func TestPostgresInteractionStore_PerActionTimestampStable(t *testing.T) {
	_, _, interactions := openEducationDB(t)
	ctx := context.Background()

	first := time.Date(2025, 4, 1, 9, 0, 0, 0, time.UTC)
	later := first.Add(15 * time.Minute)
	for _, ts := range []time.Time{first, later} {
		if err := interactions.Append(ctx, dto.UserInteraction{
			CampaignID: "camp-stable",
			UserHash:   "u-1",
			Action:     dto.InteractionOpened,
			OccurredAt: ts,
		}); err != nil {
			t.Fatalf("Append at %s: %v", ts, err)
		}
	}
	got, err := interactions.ListByCampaign(ctx, "camp-stable")
	if err != nil {
		t.Fatalf("ListByCampaign: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected single deduped row, got %d (%+v)", len(got), summarise(got))
	}
	if !got[0].OccurredAt.Equal(first) {
		t.Fatalf("OccurredAt = %s, want first observation %s (later replay must not bump per-action ts)",
			got[0].OccurredAt, first)
	}
}

func summarise(items []dto.UserInteraction) string {
	if len(items) == 0 {
		return "[]"
	}
	cpy := make([]dto.UserInteraction, len(items))
	copy(cpy, items)
	sort.Slice(cpy, func(i, j int) bool {
		if cpy[i].UserHash != cpy[j].UserHash {
			return cpy[i].UserHash < cpy[j].UserHash
		}
		return cpy[i].Action < cpy[j].Action
	})
	out := "["
	for i, it := range cpy {
		if i > 0 {
			out += ", "
		}
		out += string(it.Action) + "/" + it.UserHash
	}
	out += "]"
	return out
}
