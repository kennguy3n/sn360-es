package education

import (
	"context"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

func TestAdaptive_SelectDifficulty(t *testing.T) {
	a, _ := NewAdaptiveDifficulty(newTestLibrary(t))
	cases := []struct {
		score int
		want  dto.DifficultyLevel
	}{
		{0, dto.DifficultyEasy},
		{39, dto.DifficultyEasy},
		{40, dto.DifficultyMedium},
		{69, dto.DifficultyMedium},
		{70, dto.DifficultyHard},
		{100, dto.DifficultyHard},
	}
	for _, c := range cases {
		if got := a.SelectDifficulty(c.score); got != c.want {
			t.Fatalf("SelectDifficulty(%d) = %q; want %q", c.score, got, c.want)
		}
	}
}

func TestAdaptive_AdjustDifficulty(t *testing.T) {
	a, _ := NewAdaptiveDifficulty(newTestLibrary(t))
	cases := []struct {
		base dto.DifficultyLevel
		p    Progression
		want dto.DifficultyLevel
	}{
		{dto.DifficultyEasy, Progression{ConsecutiveDetections: 3}, dto.DifficultyMedium},
		{dto.DifficultyMedium, Progression{ConsecutiveDetections: 5}, dto.DifficultyHard},
		{dto.DifficultyHard, Progression{ConsecutiveDetections: 5}, dto.DifficultyHard},
		{dto.DifficultyHard, Progression{ConsecutiveFailures: 2}, dto.DifficultyMedium},
		{dto.DifficultyMedium, Progression{ConsecutiveFailures: 2}, dto.DifficultyEasy},
		{dto.DifficultyEasy, Progression{ConsecutiveFailures: 4}, dto.DifficultyEasy},
		{dto.DifficultyMedium, Progression{}, dto.DifficultyMedium},
	}
	for _, c := range cases {
		if got := a.AdjustDifficulty(c.base, c.p); got != c.want {
			t.Fatalf("AdjustDifficulty(%q, %+v) = %q; want %q", c.base, c.p, got, c.want)
		}
	}
}

func TestAdaptive_SelectTemplateDeterministic(t *testing.T) {
	a, _ := NewAdaptiveDifficulty(newTestLibrary(t))
	tmpl1, err := a.SelectTemplate(context.Background(), "acme", "u-1", dto.AttackTypeBEC, dto.DifficultyHard)
	if err != nil {
		t.Fatalf("SelectTemplate: %v", err)
	}
	tmpl2, _ := a.SelectTemplate(context.Background(), "acme", "u-1", dto.AttackTypeBEC, dto.DifficultyHard)
	if tmpl1.TemplateID != tmpl2.TemplateID {
		t.Fatalf("selection not deterministic: %q vs %q", tmpl1.TemplateID, tmpl2.TemplateID)
	}
	if tmpl1.Difficulty != dto.DifficultyHard {
		t.Fatalf("difficulty mismatch: %q", tmpl1.Difficulty)
	}
}

func TestAdaptive_SelectForUser_FullFlow(t *testing.T) {
	a, _ := NewAdaptiveDifficulty(newTestLibrary(t))
	tmpl, err := a.SelectForUser(context.Background(), "acme", "u-1", dto.AttackTypeCredentialPhishing,
		35, Progression{ConsecutiveDetections: 3})
	if err != nil {
		t.Fatalf("SelectForUser: %v", err)
	}
	// 35 → Easy; ConsecutiveDetections=3 bumps to Medium.
	if tmpl.Difficulty != dto.DifficultyMedium {
		t.Fatalf("expected adjusted difficulty=medium, got %q", tmpl.Difficulty)
	}
}

func TestAdaptive_RejectsInvalid(t *testing.T) {
	a, _ := NewAdaptiveDifficulty(newTestLibrary(t))
	if _, err := a.SelectTemplate(context.Background(), "", "u", dto.AttackTypeBEC, dto.DifficultyEasy); err == nil {
		t.Fatal("expected error for empty tenant")
	}
	if _, err := a.SelectTemplate(context.Background(), "acme", "", dto.AttackTypeBEC, dto.DifficultyEasy); err == nil {
		t.Fatal("expected error for empty user")
	}
	if _, err := a.SelectTemplate(context.Background(), "acme", "u", dto.AttackType("nope"), dto.DifficultyEasy); err == nil {
		t.Fatal("expected error for bad attack_type")
	}
	if _, err := a.SelectTemplate(context.Background(), "acme", "u", dto.AttackTypeBEC, dto.DifficultyLevel("nope")); err == nil {
		t.Fatal("expected error for bad difficulty")
	}
}
