package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// captureLog returns a slog.Logger that writes JSON records to a
// buffer, wrapped by LogSanitizer. The buffer is exposed so tests
// can decode the final, post-sanitisation output.
func captureLog(t *testing.T) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	base := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(NewLogSanitizer(base, nil)), &buf
}

// decodeRecords returns each JSON record in buf as a map.
func decodeRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	out := []map[string]any{}
	for _, line := range bytes.Split(buf.Bytes(), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

func TestLogSanitizer_MasksEmailInMessage(t *testing.T) {
	logger, buf := captureLog(t)
	logger.Info("user alice@example.com signed in")
	recs := decodeRecords(t, buf)
	if len(recs) != 1 {
		t.Fatalf("recs=%d", len(recs))
	}
	msg := recs[0]["msg"].(string)
	if strings.Contains(msg, "alice@example.com") {
		t.Fatalf("raw email leaked: %q", msg)
	}
	if !strings.Contains(msg, "***@example.com") {
		t.Fatalf("expected masked email, got %q", msg)
	}
}

func TestLogSanitizer_MasksEmailInStringAttr(t *testing.T) {
	logger, buf := captureLog(t)
	logger.Info("login", slog.String("from", "Forwarded by carol@acme.com via ops"))
	recs := decodeRecords(t, buf)
	got := recs[0]["from"].(string)
	if strings.Contains(got, "carol@acme.com") {
		t.Fatalf("email leaked: %q", got)
	}
	if !strings.Contains(got, "***@acme.com") {
		t.Fatalf("expected masked email, got %q", got)
	}
}

func TestLogSanitizer_ElidesSubjectKey(t *testing.T) {
	logger, buf := captureLog(t)
	logger.Info("evaluate",
		slog.String("subject", "Urgent: wire transfer required"),
		slog.String("email_subject", "Login alert for user@example.com"),
		slog.String("raw_subject_line", "Hello"),
		slog.String("description", "kept as-is"),
	)
	rec := decodeRecords(t, buf)[0]
	for _, k := range []string{"subject", "email_subject", "raw_subject_line"} {
		v, ok := rec[k].(string)
		if !ok || v != "***" {
			t.Fatalf("key %q: got %v, want \"***\"", k, rec[k])
		}
	}
	if got := rec["description"].(string); got != "kept as-is" {
		t.Fatalf("non-subject string mutated: %q", got)
	}
}

func TestLogSanitizer_RecursesIntoGroups(t *testing.T) {
	logger, buf := captureLog(t)
	logger.Info("nested",
		slog.Group("envelope",
			slog.String("from", "dan@example.com"),
			slog.String("subject", "secret"),
			slog.Group("inner",
				slog.String("note", "ping eve@example.com"),
			),
		),
	)
	rec := decodeRecords(t, buf)[0]
	env := rec["envelope"].(map[string]any)
	if got := env["from"].(string); strings.Contains(got, "dan@example.com") {
		t.Fatalf("group email leaked: %q", got)
	}
	if got := env["subject"]; got != "***" {
		t.Fatalf("group subject not elided: %v", got)
	}
	inner := env["inner"].(map[string]any)
	if got := inner["note"].(string); !strings.Contains(got, "***@example.com") {
		t.Fatalf("nested string not masked: %q", got)
	}
}

func TestLogSanitizer_PassesNonStringValues(t *testing.T) {
	logger, buf := captureLog(t)
	logger.Info("metrics",
		slog.Int("count", 42),
		slog.Float64("ratio", 0.5),
		slog.Bool("hit", true),
	)
	rec := decodeRecords(t, buf)[0]
	if rec["count"].(float64) != 42 {
		t.Fatalf("count: %v", rec["count"])
	}
	if rec["ratio"].(float64) != 0.5 {
		t.Fatalf("ratio: %v", rec["ratio"])
	}
	if rec["hit"].(bool) != true {
		t.Fatalf("hit: %v", rec["hit"])
	}
}

func TestLogSanitizer_WithAttrsSanitisesPreBound(t *testing.T) {
	logger, buf := captureLog(t)
	bound := logger.With(
		slog.String("sender", "frank@example.com"),
		slog.String("subject", "secret"),
	)
	bound.Info("event")
	rec := decodeRecords(t, buf)[0]
	if got := rec["sender"].(string); strings.Contains(got, "frank@example.com") {
		t.Fatalf("bound sender leaked: %q", got)
	}
	if got := rec["subject"]; got != "***" {
		t.Fatalf("bound subject not elided: %v", got)
	}
}

func TestLogSanitizer_WithGroupNamespacesOutput(t *testing.T) {
	logger, buf := captureLog(t)
	scoped := logger.WithGroup("evaluate")
	scoped.Info("done", slog.String("subject", "secret"), slog.String("from", "gabe@x.io"))
	rec := decodeRecords(t, buf)[0]
	evaluate, ok := rec["evaluate"].(map[string]any)
	if !ok {
		t.Fatalf("missing evaluate group: %v", rec)
	}
	if got := evaluate["subject"]; got != "***" {
		t.Fatalf("subject not elided: %v", got)
	}
	if got := evaluate["from"].(string); !strings.Contains(got, "***@x.io") {
		t.Fatalf("email not masked: %q", got)
	}
}

func TestLogSanitizer_RespectsEnabled(t *testing.T) {
	logger, buf := captureLog(t)
	logger.Log(context.Background(), slog.LevelDebug-1, "below-level")
	if buf.Len() != 0 {
		t.Fatalf("expected no output, got %q", buf.String())
	}
}
