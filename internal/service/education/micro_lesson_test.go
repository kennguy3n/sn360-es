package education

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/pkg/events"
)

// recordingPublisher implements events.EventService for assertions.
type recordingPublisher struct {
	mu       sync.Mutex
	subjects []string
	payloads [][]byte
	err      error
}

func (p *recordingPublisher) Publish(_ context.Context, subject string, data []byte, _ ...events.PublishOption) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	p.subjects = append(p.subjects, subject)
	cp := make([]byte, len(data))
	copy(cp, data)
	p.payloads = append(p.payloads, cp)
	return nil
}

func (p *recordingPublisher) Subscribe(context.Context, string, events.MessageHandler, ...events.SubscribeOption) (events.Subscription, error) {
	return nil, errors.New("not implemented")
}

func (p *recordingPublisher) Close() error { return nil }

func newTestService(t *testing.T, pub events.EventService) *MicroLessonService {
	t.Helper()
	store, err := DefaultLessonStore()
	if err != nil {
		t.Fatalf("DefaultLessonStore: %v", err)
	}
	svc, err := NewMicroLessonService(MicroLessonConfig{
		Store:     store,
		Publisher: pub,
	})
	if err != nil {
		t.Fatalf("NewMicroLessonService: %v", err)
	}
	return svc
}

func TestMicroLesson_AllCategoriesHaveEnglishLesson(t *testing.T) {
	svc := newTestService(t, nil)
	for _, cat := range constant.AllCategories {
		l, ok := svc.GetLesson(context.Background(), cat, "en")
		if !ok {
			t.Fatalf("missing lesson for %q in en", cat)
		}
		if l.Category != cat {
			t.Fatalf("lesson category mismatch: got %q want %q", l.Category, cat)
		}
		if err := l.Validate(); err != nil {
			t.Fatalf("lesson %q invalid: %v", cat, err)
		}
	}
}

func TestMicroLesson_FallbackToEnglish(t *testing.T) {
	svc := newTestService(t, nil)
	// "fr" is not registered → should fall back to "en".
	l, ok := svc.GetLesson(context.Background(), constant.CategoryLikelyPhishing, "fr")
	if !ok {
		t.Fatal("expected fallback lesson")
	}
	if l.LessonID == "" {
		t.Fatal("fallback lesson missing id")
	}
}

func TestMicroLesson_LanguageOnlyFallback(t *testing.T) {
	svc := newTestService(t, nil)
	// "en-GB" → should match "en".
	l, ok := svc.GetLesson(context.Background(), constant.CategoryLikelyPhishing, "en-GB")
	if !ok {
		t.Fatal("expected en-GB to fall back to en")
	}
	if l.LessonID == "" {
		t.Fatal("missing lesson id")
	}
}

func TestMicroLesson_UnknownCategoryReturnsFalse(t *testing.T) {
	svc := newTestService(t, nil)
	if _, ok := svc.GetLesson(context.Background(), constant.Category("MADE_UP"), "en"); ok {
		t.Fatal("expected ok=false for unknown category")
	}
}

func TestMicroLesson_ServeRejectsBadRequest(t *testing.T) {
	svc := newTestService(t, nil)
	cases := []ServeRequest{
		{}, // missing tenant
		{TenantID: "acme"},
		{TenantID: "acme", Category: constant.Category("NOPE")},
	}
	for i, c := range cases {
		if _, err := svc.Serve(context.Background(), c); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func TestMicroLesson_ServePublishesTrigger(t *testing.T) {
	pub := &recordingPublisher{}
	svc := newTestService(t, pub)
	l, err := svc.Serve(context.Background(), ServeRequest{
		TenantID:        "acme",
		UserHash:        "user-hash-1",
		Category:        constant.CategoryBECImpersonation,
		Locale:          "en",
		PseudoMessageID: "msg-1",
	})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if l.LessonID == "" {
		t.Fatal("expected lesson")
	}
	if len(pub.subjects) != 1 {
		t.Fatalf("publish count: %d", len(pub.subjects))
	}
	if pub.subjects[0] != "es.education.lesson.trigger" {
		t.Fatalf("subject: %q", pub.subjects[0])
	}
	var env map[string]any
	if err := json.Unmarshal(pub.payloads[0], &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env["tenant_id"] != "acme" {
		t.Fatalf("tenant: %v", env["tenant_id"])
	}
	if env["category"] != string(constant.CategoryBECImpersonation) {
		t.Fatalf("category: %v", env["category"])
	}
	if ts, _ := env["served_at"].(string); ts == "" {
		t.Fatal("missing served_at")
	} else if _, err := time.Parse(time.RFC3339, ts); err != nil {
		t.Fatalf("served_at not RFC3339: %v", err)
	}
}

func TestMicroLesson_PublisherFailureDoesNotBreakServe(t *testing.T) {
	pub := &recordingPublisher{err: errors.New("nats down")}
	svc := newTestService(t, pub)
	if _, err := svc.Serve(context.Background(), ServeRequest{
		TenantID: "acme",
		Category: constant.CategoryLikelyPhishing,
		Locale:   "en",
	}); err != nil {
		t.Fatalf("Serve should not propagate publish error: %v", err)
	}
}

func TestMicroLesson_StaticStoreSupportsCustomLocale(t *testing.T) {
	store := NewStaticLessonStore(map[string]map[constant.Category]MicroLesson{
		"en": {
			constant.CategoryLikelyPhishing: {
				LessonID: "lesson.phishing.en", Category: constant.CategoryLikelyPhishing,
				Title: "Phishing", BodyHTML: "<p>P</p>", EstimatedSeconds: 30,
			},
		},
		"vi": {
			constant.CategoryLikelyPhishing: {
				LessonID: "lesson.phishing.vi", Category: constant.CategoryLikelyPhishing,
				Title: "Lừa đảo", BodyHTML: "<p>L</p>", EstimatedSeconds: 30,
			},
		},
	})
	svc, err := NewMicroLessonService(MicroLessonConfig{Store: store})
	if err != nil {
		t.Fatalf("NewMicroLessonService: %v", err)
	}
	got, ok := svc.GetLesson(context.Background(), constant.CategoryLikelyPhishing, "vi")
	if !ok {
		t.Fatal("expected vi lesson")
	}
	if got.LessonID != "lesson.phishing.vi" {
		t.Fatalf("locale not respected: %q", got.LessonID)
	}
}
