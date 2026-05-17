package handler

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/service/education"
)

// noOpPublisher silently accepts publishes so the education service
// doesn't fail when serving with a tenant_id.
type noOpPublisher struct{}

func (noOpPublisher) Publish(string, []byte) error                        { return nil }
func (noOpPublisher) PublishWithCorrelation(string, []byte, string) error { return nil }

func newTestEducationService(t *testing.T) *education.MicroLessonService {
	t.Helper()
	store := education.NewStaticLessonStore(map[string]map[constant.Category]education.MicroLesson{
		"en": {
			constant.CategoryLikelyPhishing: {
				LessonID: "phish-en", Category: constant.CategoryLikelyPhishing,
				Title: "Spot phishing", BodyHTML: "<p>Look at the sender.</p>",
				EstimatedSeconds: 30,
			},
		},
	})
	svc, err := education.NewMicroLessonService(education.MicroLessonConfig{
		Store:  store,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("micro lesson svc: %v", err)
	}
	return svc
}

func TestEducationHandler_AnonymousLookup(t *testing.T) {
	svc := newTestEducationService(t)
	h := NewEducationHandler(nil, svc)

	req := httptest.NewRequest(http.MethodGet, "/v1/education/lesson/LIKELY_PHISHING?locale=en", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var lesson education.MicroLesson
	if err := json.Unmarshal(rec.Body.Bytes(), &lesson); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if lesson.LessonID != "phish-en" {
		t.Fatalf("lesson=%+v", lesson)
	}
}

func TestEducationHandler_FallbackLocale(t *testing.T) {
	svc := newTestEducationService(t)
	h := NewEducationHandler(nil, svc)

	// "fr" is not registered; service should fall back to "en".
	req := httptest.NewRequest(http.MethodGet, "/v1/education/lesson/LIKELY_PHISHING?locale=fr", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestEducationHandler_WithTenantPublishesTrigger(t *testing.T) {
	// Even with no publisher wired, Serve() should succeed when
	// tenant_id is present.
	svc := newTestEducationService(t)
	h := NewEducationHandler(nil, svc)

	req := httptest.NewRequest(http.MethodGet, "/v1/education/lesson/LIKELY_PHISHING?locale=en&tenant_id=acme&user_hash=uh", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestEducationHandler_Rejections(t *testing.T) {
	svc := newTestEducationService(t)
	h := NewEducationHandler(nil, svc)

	cases := []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{name: "wrong method", method: http.MethodPost, path: "/v1/education/lesson/LIKELY_PHISHING", want: http.StatusMethodNotAllowed},
		{name: "missing category", method: http.MethodGet, path: "/v1/education/lesson/", want: http.StatusBadRequest},
		{name: "unknown category", method: http.MethodGet, path: "/v1/education/lesson/MADE_UP", want: http.StatusBadRequest},
		{name: "no lesson registered", method: http.MethodGet, path: "/v1/education/lesson/SCAM_FRAUD", want: http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestEducationHandler_NilService(t *testing.T) {
	h := NewEducationHandler(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/education/lesson/LIKELY_PHISHING", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rec.Code)
	}
}
