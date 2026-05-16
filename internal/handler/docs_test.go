package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDocsHandler_SpecLoads(t *testing.T) {
	h, err := NewDocsHandler()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(h.Spec()), "openapi: 3.1.0") {
		t.Fatal("expected OpenAPI 3.1 spec")
	}
}

func TestDocsHandler_ServeSwaggerUI(t *testing.T) {
	h, _ := NewDocsHandler()
	rec := httptest.NewRecorder()
	h.ServeSwaggerUI(rec, httptest.NewRequest(http.MethodGet, "/docs", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type=%s", ct)
	}
	if !strings.Contains(rec.Body.String(), "swagger-ui") {
		t.Fatal("expected swagger-ui markup")
	}
	if !strings.Contains(rec.Body.String(), "/openapi.yaml") {
		t.Fatal("expected reference to openapi.yaml")
	}
}

func TestDocsHandler_ServeOpenAPI(t *testing.T) {
	h, _ := NewDocsHandler()
	rec := httptest.NewRecorder()
	h.ServeOpenAPI(rec, httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/yaml") {
		t.Fatalf("content-type=%s", ct)
	}
	if !strings.Contains(rec.Body.String(), "/v1/banner/action") {
		t.Fatal("expected banner action path in spec")
	}
}

func TestDocsHandler_MethodNotAllowed(t *testing.T) {
	h, _ := NewDocsHandler()
	rec := httptest.NewRecorder()
	h.ServeOpenAPI(rec, httptest.NewRequest(http.MethodPost, "/openapi.yaml", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", rec.Code)
	}
}
