package workmail

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestStaticCredentials(t *testing.T) {
	if _, err := (StaticCredentials{}).Retrieve(context.Background()); err == nil {
		t.Fatal("empty static credentials must error")
	}
	got, err := (StaticCredentials{Credentials: Credentials{AccessKeyID: "AKIA", SecretAccessKey: "S"}}).Retrieve(context.Background())
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if got.AccessKeyID != "AKIA" || got.SecretAccessKey != "S" {
		t.Fatalf("Retrieve returned %+v", got)
	}
}

func TestSigner_AddsExpectedHeadersAndAuthorization(t *testing.T) {
	creds := StaticCredentials{Credentials: Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}}
	signer, err := NewSigner(SignerConfig{
		Region:      "us-east-1",
		Service:     "workmail",
		Credentials: creds,
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	// Deterministic clock: 2024-01-02T03:04:05Z.
	signer.now = func() time.Time { return time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC) }

	req, err := http.NewRequest(http.MethodPost,
		"https://workmail.us-east-1.amazonaws.com/", strings.NewReader(""))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AWSWorkMail_20171001.ListUsers")
	payload := []byte(`{"OrganizationId":"m-abc"}`)
	if err := signer.Sign(context.Background(), req, payload); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := req.Header.Get("X-Amz-Date"); got != "20240102T030405Z" {
		t.Errorf("X-Amz-Date = %q", got)
	}
	if got := req.Header.Get("X-Amz-Content-Sha256"); got == "" {
		t.Error("X-Amz-Content-Sha256 missing")
	}
	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20240102/us-east-1/workmail/aws4_request") {
		t.Errorf("Authorization Credential mismatch: %q", auth)
	}
	if !strings.Contains(auth, "SignedHeaders=") {
		t.Errorf("Authorization missing SignedHeaders: %q", auth)
	}
	if !strings.Contains(auth, "Signature=") {
		t.Errorf("Authorization missing Signature: %q", auth)
	}
	// SignedHeaders must always include host + x-amz-date + x-amz-content-sha256.
	for _, want := range []string{"host", "x-amz-content-sha256", "x-amz-date", "x-amz-target"} {
		if !strings.Contains(auth, want) {
			t.Errorf("SignedHeaders missing %q: %v", want, auth)
		}
	}
}

func TestSigner_SessionTokenPropagatedAndSigned(t *testing.T) {
	creds := StaticCredentials{Credentials: Credentials{
		AccessKeyID:     "AKIA",
		SecretAccessKey: "secret",
		SessionToken:    "session-xyz",
	}}
	signer, _ := NewSigner(SignerConfig{
		Region: "us-west-2", Service: "workmail", Credentials: creds,
	})
	signer.now = func() time.Time { return time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC) }
	req, _ := http.NewRequest(http.MethodGet, "https://workmail.us-west-2.amazonaws.com/", nil)
	if err := signer.Sign(context.Background(), req, nil); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if req.Header.Get("X-Amz-Security-Token") != "session-xyz" {
		t.Errorf("X-Amz-Security-Token = %q", req.Header.Get("X-Amz-Security-Token"))
	}
	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "x-amz-security-token") {
		t.Errorf("session token not in SignedHeaders: %v", auth)
	}
}

func TestSigner_SignatureChangesWithBody(t *testing.T) {
	creds := StaticCredentials{Credentials: Credentials{AccessKeyID: "K", SecretAccessKey: "S"}}
	signer, _ := NewSigner(SignerConfig{
		Region: "us-east-1", Service: "workmail", Credentials: creds,
	})
	signer.now = func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) }

	sign := func(body []byte) string {
		req, _ := http.NewRequest(http.MethodPost, "https://workmail.us-east-1.amazonaws.com/", nil)
		if err := signer.Sign(context.Background(), req, body); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return req.Header.Get("Authorization")
	}
	a := sign([]byte(`{"a":1}`))
	b := sign([]byte(`{"a":2}`))
	if a == b {
		t.Fatal("signature should differ when payload differs")
	}
}

func TestNewSigner_Validation(t *testing.T) {
	cases := []SignerConfig{
		{Service: "workmail", Credentials: StaticCredentials{}},
		{Region: "us-east-1", Credentials: StaticCredentials{}},
		{Region: "us-east-1", Service: "workmail"},
	}
	for i, c := range cases {
		if _, err := NewSigner(c); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
}
