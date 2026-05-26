package workmail

import (
	"context"
	"encoding/hex"
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

// TestSigner_AWSCanonicalGetVanillaVector pins the canonical
// AWS-style "get-vanilla" SigV4 test vector end-to-end through the
// low-level helpers. The test verifies that:
//
//  1. sha256Sum produces the canonical empty-payload SHA256 hash
//     (`e3b0c4…b855`) — a value documented in countless cryptographic
//     standards and independently verifiable via any SHA256 tool.
//  2. buildCanonicalRequest emits the AWS-format canonical-request
//     bytes and signed-headers list for an empty GET request with
//     only host + x-amz-date headers.
//  3. The SHA256 of that canonical request matches the value used in
//     the string-to-sign.
//  4. deriveSigningKey + hmacSHA256 reproduce a SigV4 signature that
//     matches a known-good HMAC-SHA256 reference. The expected
//     signature was cross-verified by running the same inputs through
//     Python's `hmac`/`hashlib` standard library — independent of our
//     Go implementation — to guarantee the assertion isn't tautological.
//
// The signer is implemented from scratch (no aws-sdk-go-v2 dependency)
// so this end-to-end vector is the strongest available cryptographic
// conformance check short of integration testing against a live AWS
// endpoint. Reference: AWS SigV4 algorithm documented at
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html
func TestSigner_AWSCanonicalGetVanillaVector(t *testing.T) {
	const (
		secret      = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
		region      = "us-east-1"
		service     = "service"
		dateStamp   = "20150830"
		amzDate     = "20150830T123600Z"
		emptyHash   = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		wantCanHash = "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
		// Independently re-derived via Python's hmac/hashlib standard
		// library using the SigV4 derivation chain (kDate ← kRegion ←
		// kService ← kSigning); this ensures the assertion validates
		// our Go HMAC chain against a non-Go reference rather than
		// against itself.
		wantSig = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	)

	// (1) Verify the empty-payload hash matches the AWS reference.
	gotEmptyHash := hex.EncodeToString(sha256Sum(nil))
	if gotEmptyHash != emptyHash {
		t.Fatalf("sha256(empty) = %q, want %q", gotEmptyHash, emptyHash)
	}

	// (2) Build the canonical request from the AWS get-vanilla input.
	req, err := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Host", "example.amazonaws.com")
	req.Header.Set("X-Amz-Date", amzDate)

	canonical, signedHeaders := buildCanonicalRequest(req, emptyHash)
	const wantCanonical = "GET\n" +
		"/\n" +
		"\n" +
		"host:example.amazonaws.com\n" +
		"x-amz-date:20150830T123600Z\n" +
		"\n" +
		"host;x-amz-date\n" +
		emptyHash
	if canonical != wantCanonical {
		t.Errorf("canonical request mismatch:\n got: %q\nwant: %q", canonical, wantCanonical)
	}
	if signedHeaders != "host;x-amz-date" {
		t.Errorf("signedHeaders = %q, want %q", signedHeaders, "host;x-amz-date")
	}

	// (3) Verify the canonical-request hash matches the AWS reference.
	gotCanHash := hex.EncodeToString(sha256Sum([]byte(canonical)))
	if gotCanHash != wantCanHash {
		t.Errorf("sha256(canonical) = %q, want %q", gotCanHash, wantCanHash)
	}

	// (4) Derive the signing key and compute the final signature.
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		dateStamp + "/" + region + "/" + service + "/aws4_request",
		gotCanHash,
	}, "\n")
	signingKey := deriveSigningKey(secret, dateStamp, region, service)
	gotSig := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))
	if gotSig != wantSig {
		t.Errorf("signature = %q, want %q", gotSig, wantSig)
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

// TestCollapseHeaderWhitespace pins down the AWS SigV4 canonical-
// header rule that the previous TrimSpace-only implementation
// silently violated: sequential whitespace inside a header value
// must collapse to a single space, not stay multi-spaced. AWS will
// reject the request if the calculated canonical value disagrees
// with theirs.
//
// Cases cover:
//   - leading + trailing trim (preserved from the old behaviour),
//   - runs of internal spaces collapsing to one,
//   - mixed-whitespace runs (tab + CR + LF + space) collapsing,
//   - empty / whitespace-only values returning the empty string,
//   - already-canonical values being left alone.
func TestCollapseHeaderWhitespace(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"trim only", "  value  ", "value"},
		{"internal run", "AAA   BBB", "AAA BBB"},
		{"tabs and newlines", "AAA\t\t \nBBB\r\nCCC", "AAA BBB CCC"},
		{"all whitespace", "  \t \r\n ", ""},
		{"empty", "", ""},
		{"single space", "AAA BBB", "AAA BBB"},
		{"only one trailing newline", "value\n", "value"},
		{"mixed-with-comma", "a, b,c,  d", "a, b,c, d"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := collapseHeaderWhitespace(tc.in); got != tc.want {
				t.Errorf("collapseHeaderWhitespace(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestBuildCanonicalRequest_CollapsesHeaderWhitespace exercises the
// SigV4 canonical-header rule through the public entry point. Pre-
// fix this test would have failed because TrimSpace alone left
// internal whitespace runs intact.
func TestBuildCanonicalRequest_CollapsesHeaderWhitespace(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Host", "example.amazonaws.com")
	req.Header.Set("X-Amz-Custom", "  multi   spaced\tvalue  ")
	canonical, signed := buildCanonicalRequest(req, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if !strings.Contains(canonical, "x-amz-custom:multi spaced value\n") {
		t.Errorf("canonical did not collapse whitespace:\n%s", canonical)
	}
	if !strings.Contains(signed, "x-amz-custom") {
		t.Errorf("signed headers missing x-amz-custom: %q", signed)
	}
}
