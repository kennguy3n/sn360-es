// Package workmail implements the SN360-ES provider integration
// against Amazon WorkMail. The package is dependency-free: SigV4
// signing, WorkMail SDK calls, and EWS SOAP calls are all
// implemented directly on top of the Go standard library so we don't
// pull in the (heavy) aws-sdk-go-v2 module.
//
// Authentication uses static IAM access keys (AccessKeyID +
// SecretAccessKey, optionally a SessionToken when delivered via STS).
// When the operator omits all three the fallback path reads the
// standard AWS environment variables (AWS_ACCESS_KEY_ID,
// AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN) so single-binary
// deployments running on EC2/ECS/EKS pick up their instance role
// credentials transparently.
package workmail

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Credentials hold the values needed to sign an AWS request.
// SessionToken is only set when the keys came from STS / instance
// metadata.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// CredentialsProvider returns a fresh Credentials value on each call.
// Allows tests to supply a static provider while production code can
// reuse the AWS default chain.
type CredentialsProvider interface {
	Retrieve(ctx context.Context) (Credentials, error)
}

// CredentialsProviderFunc adapts an ordinary function.
type CredentialsProviderFunc func(ctx context.Context) (Credentials, error)

// Retrieve implements CredentialsProvider.
func (f CredentialsProviderFunc) Retrieve(ctx context.Context) (Credentials, error) { return f(ctx) }

// StaticCredentials returns the same Credentials on every call.
type StaticCredentials struct {
	Credentials Credentials
}

// Retrieve implements CredentialsProvider.
func (s StaticCredentials) Retrieve(context.Context) (Credentials, error) {
	if s.Credentials.AccessKeyID == "" || s.Credentials.SecretAccessKey == "" {
		return Credentials{}, errors.New("workmail: static credentials missing access key or secret")
	}
	return s.Credentials, nil
}

// SignerConfig wires the SigV4 signer.
type SignerConfig struct {
	Region      string
	Service     string // "workmail" or "ews"
	Credentials CredentialsProvider
}

// Signer signs requests using AWS SigV4 (the "AWS4-HMAC-SHA256"
// algorithm). It is safe for concurrent use.
type Signer struct {
	region  string
	service string
	creds   CredentialsProvider
	now     func() time.Time // injectable for deterministic tests
}

// NewSigner validates the config and returns a usable Signer.
func NewSigner(cfg SignerConfig) (*Signer, error) {
	if cfg.Region == "" {
		return nil, errors.New("workmail: signer region is required")
	}
	if cfg.Service == "" {
		return nil, errors.New("workmail: signer service is required")
	}
	if cfg.Credentials == nil {
		return nil, errors.New("workmail: signer credentials provider is required")
	}
	return &Signer{
		region:  cfg.Region,
		service: cfg.Service,
		creds:   cfg.Credentials,
		now:     time.Now,
	}, nil
}

// Sign attaches the SigV4 Authorization header (and supporting
// X-Amz-* headers) to req. payload is the literal request body
// bytes; pass nil when the body is empty.
func (s *Signer) Sign(ctx context.Context, req *http.Request, payload []byte) error {
	creds, err := s.creds.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("workmail: retrieve credentials: %w", err)
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return errors.New("workmail: empty credentials")
	}
	now := s.now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("X-Amz-Date", amzDate)
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}
	if req.Header.Get("Host") == "" {
		req.Header.Set("Host", req.Host)
	}

	payloadHash := hex.EncodeToString(sha256Sum(payload))
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	canonicalRequest, signedHeaders := buildCanonicalRequest(req, payloadHash)
	scope := strings.Join([]string{dateStamp, s.region, s.service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hex.EncodeToString(sha256Sum([]byte(canonicalRequest))),
	}, "\n")
	signingKey := deriveSigningKey(creds.SecretAccessKey, dateStamp, s.region, s.service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		creds.AccessKeyID, scope, signedHeaders, signature)
	req.Header.Set("Authorization", authHeader)
	return nil
}

// buildCanonicalRequest assembles the SigV4 canonical-request string
// and returns it along with the semicolon-joined signed-header list.
func buildCanonicalRequest(req *http.Request, payloadHash string) (string, string) {
	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalQuery := buildCanonicalQuery(req.URL.Query())

	headerNames := make([]string, 0, len(req.Header))
	headers := make(map[string]string, len(req.Header))
	for k, vs := range req.Header {
		lc := strings.ToLower(k)
		// SigV4 always signs host, x-amz-date, x-amz-content-sha256
		// and x-amz-security-token (when present), plus any header
		// added by the caller.
		if lc == "authorization" {
			continue
		}
		headerNames = append(headerNames, lc)
		// AWS SigV4 (Task 1, step 6) requires:
		//   - trim leading and trailing whitespace
		//   - collapse sequential whitespace inside a value to a
		//     single space (unless the value is inside a quoted
		//     string, which we do not handle since EWS/WorkMail
		//     never sends quoted-string headers we sign).
		// strings.TrimSpace alone fails the second requirement, and
		// AWS rejects requests where the calculated canonical
		// header value disagrees with theirs.
		headers[lc] = collapseHeaderWhitespace(strings.Join(vs, ","))
	}
	// Ensure host is always present.
	if _, ok := headers["host"]; !ok {
		host := req.URL.Host
		if req.Host != "" {
			host = req.Host
		}
		headers["host"] = host
		headerNames = append(headerNames, "host")
	}
	sort.Strings(headerNames)

	var canonicalHeaders strings.Builder
	signedHeadersList := make([]string, 0, len(headerNames))
	for _, name := range headerNames {
		canonicalHeaders.WriteString(name)
		canonicalHeaders.WriteString(":")
		canonicalHeaders.WriteString(headers[name])
		canonicalHeaders.WriteString("\n")
		signedHeadersList = append(signedHeadersList, name)
	}
	signedHeaders := strings.Join(signedHeadersList, ";")

	canonical := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")
	return canonical, signedHeaders
}

// buildCanonicalQuery returns the canonical query string per
// SigV4 rules: URL-encoded names and values, sorted by name then value,
// joined with '&'.
func buildCanonicalQuery(values url.Values) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		vs := values[k]
		sort.Strings(vs)
		for j, v := range vs {
			if i > 0 || j > 0 {
				b.WriteString("&")
			}
			b.WriteString(awsURIEncode(k, false))
			b.WriteString("=")
			b.WriteString(awsURIEncode(v, false))
		}
	}
	return b.String()
}

// collapseHeaderWhitespace implements the canonical-header whitespace
// normalization mandated by the AWS SigV4 spec: leading/trailing
// whitespace is trimmed and every run of sequential whitespace inside
// the value is replaced with a single space. The spec exempts
// whitespace inside HTTP quoted-strings (RFC 7230 §3.2.6), but the
// EWS and WorkMail headers we sign never use quoted-string values, so
// we apply the collapse unconditionally and document the limitation.
//
// Implemented manually rather than via regexp to keep this on the
// signing hot path; ASCII whitespace classification matches
// unicode.IsSpace for the bytes that appear in HTTP headers.
func collapseHeaderWhitespace(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return v
	}
	var b strings.Builder
	b.Grow(len(v))
	inSpace := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			if !inSpace {
				b.WriteByte(' ')
				inSpace = true
			}
			continue
		}
		inSpace = false
		b.WriteByte(c)
	}
	return b.String()
}

// awsURIEncode mirrors the AWS-specific URI encoding rules (the
// standard net/url encoder is too permissive for SigV4).
func awsURIEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.' || r == '~':
			b.WriteRune(r)
		case r == '/' && !encodeSlash:
			b.WriteRune(r)
		default:
			for _, byteVal := range []byte(string(r)) {
				fmt.Fprintf(&b, "%%%02X", byteVal)
			}
		}
	}
	return b.String()
}

// deriveSigningKey produces the per-day signing key per the SigV4
// derivation chain.
func deriveSigningKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func sha256Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
