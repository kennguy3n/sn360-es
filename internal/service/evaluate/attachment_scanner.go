package evaluate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

// AttachmentVerdict is the normalised pre-screen outcome.
type AttachmentVerdict string

const (
	// AttachmentVerdictClean means the file passed every pre-screen.
	AttachmentVerdictClean AttachmentVerdict = "clean"
	// AttachmentVerdictSuspicious means YARA matched or extension/MIME
	// heuristics tripped — escalate to full sandbox.
	AttachmentVerdictSuspicious AttachmentVerdict = "suspicious"
	// AttachmentVerdictMalicious means ClamAV (or a high-confidence
	// YARA rule) returned a match.
	AttachmentVerdictMalicious AttachmentVerdict = "malicious"
	// AttachmentVerdictError indicates the scanner failed.
	AttachmentVerdictError AttachmentVerdict = "error"
)

// AttachmentMeta describes the file under test.
type AttachmentMeta struct {
	Filename string
	MIME     string
	Size     int64
}

// AttachmentScanResult is the per-attachment finding.
type AttachmentScanResult struct {
	Filename   string            `json:"filename"`
	SHA256     string            `json:"sha256"`
	Size       int64             `json:"size"`
	MIME       string            `json:"mime"`
	Verdict    AttachmentVerdict `json:"verdict"`
	Score      int               `json:"score"`
	Engine     string            `json:"engine"`
	Matches    []string          `json:"matches,omitempty"`
	ShouldSbx  bool              `json:"escalate_to_sandbox"`
	ScannedAt  time.Time         `json:"scanned_at"`
	DurationMs int64             `json:"duration_ms"`
	Err        string            `json:"error,omitempty"`
}

// YARAEngine is the abstraction over a YARA matcher.
type YARAEngine interface {
	Match(ctx context.Context, content []byte) ([]string, error)
	RuleNames() []string
}

// ClamAVClient is the abstraction over a clamd connection.
type ClamAVClient interface {
	ScanBytes(ctx context.Context, content []byte) (clean bool, signature string, err error)
}

// AttachmentScannerConfig wires the scanner.
type AttachmentScannerConfig struct {
	YARA           YARAEngine
	ClamAV         ClamAVClient
	Logger         *slog.Logger
	PerScanTimeout time.Duration // 0 -> 5s
	MaxBytes       int64         // 0 -> 25 MB
	SuspiciousExts []string
	Now            func() time.Time
}

// AttachmentScanner runs lightweight pre-screens (YARA + ClamAV + ext
// heuristics) and decides whether to escalate to the full ShieldNet
// sandbox. Per PROPOSAL.md §8, only suspicious results escalate.
type AttachmentScanner struct {
	cfg           AttachmentScannerConfig
	log           *slog.Logger
	now           func() time.Time
	maxBytes      int64
	timeout       time.Duration
	suspiciousMap map[string]struct{}
}

// NewAttachmentScanner constructs the scanner. YARA or ClamAV may be
// nil — the scanner degrades gracefully and disables that engine.
func NewAttachmentScanner(cfg AttachmentScannerConfig) (*AttachmentScanner, error) {
	if cfg.YARA == nil && cfg.ClamAV == nil {
		return nil, errors.New("attachment scanner: at least one engine required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	timeout := cfg.PerScanTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	maxBytes := cfg.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 25 * 1024 * 1024
	}
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	exts := cfg.SuspiciousExts
	if len(exts) == 0 {
		exts = DefaultSuspiciousExtensions()
	}
	sm := make(map[string]struct{}, len(exts))
	for _, e := range exts {
		sm[strings.ToLower(strings.TrimPrefix(e, "."))] = struct{}{}
	}
	return &AttachmentScanner{
		cfg:           cfg,
		log:           cfg.Logger,
		now:           now,
		maxBytes:      maxBytes,
		timeout:       timeout,
		suspiciousMap: sm,
	}, nil
}

// DefaultSuspiciousExtensions returns the canonical list of high-risk
// file extensions tracked in PROPOSAL.md §3.
func DefaultSuspiciousExtensions() []string {
	return []string{
		"exe", "scr", "cpl", "msi", "ps1", "vbs", "js", "jse",
		"wsf", "bat", "cmd", "hta", "lnk", "iso", "img", "jar",
		"docm", "xlsm", "pptm", "xll", "xlam", "xlw",
	}
}

// ScanAttachment runs the pre-screens against content and returns a
// single normalised verdict.
func (s *AttachmentScanner) ScanAttachment(ctx context.Context, meta AttachmentMeta, content []byte) (AttachmentScanResult, error) {
	if s == nil {
		return AttachmentScanResult{Verdict: AttachmentVerdictError, Err: "nil scanner"}, errors.New("nil scanner")
	}
	if int64(len(content)) > s.maxBytes {
		return AttachmentScanResult{
			Filename:  meta.Filename,
			MIME:      meta.MIME,
			Size:      int64(len(content)),
			Verdict:   AttachmentVerdictSuspicious,
			Score:     60,
			Engine:    "size_guard",
			ShouldSbx: true,
			Matches:   []string{"oversize_attachment"},
			ScannedAt: s.now(),
		}, nil
	}

	start := s.now()
	cctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	res := AttachmentScanResult{
		Filename:  meta.Filename,
		MIME:      meta.MIME,
		Size:      int64(len(content)),
		SHA256:    sha256Hex(content),
		ScannedAt: start,
		Verdict:   AttachmentVerdictClean,
		Engine:    "prescan",
	}

	// YARA --------------------------------------------------------------
	var yMatches []string
	if s.cfg.YARA != nil {
		matches, err := s.cfg.YARA.Match(cctx, content)
		if err != nil {
			s.log.WarnContext(ctx, "attachment_scanner: yara error", slog.Any("err", err))
		}
		yMatches = matches
	}

	// ClamAV ------------------------------------------------------------
	// Default to "clean from ClamAV's perspective" so that an unreachable
	// clamd does not by itself convict the attachment. The YARA engine
	// and extension heuristics continue to run and can still raise the
	// verdict above clean if warranted.
	clamClean := true
	var clamSig string
	if s.cfg.ClamAV != nil {
		clean, sig, err := s.cfg.ClamAV.ScanBytes(cctx, content)
		if err != nil {
			s.log.WarnContext(ctx, "attachment_scanner: clamav error", slog.Any("err", err))
		} else {
			clamClean = clean
			clamSig = sig
		}
	}

	// Extension heuristic ----------------------------------------------
	suspExt := s.checkExtension(meta.Filename)
	if suspExt != "" {
		yMatches = append(yMatches, "suspicious_ext:"+suspExt)
	}

	// Final verdict ----------------------------------------------------
	switch {
	case !clamClean:
		res.Verdict = AttachmentVerdictMalicious
		res.Score = 100
		res.Engine = "clamav"
		if clamSig != "" {
			res.Matches = append(res.Matches, "clamav:"+clamSig)
		}
		res.ShouldSbx = true
	case len(yMatches) >= 2:
		res.Verdict = AttachmentVerdictMalicious
		res.Score = 90
		res.Engine = "yara+heuristic"
		res.Matches = append(res.Matches, yMatches...)
		res.ShouldSbx = true
	case len(yMatches) == 1:
		res.Verdict = AttachmentVerdictSuspicious
		res.Score = 60
		res.Engine = "yara"
		res.Matches = append(res.Matches, yMatches...)
		res.ShouldSbx = true
	default:
		res.Verdict = AttachmentVerdictClean
		res.Score = 0
		res.ShouldSbx = false
	}

	res.DurationMs = s.now().Sub(start).Milliseconds()
	return res, nil
}

func (s *AttachmentScanner) checkExtension(filename string) string {
	idx := strings.LastIndex(filename, ".")
	if idx < 0 {
		return ""
	}
	ext := strings.ToLower(filename[idx+1:])
	if _, ok := s.suspiciousMap[ext]; ok {
		return ext
	}
	return ""
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// --- YARA: stdlib-only engine -------------------------------------------

// SimpleYARAEngine is a zero-dependency implementation that matches a
// set of named byte patterns. The intent is to support common malware
// markers (e.g. OLE macro magic, suspicious VBA verbs) without
// requiring the libyara cgo wrapper at build time. Real deployments
// can swap in a libyara-backed engine that satisfies the YARAEngine
// interface.
type SimpleYARAEngine struct {
	rules map[string][]byte
}

// NewSimpleYARAEngine constructs an engine seeded with the default
// rule set. Callers can extend or replace it via WithRule.
func NewSimpleYARAEngine() *SimpleYARAEngine {
	return &SimpleYARAEngine{rules: DefaultYARARules()}
}

// WithRule overrides or installs a single rule.
func (e *SimpleYARAEngine) WithRule(name string, pattern []byte) *SimpleYARAEngine {
	if e.rules == nil {
		e.rules = map[string][]byte{}
	}
	e.rules[name] = pattern
	return e
}

// RuleNames implements YARAEngine.
func (e *SimpleYARAEngine) RuleNames() []string {
	out := make([]string, 0, len(e.rules))
	for k := range e.rules {
		out = append(out, k)
	}
	return out
}

// Match implements YARAEngine.
func (e *SimpleYARAEngine) Match(_ context.Context, content []byte) ([]string, error) {
	if len(content) == 0 {
		return nil, nil
	}
	var matched []string
	for name, pat := range e.rules {
		if len(pat) == 0 {
			continue
		}
		if indexOf(content, pat) >= 0 {
			matched = append(matched, name)
		}
	}
	return matched, nil
}

// DefaultYARARules returns the seed pattern library. The patterns are
// intentionally narrow and well-documented so security teams can audit
// them.
func DefaultYARARules() map[string][]byte {
	return map[string][]byte{
		// OLE Compound Document magic (legacy MS Office macros).
		"ole_compound_doc_magic": {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1},
		// VBA module verbs commonly seen in macro malware.
		"vba_shell_invoke":    []byte("Shell("),
		"vba_createobject":    []byte("CreateObject(\"WScript.Shell\""),
		"vba_powershell_call": []byte("powershell -EncodedCommand"),
		// PE magic — useful for archive payload pre-screen.
		"pe_executable_header": []byte("MZ\x90\x00\x03\x00"),
		// Common phishing landing-page artefact.
		"html_credential_form": []byte("type=\"password\" name=\"password\""),
	}
}

// indexOf is a small, dependency-free substring matcher.
func indexOf(haystack, needle []byte) int {
	n, m := len(haystack), len(needle)
	if m == 0 || n < m {
		return -1
	}
	for i := 0; i+m <= n; i++ {
		match := true
		for j := 0; j < m; j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// --- ClamAV (clamd TCP) ---------------------------------------------------

// ClamdClient speaks the INSTREAM protocol against a clamd TCP socket.
// The implementation uses only the standard library so it can run in
// any deployment.
type ClamdClient struct {
	addr    string
	timeout time.Duration
}

// NewClamdClient constructs a configured client.
func NewClamdClient(addr string, timeout time.Duration) *ClamdClient {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &ClamdClient{addr: addr, timeout: timeout}
}

// ScanBytes implements ClamAVClient. It streams content using clamd's
// INSTREAM command and returns (clean, signature, error).
//
//	-> zINSTREAM\0
//	-> uint32(len(chunk)) chunk ... uint32(0)
//	<- "stream: OK\0"            => clean
//	<- "stream: <SIG> FOUND\0"   => malicious
func (c *ClamdClient) ScanBytes(ctx context.Context, content []byte) (bool, string, error) {
	d := net.Dialer{Timeout: c.timeout}
	conn, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return false, "", fmt.Errorf("clamd dial: %w", err)
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(c.timeout))
	}

	// Command.
	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return false, "", fmt.Errorf("clamd write cmd: %w", err)
	}

	const chunkSize = 1 << 14
	for off := 0; off < len(content); off += chunkSize {
		end := off + chunkSize
		if end > len(content) {
			end = len(content)
		}
		size := uint32(end - off)
		hdr := []byte{byte(size >> 24), byte(size >> 16), byte(size >> 8), byte(size)}
		if _, err := conn.Write(hdr); err != nil {
			return false, "", fmt.Errorf("clamd write hdr: %w", err)
		}
		if _, err := conn.Write(content[off:end]); err != nil {
			return false, "", fmt.Errorf("clamd write chunk: %w", err)
		}
	}
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return false, "", fmt.Errorf("clamd terminator: %w", err)
	}

	body, err := io.ReadAll(conn)
	if err != nil {
		return false, "", fmt.Errorf("clamd read: %w", err)
	}
	resp := strings.TrimRight(string(body), "\x00 \n\r")
	switch {
	case strings.HasSuffix(resp, " OK"):
		return true, "", nil
	case strings.HasSuffix(resp, " FOUND"):
		sig := strings.TrimSuffix(resp, " FOUND")
		// "stream: Eicar-Test-Signature"
		if i := strings.LastIndex(sig, " "); i >= 0 {
			sig = sig[i+1:]
		}
		return false, sig, nil
	case strings.Contains(resp, "ERROR"):
		return false, "", fmt.Errorf("clamd error: %s", resp)
	default:
		return false, "", fmt.Errorf("clamd unexpected response: %q", resp)
	}
}

// MemoryClamAV is a deterministic test double. It treats any content
// containing the EICAR test string as malicious.
type MemoryClamAV struct {
	mu       sync.Mutex
	Sig      string
	FailWith error
}

// ScanBytes implements ClamAVClient.
func (m *MemoryClamAV) ScanBytes(_ context.Context, content []byte) (bool, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailWith != nil {
		return false, "", m.FailWith
	}
	if strings.Contains(string(content), "EICAR-STANDARD-ANTIVIRUS-TEST-FILE") {
		sig := m.Sig
		if sig == "" {
			sig = "Eicar-Test-Signature"
		}
		return false, sig, nil
	}
	return true, "", nil
}
