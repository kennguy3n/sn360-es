package evaluate

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestAttachmentScanner_RejectsNoEngines(t *testing.T) {
	if _, err := NewAttachmentScanner(AttachmentScannerConfig{}); err == nil {
		t.Fatal("expected error when no engines configured")
	}
}

func TestAttachmentScanner_CleanWord(t *testing.T) {
	scanner, err := NewAttachmentScanner(AttachmentScannerConfig{
		YARA:   NewSimpleYARAEngine(),
		ClamAV: &MemoryClamAV{},
	})
	if err != nil {
		t.Fatalf("NewAttachmentScanner: %v", err)
	}
	res, err := scanner.ScanAttachment(context.Background(), AttachmentMeta{
		Filename: "memo.docx",
		MIME:     "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	}, []byte("PK\x03\x04 normal document content"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Verdict != AttachmentVerdictClean {
		t.Fatalf("verdict: %q", res.Verdict)
	}
	if res.ShouldSbx {
		t.Fatal("clean file should not escalate to sandbox")
	}
}

func TestAttachmentScanner_EICARMalicious(t *testing.T) {
	scanner, _ := NewAttachmentScanner(AttachmentScannerConfig{
		YARA:   NewSimpleYARAEngine(),
		ClamAV: &MemoryClamAV{},
	})
	res, err := scanner.ScanAttachment(context.Background(), AttachmentMeta{
		Filename: "test.txt",
		MIME:     "text/plain",
	}, []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Verdict != AttachmentVerdictMalicious {
		t.Fatalf("verdict: %q", res.Verdict)
	}
	if !res.ShouldSbx {
		t.Fatal("malicious file must escalate to sandbox")
	}
	if res.Engine != "clamav" {
		t.Fatalf("engine: %q", res.Engine)
	}
}

func TestAttachmentScanner_YARAOnly_Suspicious(t *testing.T) {
	scanner, _ := NewAttachmentScanner(AttachmentScannerConfig{
		YARA:   NewSimpleYARAEngine(),
		ClamAV: &MemoryClamAV{},
	})
	// Single YARA hit (no ext, no clam) -> suspicious.
	// "Shell(" macro verb only — no executable extension on filename.
	res, _ := scanner.ScanAttachment(context.Background(), AttachmentMeta{
		Filename: "doc.txt",
		MIME:     "text/plain",
	}, []byte("a benign string with Shell( embedded inside"))
	if res.Verdict != AttachmentVerdictSuspicious {
		t.Fatalf("verdict: %q (matches=%v)", res.Verdict, res.Matches)
	}
	if !res.ShouldSbx {
		t.Fatal("suspicious result must escalate to sandbox")
	}
}

func TestAttachmentScanner_SuspiciousExtension(t *testing.T) {
	scanner, _ := NewAttachmentScanner(AttachmentScannerConfig{
		YARA:   NewSimpleYARAEngine(),
		ClamAV: &MemoryClamAV{},
	})
	res, _ := scanner.ScanAttachment(context.Background(), AttachmentMeta{
		Filename: "invoice.exe",
		MIME:     "application/octet-stream",
	}, []byte("plain body without yara hits"))
	if res.Verdict != AttachmentVerdictSuspicious {
		t.Fatalf("verdict: %q matches=%v", res.Verdict, res.Matches)
	}
	if !contains(res.Matches, "suspicious_ext:exe") {
		t.Fatalf("expected ext match in %+v", res.Matches)
	}
}

func TestAttachmentScanner_YARAAndExt_Malicious(t *testing.T) {
	scanner, _ := NewAttachmentScanner(AttachmentScannerConfig{
		YARA:   NewSimpleYARAEngine(),
		ClamAV: &MemoryClamAV{},
	})
	res, _ := scanner.ScanAttachment(context.Background(), AttachmentMeta{
		Filename: "invoice.docm",
		MIME:     "application/vnd.ms-word.document.macroEnabled.12",
	}, []byte("CreateObject(\"WScript.Shell\""))
	if res.Verdict != AttachmentVerdictMalicious {
		t.Fatalf("verdict: %q matches=%v", res.Verdict, res.Matches)
	}
}

func TestAttachmentScanner_OversizeIsSuspicious(t *testing.T) {
	scanner, _ := NewAttachmentScanner(AttachmentScannerConfig{
		YARA:     NewSimpleYARAEngine(),
		ClamAV:   &MemoryClamAV{},
		MaxBytes: 16,
	})
	res, _ := scanner.ScanAttachment(context.Background(), AttachmentMeta{
		Filename: "memo.docx",
		MIME:     "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	}, []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	if res.Verdict != AttachmentVerdictSuspicious {
		t.Fatalf("verdict: %q", res.Verdict)
	}
	if !contains(res.Matches, "oversize_attachment") {
		t.Fatalf("matches: %+v", res.Matches)
	}
}

func TestAttachmentScanner_ClamAVErrorIsHandled(t *testing.T) {
	scanner, _ := NewAttachmentScanner(AttachmentScannerConfig{
		YARA:   NewSimpleYARAEngine(),
		ClamAV: &MemoryClamAV{FailWith: errors.New("clamd unreachable")},
	})
	res, err := scanner.ScanAttachment(context.Background(), AttachmentMeta{
		Filename: "memo.docx",
	}, []byte("benign"))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	// ClamAV failure must NOT mark the file malicious by itself —
	// graceful degradation per the YARA-only test rules.
	if res.Verdict != AttachmentVerdictClean {
		t.Fatalf("verdict after clam error: %q", res.Verdict)
	}
}

func TestSimpleYARAEngine_MatchesKnownPatterns(t *testing.T) {
	e := NewSimpleYARAEngine()
	matches, err := e.Match(context.Background(), []byte("inline Shell( for vba malware"))
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if !contains(matches, "vba_shell_invoke") {
		t.Fatalf("expected vba_shell_invoke in %+v", matches)
	}
}

func TestSimpleYARAEngine_NoMatchOnClean(t *testing.T) {
	e := NewSimpleYARAEngine()
	matches, _ := e.Match(context.Background(), []byte("totally benign attachment body"))
	if len(matches) != 0 {
		t.Fatalf("expected no matches, got %+v", matches)
	}
}

func TestDefaultSuspiciousExtensions_Stable(t *testing.T) {
	exts := DefaultSuspiciousExtensions()
	if len(exts) < 10 {
		t.Fatalf("expected canonical extension list, got %d items", len(exts))
	}
	if !contains(exts, "exe") || !contains(exts, "ps1") {
		t.Fatalf("missing high-risk extensions: %+v", exts)
	}
}

func TestClamdClient_ParsesOKResponse(t *testing.T) {
	addr := startFakeClamd(t, func(_ []byte) string {
		return "stream: OK\x00"
	})
	c := NewClamdClient(addr, time.Second)
	clean, sig, err := c.ScanBytes(context.Background(), []byte("benign"))
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	if !clean || sig != "" {
		t.Fatalf("got clean=%v sig=%q", clean, sig)
	}
}

func TestClamdClient_ParsesFoundResponse(t *testing.T) {
	addr := startFakeClamd(t, func(_ []byte) string {
		return "stream: Eicar-Test-Signature FOUND\x00"
	})
	c := NewClamdClient(addr, time.Second)
	clean, sig, err := c.ScanBytes(context.Background(), []byte("EICAR-STANDARD-ANTIVIRUS-TEST-FILE"))
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	if clean || sig != "Eicar-Test-Signature" {
		t.Fatalf("got clean=%v sig=%q", clean, sig)
	}
}

func TestClamdClient_OversizedResponseReturnsCapError(t *testing.T) {
	addr := startFakeClamd(t, func(_ []byte) string {
		return strings.Repeat("A", maxClamdResponseBytes+1)
	})
	c := NewClamdClient(addr, time.Second)
	_, _, err := c.ScanBytes(context.Background(), []byte("benign"))
	if err == nil || !strings.Contains(err.Error(), "byte cap") {
		t.Fatalf("expected cap error, got %v", err)
	}
}

// startFakeClamd brings up a one-shot TCP server that speaks enough
// of the INSTREAM protocol to consume the entire client request, then
// replies with the supplied string, drains any trailing bytes, and
// closes the connection cleanly. Returning the server address.
func startFakeClamd(t *testing.T, reply func(b []byte) string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		payload := drainInstream(conn)
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = conn.Write([]byte(reply(payload)))
		// Drain any straggling bytes from the client to avoid a TCP
		// RST when we close the socket while data is still buffered.
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, _ = io.Copy(io.Discard, conn)
	}()
	return ln.Addr().String()
}

// drainInstream reads a single INSTREAM request from r:
//
//	zINSTREAM\0  <- command
//	[uint32 size][size bytes payload]   <- repeated
//	[uint32 0]   <- end of stream marker
//
// The aggregated payload is returned to the caller. The reader is
// expected to have a read deadline set by the caller.
func drainInstream(r io.Reader) []byte {
	br := make([]byte, 0, 256)
	hdr := make([]byte, 1)
	// Read until we consume the trailing NUL of "zINSTREAM\x00".
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			return br
		}
		if hdr[0] == 0 {
			break
		}
	}
	sizeBuf := make([]byte, 4)
	for {
		if _, err := io.ReadFull(r, sizeBuf); err != nil {
			return br
		}
		size := binary.BigEndian.Uint32(sizeBuf)
		if size == 0 {
			return br
		}
		chunk := make([]byte, size)
		if _, err := io.ReadFull(r, chunk); err != nil {
			return br
		}
		br = append(br, chunk...)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.EqualFold(s, needle) {
			return true
		}
	}
	return false
}
