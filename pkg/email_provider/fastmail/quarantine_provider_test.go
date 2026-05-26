package fastmail

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/service/action"
)

// quarantineServerCfg lets each test customise the fake JMAP server
// response sequence without rewriting the mux from scratch.
type quarantineServerCfg struct {
	t            *testing.T
	rawMessage   string // initial RFC822 served by /download/
	mailboxes    []map[string]string
	importedIDs  []string // pre-seeded IDs to hand out from Email/import in order
	destroyOK    bool
	destroyError string
}

// quarantineServerObserver records what each request looked like so
// tests can assert on the cross-step contract.
type quarantineServerObserver struct {
	mu sync.Mutex

	// Email/get accountId and ids it was asked for.
	emailGets []emailGetCall
	// All Email/import calls (mailboxIds + blobId).
	imports []importCall
	// All Email/set calls — used for both move-via-mailboxIds and destroy.
	emailSets []emailSetCall
	// All raw blob uploads (their bodies).
	uploads []string
	// Number of downloads served.
	downloads atomic.Int32
}

type emailGetCall struct {
	IDs []string
}

type importCall struct {
	BlobID     string
	MailboxIDs map[string]bool
	Keywords   map[string]bool
}

type emailSetCall struct {
	Update  map[string]map[string]any
	Destroy []string
}

func (o *quarantineServerObserver) recordEmailGet(c emailGetCall) {
	o.mu.Lock()
	o.emailGets = append(o.emailGets, c)
	o.mu.Unlock()
}

func (o *quarantineServerObserver) recordImport(c importCall) {
	o.mu.Lock()
	o.imports = append(o.imports, c)
	o.mu.Unlock()
}

func (o *quarantineServerObserver) recordSet(c emailSetCall) {
	o.mu.Lock()
	o.emailSets = append(o.emailSets, c)
	o.mu.Unlock()
}

func (o *quarantineServerObserver) recordUpload(body string) {
	o.mu.Lock()
	o.uploads = append(o.uploads, body)
	o.mu.Unlock()
}

func newQuarantineTestServer(cfg quarantineServerCfg) (*httptest.Server, *quarantineServerObserver) {
	cfg.t.Helper()
	obs := &quarantineServerObserver{}
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/.well-known/jmap", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"apiUrl":      srv.URL + "/jmap/api/",
			"downloadUrl": srv.URL + "/jmap/download/{accountId}/{blobId}/{name}",
			"uploadUrl":   srv.URL + "/jmap/upload/{accountId}/",
			"primaryAccounts": map[string]string{
				"urn:ietf:params:jmap:mail": "acct-1",
			},
		})
	})

	mux.HandleFunc("/jmap/download/", func(w http.ResponseWriter, _ *http.Request) {
		obs.downloads.Add(1)
		w.Header().Set("Content-Type", "message/rfc822")
		_, _ = w.Write([]byte(cfg.rawMessage))
	})

	mux.HandleFunc("/jmap/upload/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		obs.recordUpload(string(body))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"blobId": "blob-uploaded"})
	})

	// Index of how many imports we've handed out.
	var importIdx atomic.Int32

	mux.HandleFunc("/jmap/api/", func(w http.ResponseWriter, r *http.Request) {
		var body jmapRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			cfg.t.Fatalf("decode jmap request: %v", err)
		}
		responses := make([][]any, 0, len(body.MethodCalls))
		for _, call := range body.MethodCalls {
			method, _ := call[0].(string)
			rawArgs, _ := json.Marshal(call[1])
			callID, _ := call[2].(string)
			switch method {
			case "Mailbox/get":
				// Return our fake mailbox list — used to resolve
				// inbox / quarantine ids in the provider.
				list := make([]map[string]string, 0, len(cfg.mailboxes))
				list = append(list, cfg.mailboxes...)
				responses = append(responses, []any{"Mailbox/get", map[string]any{"list": list}, callID})
			case "Email/get":
				var dec struct {
					IDs []string `json:"ids"`
				}
				_ = json.Unmarshal(rawArgs, &dec)
				obs.recordEmailGet(emailGetCall{IDs: dec.IDs})
				resp := map[string]any{
					"list": []map[string]any{{
						"id":         "msg-original",
						"blobId":     "blob-original",
						"mailboxIds": map[string]bool{"quarantine-mbx": true},
						"keywords":   map[string]bool{"$seen": true},
					}},
				}
				responses = append(responses, []any{"Email/get", resp, callID})
			case "Email/import":
				var dec struct {
					Emails map[string]struct {
						BlobID     string          `json:"blobId"`
						MailboxIDs map[string]bool `json:"mailboxIds"`
						Keywords   map[string]bool `json:"keywords"`
					} `json:"emails"`
				}
				_ = json.Unmarshal(rawArgs, &dec)
				for _, e := range dec.Emails {
					obs.recordImport(importCall{BlobID: e.BlobID, MailboxIDs: e.MailboxIDs, Keywords: e.Keywords})
				}
				idx := importIdx.Add(1) - 1
				var newID string
				switch {
				case int(idx) < len(cfg.importedIDs):
					newID = cfg.importedIDs[idx]
				default:
					newID = "msg-imported"
				}
				resp := map[string]any{
					"created": map[string]any{
						"new": map[string]any{"id": newID},
					},
				}
				responses = append(responses, []any{"Email/import", resp, callID})
			case "Email/set":
				var dec struct {
					Update  map[string]map[string]any `json:"update"`
					Destroy []string                  `json:"destroy"`
				}
				_ = json.Unmarshal(rawArgs, &dec)
				obs.recordSet(emailSetCall{Update: dec.Update, Destroy: dec.Destroy})
				resp := map[string]any{}
				if cfg.destroyOK || len(dec.Destroy) == 0 {
					resp["destroyed"] = dec.Destroy
				} else {
					notDestroyed := map[string]json.RawMessage{}
					for _, id := range dec.Destroy {
						notDestroyed[id] = json.RawMessage(`{"type":"serverFail","description":"` + cfg.destroyError + `"}`)
					}
					resp["notDestroyed"] = notDestroyed
				}
				responses = append(responses, []any{"Email/set", resp, callID})
			default:
				cfg.t.Errorf("unexpected method call %q", method)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"methodResponses": responses,
			"sessionState":    "s-1",
		})
	})

	srv = httptest.NewServer(mux)
	cfg.t.Cleanup(srv.Close)
	return srv, obs
}

// buildMultipartRaw returns a minimal multipart/alternative RFC822
// envelope with the supplied HTML — sufficient for replaceHTMLBody
// to splice in the stub.
func buildMultipartRaw(t *testing.T, originalHTML string) string {
	t.Helper()
	const boundary = "bnd-quarantine-test"
	return strings.Join([]string{
		"From: alice@example.test",
		"To: bob@example.test",
		"Subject: original",
		"MIME-Version: 1.0",
		`Content-Type: multipart/alternative; boundary="` + boundary + `"`,
		"",
		"--" + boundary,
		"Content-Type: text/html; charset=utf-8",
		"",
		originalHTML,
		"--" + boundary + "--",
		"",
	}, "\r\n")
}

// TestMoveToQuarantine_SingleStub_ReturnsNewID guards the round-6
// architectural fix: stub-body quarantine must do the upload/import/
// destroy dance in a single pass and return the imported message's
// new id (not the now-destroyed original). Pre-fix the function
// returned no id; the QuarantineService stored the old id and
// RestoreFromQuarantine could never locate the message.
func TestMoveToQuarantine_SingleStub_ReturnsNewID(t *testing.T) {
	srv, obs := newQuarantineTestServer(quarantineServerCfg{
		t:           t,
		rawMessage:  buildMultipartRaw(t, "<p>original body</p>"),
		mailboxes:   []map[string]string{{"id": "quarantine-mbx", "name": "SN360 / Quarantined", "role": ""}},
		importedIDs: []string{"msg-fresh-after-quarantine"},
		destroyOK:   true,
	})
	c, err := NewClient(ClientConfig{
		TokenSource: staticTokenSource("tok"),
		BaseURL:     srv.URL,
		AccountID:   "acct-1",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	qp, err := NewQuarantineProvider(QuarantineProviderConfig{Client: c})
	if err != nil {
		t.Fatalf("NewQuarantineProvider: %v", err)
	}

	newID, err := qp.MoveToQuarantine(context.Background(), "alice@example.test", "msg-original", "quarantine-mbx", "Quarantined by SN360")
	if err != nil {
		t.Fatalf("MoveToQuarantine: %v", err)
	}
	if newID != "msg-fresh-after-quarantine" {
		t.Errorf("MoveToQuarantine returned id %q, want msg-fresh-after-quarantine", newID)
	}

	// Verify the import targeted only the quarantine mailbox.
	if len(obs.imports) != 1 {
		t.Fatalf("got %d imports, want exactly 1", len(obs.imports))
	}
	if !obs.imports[0].MailboxIDs["quarantine-mbx"] || len(obs.imports[0].MailboxIDs) != 1 {
		t.Errorf("import mailboxIds = %v, want only quarantine-mbx", obs.imports[0].MailboxIDs)
	}
	// And the destroy targeted the ORIGINAL id, not the new one.
	var destroyTargets []string
	for _, s := range obs.emailSets {
		destroyTargets = append(destroyTargets, s.Destroy...)
	}
	if len(destroyTargets) != 1 || destroyTargets[0] != "msg-original" {
		t.Errorf("destroy targets = %v, want [msg-original]", destroyTargets)
	}
	// Uploaded body should contain the escaped stub text.
	if len(obs.uploads) != 1 {
		t.Fatalf("got %d uploads, want 1", len(obs.uploads))
	}
	if !strings.Contains(obs.uploads[0], "Quarantined by SN360") {
		t.Errorf("uploaded RFC822 did not include the stub: %s", obs.uploads[0])
	}
	if strings.Contains(obs.uploads[0], "<p>original body</p>") {
		t.Errorf("uploaded RFC822 still contained the original body, want it replaced")
	}
}

// TestMoveToQuarantine_EmptyStub_PreservesID covers the cheap path:
// when stubBody is empty we keep the original message and just flip
// its mailboxIds. The returned id must equal the input.
func TestMoveToQuarantine_EmptyStub_PreservesID(t *testing.T) {
	srv, obs := newQuarantineTestServer(quarantineServerCfg{
		t:          t,
		rawMessage: "should not be downloaded",
		mailboxes:  []map[string]string{{"id": "quarantine-mbx", "name": "SN360 / Quarantined", "role": ""}},
	})
	c, _ := NewClient(ClientConfig{TokenSource: staticTokenSource("tok"), BaseURL: srv.URL, AccountID: "acct-1"})
	qp, _ := NewQuarantineProvider(QuarantineProviderConfig{Client: c})
	newID, err := qp.MoveToQuarantine(context.Background(), "alice@example.test", "msg-original", "quarantine-mbx", "")
	if err != nil {
		t.Fatalf("MoveToQuarantine: %v", err)
	}
	if newID != "msg-original" {
		t.Errorf("empty-stub MoveToQuarantine returned %q, want msg-original", newID)
	}
	if got := obs.downloads.Load(); got != 0 {
		t.Errorf("empty-stub path downloaded raw %d times, want 0", got)
	}
	if len(obs.imports) != 0 {
		t.Errorf("empty-stub path performed %d imports, want 0", len(obs.imports))
	}
	// The path SHOULD call Email/set with an Update that moves
	// mailboxIds — we don't assert on its exact shape here.
	if len(obs.emailSets) == 0 {
		t.Error("empty-stub path did not call Email/set to flip mailboxIds")
	}
}

// TestRestoreFromQuarantine_ReturnsNewID covers the same architectural
// fix on the restore side: the JMAP body rewrite destroys the
// quarantined message and imports a fresh one in the inbox; the
// release flow must use the returned id, not the stale input.
func TestRestoreFromQuarantine_ReturnsNewID(t *testing.T) {
	srv, obs := newQuarantineTestServer(quarantineServerCfg{
		t:          t,
		rawMessage: buildMultipartRaw(t, "<p>stub body</p>"),
		mailboxes: []map[string]string{
			{"id": "inbox-1", "name": "Inbox", "role": "inbox"},
			{"id": "quarantine-mbx", "name": "SN360 / Quarantined", "role": ""},
		},
		importedIDs: []string{"msg-fresh-after-restore"},
		destroyOK:   true,
	})
	c, _ := NewClient(ClientConfig{TokenSource: staticTokenSource("tok"), BaseURL: srv.URL, AccountID: "acct-1"})
	qp, _ := NewQuarantineProvider(QuarantineProviderConfig{Client: c})
	newID, err := qp.RestoreFromQuarantine(context.Background(), "alice@example.test", "msg-quarantined", "quarantine-mbx", "<p>Released by SN360.</p>")
	if err != nil {
		t.Fatalf("RestoreFromQuarantine: %v", err)
	}
	if newID != "msg-fresh-after-restore" {
		t.Errorf("RestoreFromQuarantine returned %q, want msg-fresh-after-restore", newID)
	}
	if len(obs.imports) != 1 || !obs.imports[0].MailboxIDs["inbox-1"] || len(obs.imports[0].MailboxIDs) != 1 {
		t.Errorf("restore import mailboxIds = %v, want only inbox-1", obs.imports[0].MailboxIDs)
	}
}

// TestMoveToQuarantine_DestroyPartialFailure_ReturnsNewIDWithError
// pins down the partial-failure contract: when the import has already
// succeeded but the destroy fails, the provider must return the
// freshly-imported id together with the error so the caller's
// QuarantineRecord points at the message that actually exists.
func TestMoveToQuarantine_DestroyPartialFailure_ReturnsNewIDWithError(t *testing.T) {
	srv, _ := newQuarantineTestServer(quarantineServerCfg{
		t:            t,
		rawMessage:   buildMultipartRaw(t, "<p>original</p>"),
		mailboxes:    []map[string]string{{"id": "quarantine-mbx", "name": "SN360 / Quarantined", "role": ""}},
		importedIDs:  []string{"msg-fresh"},
		destroyOK:    false,
		destroyError: "would block",
	})
	c, _ := NewClient(ClientConfig{TokenSource: staticTokenSource("tok"), BaseURL: srv.URL, AccountID: "acct-1"})
	qp, _ := NewQuarantineProvider(QuarantineProviderConfig{Client: c})
	newID, err := qp.MoveToQuarantine(context.Background(), "alice@example.test", "msg-original", "quarantine-mbx", "Quarantined")
	if err == nil {
		t.Fatal("expected destroy-failure error to surface")
	}
	if newID != "msg-fresh" {
		t.Errorf("partial-failure newID = %q, want msg-fresh (the import succeeded)", newID)
	}
}

// Compile-time guard that the test-only fake fastmail-quarantine
// provider satisfies the public action.QuarantineProvider interface.
var _ action.QuarantineProvider = (*QuarantineProvider)(nil)
