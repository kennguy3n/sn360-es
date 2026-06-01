package dto

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestEvaluateResult_HashFields_RoundTrip pins the WS-3b participant
// hash propagation contract: the (sender_hash, recipient_hash) bytes
// stamped onto the result by the producer (per-message handler or
// batch finalisePending) must survive a JSON round-trip identically
// — both fields use the same `encoding/json` BYTEA-base64 wire shape
// as the existing message_id_hash + dedup_id elsewhere in the DTO
// surface. A regression here would silently break the investigation
// API's sender-trail lookup because the management Postgres writer
// would insert a different hash than the one indexed on.
func TestEvaluateResult_HashFields_RoundTrip(t *testing.T) {
	in := EvaluateResult{
		MessageID:     "msg-1",
		Score:         88,
		Tier:          "blocked",
		SenderHash:    []byte{0x01, 0x02, 0x03},
		RecipientHash: []byte{0xfe, 0xff},
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out EvaluateResult
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !bytes.Equal(out.SenderHash, in.SenderHash) {
		t.Errorf("sender_hash round-trip: got %x, want %x", out.SenderHash, in.SenderHash)
	}
	if !bytes.Equal(out.RecipientHash, in.RecipientHash) {
		t.Errorf("recipient_hash round-trip: got %x, want %x", out.RecipientHash, in.RecipientHash)
	}
}

// TestEvaluateResult_HashFields_OmitemptyBackwardCompat pins the
// backward-compat property: when both hashes are empty, the wire
// form omits the keys entirely so an older consumer that doesn't
// know about the fields cannot accidentally interpret them. This
// also keeps the typical wire size small for the high-throughput
// evaluate.result subject.
func TestEvaluateResult_HashFields_OmitemptyBackwardCompat(t *testing.T) {
	in := EvaluateResult{MessageID: "msg-1", Score: 50}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	wire := string(raw)
	if strings.Contains(wire, "sender_hash") {
		t.Errorf("empty sender_hash leaked into wire form: %s", wire)
	}
	if strings.Contains(wire, "recipient_hash") {
		t.Errorf("empty recipient_hash leaked into wire form: %s", wire)
	}
}

// TestEvaluateResult_HashFields_DecodeMissingTolerated pins the
// other half of backward compat: a producer that omits the fields
// (older binary still on the wire) MUST decode cleanly with both
// fields zero-length. The investigation API treats zero-length as
// "participant unknown" and renders an absent join.
func TestEvaluateResult_HashFields_DecodeMissingTolerated(t *testing.T) {
	wire := `{"message_id":"msg-1","score":50,"tier":"medium"}`
	var out EvaluateResult
	if err := json.Unmarshal([]byte(wire), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.SenderHash) != 0 {
		t.Errorf("missing sender_hash decoded as %x; want empty", out.SenderHash)
	}
	if len(out.RecipientHash) != 0 {
		t.Errorf("missing recipient_hash decoded as %x; want empty", out.RecipientHash)
	}
}
