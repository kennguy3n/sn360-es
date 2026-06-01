package config

import (
	"strings"
	"testing"
)

// TestParseNATSSuperclusterMap_EmptyReturnsNil pins the WS-7a
// backward-compat contract: NATS_SUPERCLUSTER unset / blank /
// whitespace-only must return a nil map, NOT an empty map, so the
// runtime can treat "no supercluster" identically to "single-region".
func TestParseNATSSuperclusterMap_EmptyReturnsNil(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"", "   ", "\n\t"} {
		got, err := parseNATSSuperclusterMap(raw)
		if err != nil {
			t.Fatalf("raw=%q: %v", raw, err)
		}
		if got != nil {
			t.Fatalf("raw=%q: got non-nil map %v, want nil", raw, got)
		}
	}
}

// TestParseNATSSuperclusterMap_InvalidJSON: the parser must
// fail-loud on a malformed payload so the boot stops with a clear
// error rather than silently disabling cross-region routing.
func TestParseNATSSuperclusterMap_InvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := parseNATSSuperclusterMap("not-json")
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "NATS_SUPERCLUSTER") {
		t.Fatalf("error %q must namespace itself under NATS_SUPERCLUSTER", err)
	}
}

// TestParseNATSSuperclusterMap_EmptyJSONObject rejects `{}`: an
// operator who set NATS_SUPERCLUSTER but enumerated zero regions
// almost certainly made a typo; degrading silently to single-region
// would hide it.
func TestParseNATSSuperclusterMap_EmptyJSONObject(t *testing.T) {
	t.Parallel()

	_, err := parseNATSSuperclusterMap("{}")
	if err == nil {
		t.Fatal("expected error for empty JSON object, got nil")
	}
	if !strings.Contains(err.Error(), "at least one region") {
		t.Fatalf("error %q should explain empty-map rejection", err)
	}
}

// TestParseNATSSuperclusterMap_HappyPath: round-trip a populated map
// and confirm whitespace around URLs is stripped and empty fields are
// dropped while the input order within each entry is preserved.
func TestParseNATSSuperclusterMap_HappyPath(t *testing.T) {
	t.Parallel()

	raw := `{
		"ap-southeast-1": " nats://leaf-a:4222 , nats://leaf-b:4222 ",
		"us-east-1":      "nats://leaf-us1:4222,,nats://leaf-us2:4222"
	}`
	got, err := parseNATSSuperclusterMap(raw)
	if err != nil {
		t.Fatalf("parseNATSSuperclusterMap: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 regions, got %d", len(got))
	}
	if got["ap-southeast-1"] != "nats://leaf-a:4222,nats://leaf-b:4222" {
		t.Fatalf("ap-southeast-1: not canonicalised: %q", got["ap-southeast-1"])
	}
	if got["us-east-1"] != "nats://leaf-us1:4222,nats://leaf-us2:4222" {
		t.Fatalf("us-east-1: not canonicalised: %q", got["us-east-1"])
	}
}

// TestParseNATSSuperclusterMap_RejectsEmptyURLList covers the
// fail-closed contract on the entry form: a region with only commas
// or whitespace must error out at boot. Otherwise a cross-region
// publish would silently dial an empty server list at dispatch time.
func TestParseNATSSuperclusterMap_RejectsEmptyURLList(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
	}{
		{name: "whitespace-only", raw: `{"ap-southeast-1": "   "}`},
		{name: "commas-only", raw: `{"ap-southeast-1": ",,,"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNATSSuperclusterMap(tc.raw)
			if err == nil {
				t.Fatalf("expected error for raw=%q, got nil", tc.raw)
			}
			if !strings.Contains(err.Error(), "ap-southeast-1") {
				t.Fatalf("error %q must name offending region", err)
			}
		})
	}
}
