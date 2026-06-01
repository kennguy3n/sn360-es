package nats

import (
	"strings"
	"testing"
)

// TestResolveSuperclusterServers_EmptyMap covers the WS-7a backward
// compatibility contract: when Supercluster is nil / empty the helper
// must return cfg.URL unchanged. A regression here would force every
// existing single-region deployment to set NATS_SUPERCLUSTER just to
// keep booting.
func TestResolveSuperclusterServers_EmptyMap(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "nil supercluster + nonempty URL stays unchanged",
			cfg:  Config{URL: "nats://primary:4222"},
			want: "nats://primary:4222",
		},
		{
			name: "empty supercluster + nonempty URL stays unchanged",
			cfg: Config{
				URL:          "nats://primary:4222",
				HomeRegion:   "ap-southeast-1",
				Supercluster: map[string]string{},
			},
			want: "nats://primary:4222",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveSuperclusterServers(tc.cfg)
			if err != nil {
				t.Fatalf("resolveSuperclusterServers: %v", err)
			}
			if got != tc.want {
				t.Fatalf("connect URL: got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestResolveSuperclusterServers_HomeRegionMissing verifies the
// fail-closed contract on misconfiguration: an operator who set
// NATS_SUPERCLUSTER but forgot PG_HOME_REGION must see the binary fail
// at boot, not at first message.
func TestResolveSuperclusterServers_HomeRegionMissing(t *testing.T) {
	t.Parallel()

	_, err := resolveSuperclusterServers(Config{
		URL: "nats://primary:4222",
		Supercluster: map[string]string{
			"ap-southeast-1": "nats://leaf-1:4222",
		},
	})
	if err == nil {
		t.Fatal("expected error when home region empty, got nil")
	}
	if !strings.Contains(err.Error(), "supercluster configured without home region") {
		t.Fatalf("error %q does not mention home region requirement", err)
	}
}

// TestResolveSuperclusterServers_HomeRegionNotInMap is the second
// fail-closed case: the operator picked a home region that has no
// entry in the supercluster map (likely a typo). The error must list
// the available regions to make the typo obvious.
func TestResolveSuperclusterServers_HomeRegionNotInMap(t *testing.T) {
	t.Parallel()

	_, err := resolveSuperclusterServers(Config{
		URL:        "nats://primary:4222",
		HomeRegion: "us-east-2",
		Supercluster: map[string]string{
			"ap-southeast-1": "nats://leaf-ap:4222",
			"us-east-1":      "nats://leaf-use1:4222",
		},
	})
	if err == nil {
		t.Fatal("expected error when home region absent from map, got nil")
	}
	if !strings.Contains(err.Error(), "us-east-2") {
		t.Fatalf("error %q does not mention the missing home region", err)
	}
	// Both populated regions must be listed in lexicographic order
	// so error messages are stable across boots.
	if !strings.Contains(err.Error(), "[ap-southeast-1 us-east-1]") {
		t.Fatalf("error %q does not list populated regions in lex order", err)
	}
}

// TestResolveSuperclusterServers_EmptyURLList rejects the misconfig
// where the operator supplied an entry but left the URL list empty
// (e.g. "ap-southeast-1": "  ,  "). Falling back to cfg.URL would
// silently defeat the failover the operator clearly intended.
func TestResolveSuperclusterServers_EmptyURLList(t *testing.T) {
	t.Parallel()

	_, err := resolveSuperclusterServers(Config{
		URL:        "nats://primary:4222",
		HomeRegion: "ap-southeast-1",
		Supercluster: map[string]string{
			"ap-southeast-1": "  ,  ",
		},
	})
	if err == nil {
		t.Fatal("expected error when home region URL list empty, got nil")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("error %q should mention empty list", err)
	}
}

// TestResolveSuperclusterServers_MergesPrimaryAndLeaves is the
// happy-path test: nats.Connect must receive the primary URL first
// followed by every leaf URL in input order. Order matters here
// because nats.Connect dials in list order and we want the primary
// (locally health-checked) to win under normal conditions.
func TestResolveSuperclusterServers_MergesPrimaryAndLeaves(t *testing.T) {
	t.Parallel()

	got, err := resolveSuperclusterServers(Config{
		URL:        "nats://primary:4222",
		HomeRegion: "ap-southeast-1",
		Supercluster: map[string]string{
			"ap-southeast-1": "nats://leaf-ap1:4222, nats://leaf-ap2:4222",
			"us-east-1":      "nats://leaf-use1:4222",
		},
	})
	if err != nil {
		t.Fatalf("resolveSuperclusterServers: %v", err)
	}
	want := "nats://primary:4222,nats://leaf-ap1:4222,nats://leaf-ap2:4222"
	if got != want {
		t.Fatalf("connect URL: got %q, want %q", got, want)
	}
}

// TestResolveSuperclusterServers_DropsDuplicates protects against the
// trivial misconfig where an operator pasted the primary URL into
// the supercluster list — duplicates would otherwise inflate the
// reconnect-attempt count and produce confusing fail-over logs.
func TestResolveSuperclusterServers_DropsDuplicates(t *testing.T) {
	t.Parallel()

	got, err := resolveSuperclusterServers(Config{
		URL:        "nats://primary:4222",
		HomeRegion: "ap-southeast-1",
		Supercluster: map[string]string{
			"ap-southeast-1": "nats://primary:4222, nats://leaf-ap1:4222, nats://primary:4222",
		},
	})
	if err != nil {
		t.Fatalf("resolveSuperclusterServers: %v", err)
	}
	want := "nats://primary:4222,nats://leaf-ap1:4222"
	if got != want {
		t.Fatalf("connect URL: got %q, want %q", got, want)
	}
}

// TestMergeNATSServerList_NoPrimary covers the edge case where the
// primary URL was left blank but a leaf-cluster list was supplied
// (an unusual but valid deployment topology: operate only the leaf
// nodes). The helper should fall through to the leaf list rather
// than emit a leading empty entry.
func TestMergeNATSServerList_NoPrimary(t *testing.T) {
	t.Parallel()

	got := mergeNATSServerList("", []string{"nats://leaf-a:4222", " nats://leaf-b:4222 "})
	want := []string{"nats://leaf-a:4222", "nats://leaf-b:4222"}
	if len(got) != len(want) {
		t.Fatalf("merged servers: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("merged servers[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}
