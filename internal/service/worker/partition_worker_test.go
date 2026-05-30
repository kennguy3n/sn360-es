package worker

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"
)

// fakePartitionManager is an in-memory PartitionManager. It records
// every CreatePartition / DropPartition call and serves
// ListPartitions out of a sorted map so tests can assert against
// the post-cycle state.
type fakePartitionManager struct {
	mu      sync.Mutex
	state   map[string]map[string]Partition // parent → name → Partition
	created []callRecord
	dropped []callRecord
	// listErr / createErr / dropErr can be set to force an error
	// path on the next call. They are not consumed.
	listErr   error
	createErr error
	dropErr   error
}

type callRecord struct {
	parent    string
	partition string
	lower     time.Time
	upper     time.Time
}

func newFakeManager() *fakePartitionManager {
	return &fakePartitionManager{state: map[string]map[string]Partition{}}
}

func (f *fakePartitionManager) ListPartitions(ctx context.Context, parent string) ([]Partition, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]Partition, 0, len(f.state[parent]))
	for _, p := range f.state[parent] {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Upper.Before(out[j].Upper) })
	return out, nil
}

func (f *fakePartitionManager) CreatePartition(ctx context.Context, parent, partition string, lower, upper time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return f.createErr
	}
	if f.state[parent] == nil {
		f.state[parent] = map[string]Partition{}
	}
	f.state[parent][partition] = Partition{Name: partition, Lower: lower, Upper: upper}
	f.created = append(f.created, callRecord{parent: parent, partition: partition, lower: lower, upper: upper})
	return nil
}

func (f *fakePartitionManager) DropPartition(ctx context.Context, parent, partition string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dropErr != nil {
		return f.dropErr
	}
	if f.state[parent] != nil {
		delete(f.state[parent], partition)
	}
	f.dropped = append(f.dropped, callRecord{parent: parent, partition: partition})
	return nil
}

func (f *fakePartitionManager) seedLegacy(parent string, upper time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state[parent] == nil {
		f.state[parent] = map[string]Partition{}
	}
	name := parent + "_legacy"
	f.state[parent][name] = Partition{
		Name:   name,
		Lower:  time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		Upper:  upper,
		Legacy: true,
	}
}

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// TestPartitionMaintenanceJob_CreatesLookaheadMonths verifies that
// the maintenance cycle pre-creates the current month plus
// LookaheadMonths forward months when none exist.
func TestPartitionMaintenanceJob_CreatesLookaheadMonths(t *testing.T) {
	mgr := newFakeManager()
	mgr.seedLegacy("evaluation_results", time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC))

	job, err := NewPartitionMaintenanceJob(PartitionMaintenanceConfig{
		Interval:        time.Hour,
		LookaheadMonths: 3,
		Tables: []PartitionedTable{
			{Parent: "evaluation_results", NamePrefix: "evaluation_results", RetentionMonths: 12},
		},
		Manager: mgr,
		Logger:  discardLogger(),
		Clock:   fixedClock(time.Date(2026, 5, 29, 14, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatalf("NewPartitionMaintenanceJob: %v", err)
	}
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Should have created May, Jun, Jul, Aug 2026 (current + 3
	// forward). Legacy already existed and was not touched.
	wantNames := []string{
		"evaluation_results_2026_05",
		"evaluation_results_2026_06",
		"evaluation_results_2026_07",
		"evaluation_results_2026_08",
	}
	if got := len(mgr.created); got != len(wantNames) {
		t.Fatalf("created %d partitions, want %d (records: %+v)", got, len(wantNames), mgr.created)
	}
	for _, want := range wantNames {
		if _, ok := mgr.state["evaluation_results"][want]; !ok {
			t.Errorf("missing partition %s in post-cycle state", want)
		}
	}
}

// TestPartitionMaintenanceJob_DoesNotRecreateExisting verifies the
// CREATE step is idempotent: re-running a cycle with an already-
// populated partition set produces zero new CreatePartition calls.
func TestPartitionMaintenanceJob_DoesNotRecreateExisting(t *testing.T) {
	mgr := newFakeManager()
	mgr.seedLegacy("audit_logs", time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC))

	job, err := NewPartitionMaintenanceJob(PartitionMaintenanceConfig{
		Interval:        time.Hour,
		LookaheadMonths: 2,
		Tables: []PartitionedTable{
			{Parent: "audit_logs", NamePrefix: "audit_logs", RetentionMonths: 6},
		},
		Manager: mgr,
		Logger:  discardLogger(),
		Clock:   fixedClock(time.Date(2026, 5, 29, 14, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatalf("NewPartitionMaintenanceJob: %v", err)
	}
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	firstCount := len(mgr.created)
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if got := len(mgr.created); got != firstCount {
		t.Fatalf("second cycle created %d additional partitions; want 0 (records: %+v)",
			got-firstCount, mgr.created[firstCount:])
	}
}

// TestPartitionMaintenanceJob_DropsBeyondRetention exercises the
// retention-driven drop logic and verifies that the legacy partition
// is never dropped.
func TestPartitionMaintenanceJob_DropsBeyondRetention(t *testing.T) {
	mgr := newFakeManager()
	// Seed legacy (must survive). Seed three monthly partitions:
	// one well outside retention (Jan), one just outside (Feb),
	// one inside (Apr).
	mgr.seedLegacy("feedback_events", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	mgr.state["feedback_events"]["feedback_events_2026_01"] = Partition{
		Name:  "feedback_events_2026_01",
		Lower: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Upper: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
	}
	mgr.state["feedback_events"]["feedback_events_2026_02"] = Partition{
		Name:  "feedback_events_2026_02",
		Lower: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		Upper: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
	}
	mgr.state["feedback_events"]["feedback_events_2026_04"] = Partition{
		Name:  "feedback_events_2026_04",
		Lower: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		Upper: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
	}

	// RetentionMonths=3 with now=2026-05-29 → curStart=2026-05-01
	// → cutoff=2026-02-01. Partitions with Upper at-or-before
	// 2026-02-01 are dropped (rows entirely older than cutoff):
	// the 2026_01 partition (Upper = 2026-02-01) qualifies.
	// 2026_02 (Upper = 2026-03-01) is later than cutoff so it
	// survives. 2026_04 (Upper = 2026-05-01) is well after cutoff.
	job, err := NewPartitionMaintenanceJob(PartitionMaintenanceConfig{
		Interval:        time.Hour,
		LookaheadMonths: 0,
		Tables: []PartitionedTable{
			{Parent: "feedback_events", NamePrefix: "feedback_events", RetentionMonths: 3},
		},
		Manager: mgr,
		Logger:  discardLogger(),
		Clock:   fixedClock(time.Date(2026, 5, 29, 14, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatalf("NewPartitionMaintenanceJob: %v", err)
	}
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got, want := len(mgr.dropped), 1; got != want {
		t.Fatalf("dropped %d partitions, want %d (records: %+v)", got, want, mgr.dropped)
	}
	if mgr.dropped[0].partition != "feedback_events_2026_01" {
		t.Errorf("dropped %q, want feedback_events_2026_01", mgr.dropped[0].partition)
	}
	if _, ok := mgr.state["feedback_events"]["feedback_events_legacy"]; !ok {
		t.Error("legacy partition was dropped; it must always survive")
	}
}

// TestPartitionMaintenanceJob_HonoursRetentionDisabled verifies
// that RetentionMonths<=0 skips the drop sweep entirely while
// forward creation still proceeds.
func TestPartitionMaintenanceJob_HonoursRetentionDisabled(t *testing.T) {
	mgr := newFakeManager()
	mgr.state["audit_logs"] = map[string]Partition{
		"audit_logs_1990_01": {
			Name:  "audit_logs_1990_01",
			Lower: time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC),
			Upper: time.Date(1990, 2, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	job, err := NewPartitionMaintenanceJob(PartitionMaintenanceConfig{
		Interval:        time.Hour,
		LookaheadMonths: 1,
		Tables: []PartitionedTable{
			{Parent: "audit_logs", NamePrefix: "audit_logs", RetentionMonths: 0},
		},
		Manager: mgr,
		Logger:  discardLogger(),
		Clock:   fixedClock(time.Date(2026, 5, 29, 14, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatalf("NewPartitionMaintenanceJob: %v", err)
	}
	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(mgr.dropped) != 0 {
		t.Errorf("drop occurred with RetentionMonths=0: %+v", mgr.dropped)
	}
	if len(mgr.created) == 0 {
		t.Errorf("forward creation did not run with RetentionMonths=0; expected at least 1")
	}
}

// TestPartitionMaintenanceJob_PerTableErrorIsolation verifies that
// an error on one table does not prevent the next from being
// reconciled.
func TestPartitionMaintenanceJob_PerTableErrorIsolation(t *testing.T) {
	good := newFakeManager()
	good.seedLegacy("audit_logs", time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC))
	good.seedLegacy("evaluation_results", time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC))

	// Force the first table's list to fail. The second table must
	// still get its forward partitions created.
	failOnFirst := &selectiveErrManager{inner: good, failOn: "audit_logs"}
	job, err := NewPartitionMaintenanceJob(PartitionMaintenanceConfig{
		Interval:        time.Hour,
		LookaheadMonths: 1,
		Tables: []PartitionedTable{
			{Parent: "audit_logs", NamePrefix: "audit_logs", RetentionMonths: 6},
			{Parent: "evaluation_results", NamePrefix: "evaluation_results", RetentionMonths: 6},
		},
		Manager: failOnFirst,
		Logger:  discardLogger(),
		Clock:   fixedClock(time.Date(2026, 5, 29, 14, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatalf("NewPartitionMaintenanceJob: %v", err)
	}
	err = job.Run(context.Background())
	if err == nil {
		t.Fatalf("Run: expected error from the failing table")
	}
	// Second table partitions must exist.
	for _, want := range []string{"evaluation_results_2026_05", "evaluation_results_2026_06"} {
		if _, ok := good.state["evaluation_results"][want]; !ok {
			t.Errorf("second table not reconciled: missing %s", want)
		}
	}
}

// selectiveErrManager wraps a fakePartitionManager and forces
// ListPartitions to fail for one specific parent. It exists only
// for TestPartitionMaintenanceJob_PerTableErrorIsolation.
type selectiveErrManager struct {
	inner  *fakePartitionManager
	failOn string
}

func (s *selectiveErrManager) ListPartitions(ctx context.Context, parent string) ([]Partition, error) {
	if parent == s.failOn {
		return nil, errors.New("forced failure")
	}
	return s.inner.ListPartitions(ctx, parent)
}

func (s *selectiveErrManager) CreatePartition(ctx context.Context, parent, partition string, lower, upper time.Time) error {
	return s.inner.CreatePartition(ctx, parent, partition, lower, upper)
}

func (s *selectiveErrManager) DropPartition(ctx context.Context, parent, partition string) error {
	return s.inner.DropPartition(ctx, parent, partition)
}

// TestNewPartitionMaintenanceJob_RejectsBadConfig pins the
// constructor's required-field validation so a misconfiguration in
// wire_infra.go fails fast at boot rather than at the first cycle.
func TestNewPartitionMaintenanceJob_RejectsBadConfig(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*PartitionMaintenanceConfig)
	}{
		{name: "zero interval", mut: func(c *PartitionMaintenanceConfig) { c.Interval = 0 }},
		{name: "nil manager", mut: func(c *PartitionMaintenanceConfig) { c.Manager = nil }},
		{name: "empty tables", mut: func(c *PartitionMaintenanceConfig) { c.Tables = nil }},
		{name: "empty parent", mut: func(c *PartitionMaintenanceConfig) {
			c.Tables = []PartitionedTable{{Parent: "", NamePrefix: "x"}}
		}},
		{name: "empty prefix", mut: func(c *PartitionMaintenanceConfig) {
			c.Tables = []PartitionedTable{{Parent: "x", NamePrefix: ""}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := PartitionMaintenanceConfig{
				Interval:        time.Hour,
				LookaheadMonths: 1,
				Tables:          []PartitionedTable{{Parent: "audit_logs", NamePrefix: "audit_logs"}},
				Manager:         newFakeManager(),
			}
			tc.mut(&cfg)
			if _, err := NewPartitionMaintenanceJob(cfg); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

// TestSanitizePartitionName locks in the DDL-safe identifier
// contract: the worker never concatenates user-controlled strings,
// but SanitizePartitionName exists as a defensive helper for any
// future caller (e.g. a manual repartition tool) and the contract
// MUST stay strict.
func TestSanitizePartitionName(t *testing.T) {
	type tc struct {
		in   string
		want string
		err  bool
	}
	cases := []tc{
		{in: "audit_logs_2026_05", want: "audit_logs_2026_05"},
		{in: "AUDIT_LOGS_2026_05", want: "audit_logs_2026_05"},
		{in: "_internal_partition_1", want: "_internal_partition_1"},
		{in: "", err: true},
		{in: "audit_logs;DROP TABLE foo", err: true},
		{in: "audit_logs--", err: true},
		{in: "1month_partition", err: true},       // leading digit
		{in: fmt.Sprintf("%64s", "x"), err: true}, // too long
	}
	for _, c := range cases {
		got, err := SanitizePartitionName(c.in)
		if c.err {
			if err == nil {
				t.Errorf("Sanitize(%q): expected error, got %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("Sanitize(%q): unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("Sanitize(%q): got %q, want %q", c.in, got, c.want)
		}
	}
}
