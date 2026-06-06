package worker

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/agent"
)

type fakeDirSyncTenantLister struct {
	tenants []repository.Tenant
	err     error
}

func (f *fakeDirSyncTenantLister) List(_ context.Context, _ int) ([]repository.Tenant, error) {
	return f.tenants, f.err
}

// IterateActive satisfies the keyset-pagination contract on
// TenantLister. The fake yields all configured tenants in a single
// batch — tests that want to exercise multi-batch boundary behaviour
// should construct a custom lister that yields in chunks.
func (f *fakeDirSyncTenantLister) IterateActive(_ context.Context, _ int, yield func([]repository.Tenant) error) error {
	if f.err != nil {
		return f.err
	}
	if len(f.tenants) == 0 {
		return nil
	}
	return yield(f.tenants)
}

type fakeDirSyncDirectoryClient struct {
	users  []agent.DiscoveredUser
	groups []agent.DiscoveredGroup
}

func (f *fakeDirSyncDirectoryClient) ListUsers(_ context.Context, _ string) ([]agent.DiscoveredUser, error) {
	return f.users, nil
}

func (f *fakeDirSyncDirectoryClient) ListGroups(_ context.Context, _ string) ([]agent.DiscoveredGroup, error) {
	return f.groups, nil
}

// fakeDirSyncDirectoryClientTracked records whether ListUsers was
// called, so a test can prove the iam-core source bypasses the native
// provider's user roster entirely.
type fakeDirSyncDirectoryClientTracked struct {
	fakeDirSyncDirectoryClient
	listUsersCalled bool
}

func (f *fakeDirSyncDirectoryClientTracked) ListUsers(ctx context.Context, tenantID string) ([]agent.DiscoveredUser, error) {
	f.listUsersCalled = true
	return f.fakeDirSyncDirectoryClient.ListUsers(ctx, tenantID)
}

// fakeIAMCoreUserSource is a stub agent.IAMCoreUserSource that records
// the tenant IDs it was asked about and returns a fixed roster.
type fakeIAMCoreUserSource struct {
	users     []agent.DiscoveredUser
	err       error
	calledFor []string
}

func (f *fakeIAMCoreUserSource) ListUsers(_ context.Context, tenantID string) ([]agent.DiscoveredUser, error) {
	f.calledFor = append(f.calledFor, tenantID)
	if f.err != nil {
		return nil, f.err
	}
	return f.users, nil
}

type fakeUserRepo struct {
	users   map[string][]repository.User
	upserts int
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{users: make(map[string][]repository.User)}
}

func (f *fakeUserRepo) Upsert(_ context.Context, u *repository.User) error {
	f.upserts++
	// Assign a deterministic ID the way the real Postgres repo does, so
	// membership resolution (which re-reads users and keys by email hash
	// to the generated UUID) has a non-empty ID to work with in tests.
	if u.ID == "" {
		u.ID = fmt.Sprintf("uid:%x", u.EmailHash)
	}
	f.users[u.TenantID] = append(f.users[u.TenantID], *u)
	return nil
}

func (f *fakeUserRepo) GetByHash(_ context.Context, _ string, _ []byte) (*repository.User, error) {
	return nil, fmt.Errorf("not found")
}

func (f *fakeUserRepo) List(_ context.Context, tenantID string, _ int) ([]repository.User, error) {
	return f.users[tenantID], nil
}

func (f *fakeUserRepo) Count(_ context.Context, _ string) (int, error) {
	total := 0
	for _, uu := range f.users {
		total += len(uu)
	}
	return total, nil
}

type fakeGroupRepo struct {
	groups  map[string][]repository.Group
	upserts int
}

func newFakeGroupRepo() *fakeGroupRepo {
	return &fakeGroupRepo{groups: make(map[string][]repository.Group)}
}

func (f *fakeGroupRepo) Create(_ context.Context, g *repository.Group) error {
	f.groups[g.TenantID] = append(f.groups[g.TenantID], *g)
	return nil
}

func (f *fakeGroupRepo) Upsert(_ context.Context, g *repository.Group) error {
	f.upserts++
	if g.ID == "" {
		g.ID = "gid:" + g.Name
	}
	f.groups[g.TenantID] = append(f.groups[g.TenantID], *g)
	return nil
}

func (f *fakeGroupRepo) GetByName(_ context.Context, tenantID, name string) (*repository.Group, error) {
	for i := range f.groups[tenantID] {
		if f.groups[tenantID][i].Name == name {
			g := f.groups[tenantID][i]
			return &g, nil
		}
	}
	return nil, fmt.Errorf("not found")
}

func (f *fakeGroupRepo) List(_ context.Context, _ string) ([]repository.Group, error) {
	return nil, nil
}

func (f *fakeGroupRepo) Count(_ context.Context, _ string) (int, error) {
	total := 0
	for _, gg := range f.groups {
		total += len(gg)
	}
	return total, nil
}

// fakeMembershipRepo records the userIDs passed to ReplaceForGroup so a
// test can prove memberships are written (not silently wiped with an
// empty set) under the iam-core source.
type fakeMembershipRepo struct {
	replaced map[string][]string // groupID -> userIDs
}

func newFakeMembershipRepo() *fakeMembershipRepo {
	return &fakeMembershipRepo{replaced: make(map[string][]string)}
}

func (f *fakeMembershipRepo) Upsert(_ context.Context, _ *repository.GroupMembership) error {
	return nil
}

func (f *fakeMembershipRepo) ListByGroup(_ context.Context, _ string) ([]repository.GroupMembership, error) {
	return nil, nil
}

func (f *fakeMembershipRepo) ListByUser(_ context.Context, _ string) ([]repository.GroupMembership, error) {
	return nil, nil
}

func (f *fakeMembershipRepo) DeleteByGroup(_ context.Context, _ string) error { return nil }

func (f *fakeMembershipRepo) ReplaceForGroup(_ context.Context, groupID string, userIDs []string) error {
	f.replaced[groupID] = append([]string(nil), userIDs...)
	return nil
}

// capturingClassifier records the inputs it was asked to classify so a
// test can assert that group/admin context (sourced from the native
// provider) reaches the classifier even when the user list comes from
// iam-core.
type capturingClassifier struct {
	inputs []agent.UserClassifyInput
}

func (c *capturingClassifier) ClassifyBatch(_ context.Context, users []agent.UserClassifyInput) ([]agent.ClassifyResult, error) {
	c.inputs = append([]agent.UserClassifyInput(nil), users...)
	return make([]agent.ClassifyResult, len(users)), nil
}

type fakeEventPublisher struct {
	published int
}

func (f *fakeEventPublisher) Publish(_ context.Context, _ string, _ []byte) error {
	f.published++
	return nil
}

func TestNewDirectorySyncJob_Validation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     DirectorySyncJobConfig
		wantErr bool
	}{
		{
			name:    "nil tenants",
			cfg:     DirectorySyncJobConfig{},
			wantErr: true,
		},
		{
			name: "nil directory",
			cfg: DirectorySyncJobConfig{
				Tenants: &fakeDirSyncTenantLister{},
			},
			wantErr: true,
		},
		{
			name: "nil users",
			cfg: DirectorySyncJobConfig{
				Tenants:   &fakeDirSyncTenantLister{},
				Directory: &fakeDirSyncDirectoryClient{},
			},
			wantErr: true,
		},
		{
			name: "nil groups",
			cfg: DirectorySyncJobConfig{
				Tenants:   &fakeDirSyncTenantLister{},
				Directory: &fakeDirSyncDirectoryClient{},
				Users:     newFakeUserRepo(),
			},
			wantErr: true,
		},
		{
			name: "nil hasher",
			cfg: DirectorySyncJobConfig{
				Tenants:   &fakeDirSyncTenantLister{},
				Directory: &fakeDirSyncDirectoryClient{},
				Users:     newFakeUserRepo(),
				Groups:    newFakeGroupRepo(),
			},
			wantErr: true,
		},
		{
			name: "valid",
			cfg: DirectorySyncJobConfig{
				Tenants:   &fakeDirSyncTenantLister{},
				Directory: &fakeDirSyncDirectoryClient{},
				Users:     newFakeUserRepo(),
				Groups:    newFakeGroupRepo(),
				Hasher:    func(_, input string) ([]byte, error) { return []byte(input), nil },
			},
			wantErr: false,
		},
		{
			// iam-core source with no Management API client must fail
			// loud rather than silently fall back to the native provider.
			name: "iam-core source without IAMCore client",
			cfg: DirectorySyncJobConfig{
				Tenants:   &fakeDirSyncTenantLister{},
				Directory: &fakeDirSyncDirectoryClient{},
				Users:     newFakeUserRepo(),
				Groups:    newFakeGroupRepo(),
				Hasher:    func(_, input string) ([]byte, error) { return []byte(input), nil },
				Source:    SourceIAMCore,
			},
			wantErr: true,
		},
		{
			name: "iam-core source with IAMCore client",
			cfg: DirectorySyncJobConfig{
				Tenants:   &fakeDirSyncTenantLister{},
				Directory: &fakeDirSyncDirectoryClient{},
				Users:     newFakeUserRepo(),
				Groups:    newFakeGroupRepo(),
				Hasher:    func(_, input string) ([]byte, error) { return []byte(input), nil },
				Source:    SourceIAMCore,
				IAMCore:   &fakeIAMCoreUserSource{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewDirectorySyncJob(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestDirectorySyncJob_NameAndInterval(t *testing.T) {
	job, err := NewDirectorySyncJob(DirectorySyncJobConfig{
		Interval:  8 * time.Hour,
		Tenants:   &fakeDirSyncTenantLister{},
		Directory: &fakeDirSyncDirectoryClient{},
		Users:     newFakeUserRepo(),
		Groups:    newFakeGroupRepo(),
		Hasher:    func(_, input string) ([]byte, error) { return []byte(input), nil },
	})
	if err != nil {
		t.Fatalf("NewDirectorySyncJob: %v", err)
	}
	if job.Name() != "directory-sync" {
		t.Errorf("Name() = %q, want %q", job.Name(), "directory-sync")
	}
	if job.Interval() != 8*time.Hour {
		t.Errorf("Interval() = %v, want 8h", job.Interval())
	}
}

func TestDirectorySyncJob_Run_UpsertsUsers(t *testing.T) {
	userRepo := newFakeUserRepo()
	groupRepo := newFakeGroupRepo()
	events := &fakeEventPublisher{}

	job, err := NewDirectorySyncJob(DirectorySyncJobConfig{
		Interval: time.Hour,
		Tenants: &fakeDirSyncTenantLister{
			tenants: []repository.Tenant{{ID: "t1", Name: "Test Tenant"}},
		},
		Directory: &fakeDirSyncDirectoryClient{
			users: []agent.DiscoveredUser{
				{ID: "u1", Email: "user1@test.com", DisplayName: "User 1", Department: "Engineering"},
				{ID: "u2", Email: "user2@test.com", DisplayName: "User 2", Department: "Finance"},
			},
			groups: []agent.DiscoveredGroup{
				{ID: "g1", Name: "Engineering"},
			},
		},
		Users:  userRepo,
		Groups: groupRepo,
		Events: events,
		Hasher: func(tenantID, input string) ([]byte, error) {
			return []byte("hash:" + input), nil
		},
		Logger: slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewDirectorySyncJob: %v", err)
	}

	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if userRepo.upserts != 2 {
		t.Errorf("user upserts = %d, want 2", userRepo.upserts)
	}
	if groupRepo.upserts != 1 {
		t.Errorf("group upserts = %d, want 1", groupRepo.upserts)
	}
	if events.published != 2 {
		t.Errorf("events published = %d, want 2", events.published)
	}
}

func TestDirectorySyncJob_Run_NoTenants(t *testing.T) {
	job, err := NewDirectorySyncJob(DirectorySyncJobConfig{
		Interval:  time.Hour,
		Tenants:   &fakeDirSyncTenantLister{tenants: nil},
		Directory: &fakeDirSyncDirectoryClient{},
		Users:     newFakeUserRepo(),
		Groups:    newFakeGroupRepo(),
		Hasher:    func(_, input string) ([]byte, error) { return []byte(input), nil },
		Logger:    slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewDirectorySyncJob: %v", err)
	}

	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("Run with no tenants should not error: %v", err)
	}
}

// TestDirectorySyncJob_Run_IAMCoreSource proves the iam-core source
// contract: the authoritative user *list* comes from the Management API
// (IAMCore), while groups, memberships and group/admin classification
// context still come from the native provider, matched back to the
// iam-core users by email. Critically, it asserts memberships are
// written from the native roster and NOT wiped — the regression guard
// for the silent ReplaceForGroup-with-empty-set bug.
func TestDirectorySyncJob_Run_IAMCoreSource(t *testing.T) {
	userRepo := newFakeUserRepo()
	groupRepo := newFakeGroupRepo()
	memberRepo := newFakeMembershipRepo()
	classifier := &capturingClassifier{}

	native := &fakeDirSyncDirectoryClientTracked{
		fakeDirSyncDirectoryClient: fakeDirSyncDirectoryClient{
			// Native roster supplies group membership + admin context.
			// alice (matched to the iam-core list by email) is in g1 and
			// is an admin; the iam-core list carries neither fact.
			users: []agent.DiscoveredUser{
				{ID: "native-1", Email: "alice@test.com", DisplayName: "Native Alice", GroupIDs: []string{"g1"}, IsAdmin: true},
			},
			groups: []agent.DiscoveredGroup{{ID: "g1", Name: "Engineering"}},
		},
	}
	iamCore := &fakeIAMCoreUserSource{
		users: []agent.DiscoveredUser{
			{ID: "iam-1", Email: "alice@test.com", DisplayName: "Alice", Department: "Engineering"},
			{ID: "iam-2", Email: "bob@test.com", DisplayName: "Bob", Department: "Finance"},
		},
	}

	job, err := NewDirectorySyncJob(DirectorySyncJobConfig{
		Interval:    time.Hour,
		Tenants:     &fakeDirSyncTenantLister{tenants: []repository.Tenant{{ID: "t1", Name: "T1"}}},
		Directory:   native,
		Users:       userRepo,
		Groups:      groupRepo,
		Memberships: memberRepo,
		Classifier:  classifier,
		Hasher:      func(_, input string) ([]byte, error) { return []byte("hash:" + input), nil },
		Logger:      slog.Default(),
		Source:      SourceIAMCore,
		IAMCore:     iamCore,
	})
	if err != nil {
		t.Fatalf("NewDirectorySyncJob: %v", err)
	}

	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The authoritative user list comes from iam-core...
	if len(iamCore.calledFor) != 1 || iamCore.calledFor[0] != "t1" {
		t.Errorf("iam-core ListUsers calledFor = %v, want [t1]", iamCore.calledFor)
	}
	// ...but the native provider is still consulted for group/membership
	// context (it does NOT supply the persisted user list).
	if !native.listUsersCalled {
		t.Error("native Directory.ListUsers was not called; iam-core source still needs native group context")
	}
	if userRepo.upserts != 2 {
		t.Errorf("user upserts = %d, want 2 (from iam-core roster)", userRepo.upserts)
	}
	// Groups still sync from the native provider.
	if groupRepo.upserts != 1 {
		t.Errorf("group upserts = %d, want 1 (groups still from native provider)", groupRepo.upserts)
	}
	// Persisted users carry the iam-core roster's departments.
	gotDepts := map[string]bool{}
	for _, u := range userRepo.users["t1"] {
		gotDepts[u.Department] = true
	}
	if !gotDepts["Engineering"] || !gotDepts["Finance"] {
		t.Errorf("persisted departments = %v, want Engineering+Finance from iam-core roster", gotDepts)
	}

	// Regression guard: memberships must be written from the native
	// roster, NOT wiped. alice resolves to her persisted UUID and must
	// be a member of the Engineering group.
	wantUID := fmt.Sprintf("uid:%x", []byte("hash:alice@test.com"))
	members := memberRepo.replaced["gid:Engineering"]
	if len(members) != 1 || members[0] != wantUID {
		t.Errorf("Engineering members = %v, want [%s] (memberships must not be wiped under iam-core source)", members, wantUID)
	}

	// The group/admin context the classifier saw must come from the
	// native roster matched by email: alice is admin + in Engineering,
	// bob has no native context.
	byName := map[string]agent.UserClassifyInput{}
	for _, in := range classifier.inputs {
		byName[in.DisplayName] = in
	}
	alice := byName["Alice"]
	if !alice.IsAdmin {
		t.Error("classifier input for Alice: IsAdmin = false, want true (from native context)")
	}
	if len(alice.GroupNames) != 1 || alice.GroupNames[0] != "Engineering" {
		t.Errorf("classifier input for Alice: GroupNames = %v, want [Engineering]", alice.GroupNames)
	}
	if bob := byName["Bob"]; bob.IsAdmin || len(bob.GroupNames) != 0 {
		t.Errorf("classifier input for Bob: IsAdmin=%v GroupNames=%v, want false/[]", bob.IsAdmin, bob.GroupNames)
	}
}

// TestDirectorySyncJob_Run_NativeSourceDefault proves the default
// (native) source is unchanged: users come from the native provider
// even when an IAMCore client happens to be wired.
func TestDirectorySyncJob_Run_NativeSourceDefault(t *testing.T) {
	userRepo := newFakeUserRepo()
	groupRepo := newFakeGroupRepo()

	native := &fakeDirSyncDirectoryClientTracked{
		fakeDirSyncDirectoryClient: fakeDirSyncDirectoryClient{
			users:  []agent.DiscoveredUser{{ID: "u1", Email: "user1@test.com", DisplayName: "User 1"}},
			groups: []agent.DiscoveredGroup{{ID: "g1", Name: "Engineering"}},
		},
	}
	// Wired but must remain unused under the default source.
	iamCore := &fakeIAMCoreUserSource{
		users: []agent.DiscoveredUser{{ID: "iam-1", Email: "alice@test.com"}},
	}

	job, err := NewDirectorySyncJob(DirectorySyncJobConfig{
		Interval:  time.Hour,
		Tenants:   &fakeDirSyncTenantLister{tenants: []repository.Tenant{{ID: "t1", Name: "T1"}}},
		Directory: native,
		Users:     userRepo,
		Groups:    groupRepo,
		Hasher:    func(_, input string) ([]byte, error) { return []byte("hash:" + input), nil },
		Logger:    slog.Default(),
		// Source left zero-valued — defaults to native behaviour.
		IAMCore: iamCore,
	})
	if err != nil {
		t.Fatalf("NewDirectorySyncJob: %v", err)
	}

	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if !native.listUsersCalled {
		t.Error("native Directory.ListUsers was not called under default source")
	}
	if len(iamCore.calledFor) != 0 {
		t.Errorf("iam-core source was queried under native source: %v", iamCore.calledFor)
	}
	if userRepo.upserts != 1 {
		t.Errorf("user upserts = %d, want 1 (from native roster)", userRepo.upserts)
	}
}
