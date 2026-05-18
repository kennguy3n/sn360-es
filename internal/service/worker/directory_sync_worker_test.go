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
}

func (f *fakeDirSyncTenantLister) List(_ context.Context, _ int) ([]repository.Tenant, error) {
	return f.tenants, nil
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

type fakeUserRepo struct {
	users   map[string][]repository.User
	upserts int
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{users: make(map[string][]repository.User)}
}

func (f *fakeUserRepo) Upsert(_ context.Context, u *repository.User) error {
	f.upserts++
	f.users[u.TenantID] = append(f.users[u.TenantID], *u)
	return nil
}

func (f *fakeUserRepo) GetByHash(_ context.Context, _ string, _ []byte) (*repository.User, error) {
	return nil, fmt.Errorf("not found")
}

func (f *fakeUserRepo) List(_ context.Context, tenantID string, _ int) ([]repository.User, error) {
	return f.users[tenantID], nil
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
	f.groups[g.TenantID] = append(f.groups[g.TenantID], *g)
	return nil
}

func (f *fakeGroupRepo) GetByName(_ context.Context, _, _ string) (*repository.Group, error) {
	return nil, fmt.Errorf("not found")
}

func (f *fakeGroupRepo) List(_ context.Context, _ string) ([]repository.Group, error) {
	return nil, nil
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
