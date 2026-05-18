package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/agent"
)

// DirectorySyncJobConfig holds all dependencies for the directory
// sync worker.
type DirectorySyncJobConfig struct {
	Interval    time.Duration
	Tenants     TenantLister
	Directory   agent.DirectoryClient
	Users       repository.UserRepository
	Groups      repository.GroupRepository
	Memberships repository.GroupMembershipRepository
	Classifier  agent.SensitivityClassifier
	Events      agent.EventPublisher
	Hasher      func(tenantID, input string) ([]byte, error)
	Logger      *slog.Logger
}

// DirectorySyncJob implements the Job interface for periodic
// directory synchronization. It discovers new/changed users,
// reclassifies sensitivity, and emits events.
type DirectorySyncJob struct {
	cfg      DirectorySyncJobConfig
	interval time.Duration
}

// NewDirectorySyncJob constructs the directory sync job.
func NewDirectorySyncJob(cfg DirectorySyncJobConfig) (*DirectorySyncJob, error) {
	if cfg.Tenants == nil {
		return nil, fmt.Errorf("worker: directory sync requires TenantLister")
	}
	if cfg.Directory == nil {
		return nil, fmt.Errorf("worker: directory sync requires DirectoryClient")
	}
	if cfg.Users == nil {
		return nil, fmt.Errorf("worker: directory sync requires UserRepository")
	}
	if cfg.Groups == nil {
		return nil, fmt.Errorf("worker: directory sync requires GroupRepository")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 6 * time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &DirectorySyncJob{cfg: cfg, interval: cfg.Interval}, nil
}

// Name implements Job.
func (j *DirectorySyncJob) Name() string { return "directory-sync" }

// Interval implements Job.
func (j *DirectorySyncJob) Interval() time.Duration { return j.interval }

// Run implements Job. Iterates active tenants, fetches current
// directory state, diffs against persisted data, and upserts changes.
func (j *DirectorySyncJob) Run(ctx context.Context) error {
	tenants, err := j.cfg.Tenants.List(ctx, 0)
	if err != nil {
		return fmt.Errorf("directory sync: list tenants: %w", err)
	}
	var lastErr error
	for _, t := range tenants {
		if err := j.syncTenant(ctx, t.ID); err != nil {
			j.cfg.Logger.Error("directory sync: tenant failed",
				slog.String("tenant_id", t.ID),
				slog.String("err", err.Error()))
			lastErr = err
			continue
		}
	}
	return lastErr
}

func (j *DirectorySyncJob) syncTenant(ctx context.Context, tenantID string) error {
	users, err := j.cfg.Directory.ListUsers(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}
	groups, err := j.cfg.Directory.ListGroups(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("list groups: %w", err)
	}

	// Fetch existing users for diff. Key by hex-encoded email hash
	// because that is the stable UPSERT conflict key (not the generated ID).
	existingUsers, err := j.cfg.Users.List(ctx, tenantID, 0)
	if err != nil {
		return fmt.Errorf("list existing users: %w", err)
	}
	existingByHash := make(map[string]repository.User, len(existingUsers))
	for _, u := range existingUsers {
		existingByHash[fmt.Sprintf("%x", u.EmailHash)] = u
	}

	// Classify sensitivity for all discovered users if classifier available.
	var classResults []agent.ClassifyResult
	if j.cfg.Classifier != nil && len(users) > 0 {
		inputs := make([]agent.UserClassifyInput, len(users))
		for i, u := range users {
			groupNames := make([]string, 0)
			for _, g := range groups {
				for _, gid := range u.GroupIDs {
					if gid == g.ID {
						groupNames = append(groupNames, g.Name)
					}
				}
			}
			inputs[i] = agent.UserClassifyInput{
				JobTitle:    u.JobTitle,
				Department:  u.Department,
				DisplayName: u.DisplayName,
				GroupNames:  groupNames,
				IsAdmin:     u.IsAdmin,
			}
		}
		classResults, err = j.cfg.Classifier.ClassifyBatch(ctx, inputs)
		if err != nil {
			j.cfg.Logger.Warn("directory sync: classification failed, using defaults",
				slog.String("tenant_id", tenantID),
				slog.String("err", err.Error()))
		}
	}

	// Upsert users.
	for i, u := range users {
		sens := agent.SensitivityDefault
		confidence := 1.0
		needsReview := false
		if i < len(classResults) {
			sens = classResults[i].Sensitivity
			confidence = classResults[i].Confidence
			needsReview = classResults[i].NeedsReview
		}

		var emailHash []byte
		if j.cfg.Hasher != nil {
			emailHash, err = j.cfg.Hasher(tenantID, u.Email)
			if err != nil {
				j.cfg.Logger.Warn("directory sync: hash failed",
					slog.String("user_id", u.ID),
					slog.String("err", err.Error()))
				continue
			}
		}

		repoUser := &repository.User{
			TenantID:        tenantID,
			EmailHash:       emailHash,
			Role:            u.JobTitle,
			Department:      u.Department,
			SensitivityTier: sens.String(),
			Locale:          "",
		}
		_ = confidence
		_ = needsReview

		if err := j.cfg.Users.Upsert(ctx, repoUser); err != nil {
			j.cfg.Logger.Warn("directory sync: user upsert failed",
				slog.String("tenant_id", tenantID),
				slog.String("err", err.Error()))
		}

		// Emit event for new users (compare by email hash — the stable conflict key).
		hashHex := fmt.Sprintf("%x", emailHash)
		if _, exists := existingByHash[hashHex]; !exists && j.cfg.Events != nil {
			evt := map[string]any{
				"tenant_id":   tenantID,
				"user_id":     repoUser.ID,
				"department":  u.Department,
				"sensitivity": sens.String(),
				"occurred_at": time.Now().UTC(),
			}
			data, _ := json.Marshal(evt)
			_ = j.cfg.Events.Publish(ctx, "es.onboarding.user.created", data)
		}
	}

	// Upsert groups.
	for _, g := range groups {
		repoGroup := &repository.Group{
			ID:          g.ID,
			TenantID:    tenantID,
			Name:        g.Name,
			Description: g.Description,
		}
		if err := j.cfg.Groups.Upsert(ctx, repoGroup); err != nil {
			j.cfg.Logger.Warn("directory sync: group upsert failed",
				slog.String("tenant_id", tenantID),
				slog.String("name", g.Name),
				slog.String("err", err.Error()))
		}

		// Update memberships.
		if j.cfg.Memberships != nil {
			memberIDs := make([]string, 0)
			for _, u := range users {
				for _, gid := range u.GroupIDs {
					if gid == g.ID {
						memberIDs = append(memberIDs, u.ID)
						break
					}
				}
			}
			if err := j.cfg.Memberships.ReplaceForGroup(ctx, g.ID, memberIDs); err != nil {
				j.cfg.Logger.Warn("directory sync: membership update failed",
					slog.String("group_id", g.ID),
					slog.String("err", err.Error()))
			}
		}
	}

	j.cfg.Logger.Info("directory sync: completed",
		slog.String("tenant_id", tenantID),
		slog.Int("users", len(users)),
		slog.Int("groups", len(groups)))
	return nil
}
