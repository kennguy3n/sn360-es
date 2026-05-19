package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/repository"
	"github.com/kennguy3n/sn360-es/internal/service/agent"
)

// DirectorySyncJobConfig holds all dependencies for the directory
// sync worker.
type DirectorySyncJobConfig struct {
	Interval        time.Duration
	Tenants         TenantLister
	Directory       agent.DirectoryClient
	Users           repository.UserRepository
	Groups          repository.GroupRepository
	Memberships     repository.GroupMembershipRepository
	Classifier      agent.SensitivityClassifier
	Events          agent.EventPublisher
	Hasher          func(tenantID, input string) ([]byte, error)
	Logger          *slog.Logger
	SyncCheckpoints repository.SyncCheckpointRepository
	OrgGraphs       repository.OrgGraphRepository
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
	if cfg.Hasher == nil {
		return nil, fmt.Errorf("worker: directory sync requires Hasher")
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
	users, err := j.fetchUsers(ctx, tenantID)
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
			SensitivityTier: sens.DBTier(),
			Locale:          "",
		}
		_ = needsReview

		if err := j.cfg.Users.Upsert(ctx, repoUser); err != nil {
			j.cfg.Logger.Warn("directory sync: user upsert failed",
				slog.String("tenant_id", tenantID),
				slog.String("err", err.Error()))
			continue
		}

		// Emit event for new users (compare by email hash — the stable conflict key).
		hashHex := fmt.Sprintf("%x", emailHash)
		if _, exists := existingByHash[hashHex]; !exists && j.cfg.Events != nil {
			evt := map[string]any{
				"tenant_id":   tenantID,
				"user_id":     repoUser.ID,
				"email_hash":  hashHex,
				"department":  u.Department,
				"sensitivity": sens.String(),
				"confidence":  confidence,
				"occurred_at": time.Now().UTC(),
			}
			data, _ := json.Marshal(evt)
			_ = j.cfg.Events.Publish(ctx, "es.onboarding.user.created", data)
		}
	}

	// Re-fetch users from DB to resolve actual UUIDs for membership FK.
	resolvedUsers, err := j.cfg.Users.List(ctx, tenantID, 0)
	if err != nil {
		j.cfg.Logger.Warn("directory sync: failed to re-fetch users for membership resolution",
			slog.String("tenant_id", tenantID),
			slog.String("err", err.Error()))
		resolvedUsers = nil
	}
	resolvedByHash := make(map[string]string, len(resolvedUsers)) // emailHash hex → DB UUID
	for _, ru := range resolvedUsers {
		resolvedByHash[fmt.Sprintf("%x", ru.EmailHash)] = ru.ID
	}

	// Upsert groups. Do NOT pass provider-assigned IDs (e.g. GWS
	// alphanumeric IDs) because the DB column is UUID. Let pgGroups.Upsert
	// generate a proper UUID; ON CONFLICT (tenant_id, name) handles dedup.
	for _, g := range groups {
		repoGroup := &repository.Group{
			TenantID:    tenantID,
			Name:        g.Name,
			Description: g.Description,
			RiskClass:   classifyGroupRisk(g.Name),
		}
		if err := j.cfg.Groups.Upsert(ctx, repoGroup); err != nil {
			j.cfg.Logger.Warn("directory sync: group upsert failed",
				slog.String("tenant_id", tenantID),
				slog.String("name", g.Name),
				slog.String("err", err.Error()))
			continue
		}

		// Resolve actual DB group ID (ON CONFLICT keeps original ID for existing groups).
		dbGroupID := repoGroup.ID
		if resolved, resolveErr := j.cfg.Groups.GetByName(ctx, tenantID, g.Name); resolveErr == nil {
			dbGroupID = resolved.ID
		}

		// Update memberships using resolved DB user UUIDs (not provider IDs).
		if j.cfg.Memberships != nil && len(resolvedByHash) > 0 {
			memberIDs := make([]string, 0)
			for _, u := range users {
				for _, gid := range u.GroupIDs {
					if gid == g.ID {
						if h, hErr := j.cfg.Hasher(tenantID, u.Email); hErr == nil {
							if dbUID, ok := resolvedByHash[fmt.Sprintf("%x", h)]; ok {
								memberIDs = append(memberIDs, dbUID)
							}
						}
						break
					}
				}
			}
			if err := j.cfg.Memberships.ReplaceForGroup(ctx, dbGroupID, memberIDs); err != nil {
				j.cfg.Logger.Warn("directory sync: membership update failed",
					slog.String("group_id", dbGroupID),
					slog.String("err", err.Error()))
			}
		}
	}

	// Persist org graph snapshot when the repository is wired.
	if j.cfg.OrgGraphs != nil {
		highRisk := make([]string, 0)
		deptSet := make(map[string]struct{})
		for i, u := range users {
			if u.Department != "" {
				deptSet[u.Department] = struct{}{}
			}
			if i < len(classResults) && classResults[i].Sensitivity >= agent.SensitivityHigh {
				if h, hErr := j.cfg.Hasher(tenantID, u.Email); hErr == nil {
					highRisk = append(highRisk, fmt.Sprintf("%x", h))
				}
			}
		}
		graphData, _ := json.Marshal(map[string]any{
			"employees":   len(users),
			"groups":      len(groups),
			"departments": len(deptSet),
			"high_risk":   len(highRisk),
		})
		snap := &repository.OrgGraphSnapshot{
			TenantID:        tenantID,
			BuiltAt:         time.Now().UTC(),
			GraphJSON:       graphData,
			HighRiskIDs:     highRisk,
			DepartmentCount: len(deptSet),
			EmployeeCount:   len(users),
			GroupCount:      len(groups),
		}
		if gErr := j.cfg.OrgGraphs.Upsert(ctx, snap); gErr != nil {
			j.cfg.Logger.Warn("directory sync: org graph upsert failed",
				slog.String("tenant_id", tenantID),
				slog.String("err", gErr.Error()))
		}
	}

	j.cfg.Logger.Info("directory sync: completed",
		slog.String("tenant_id", tenantID),
		slog.Int("users", len(users)),
		slog.Int("groups", len(groups)))
	return nil
}

// fetchUsers attempts incremental delta sync when the directory client
// supports it and a checkpoint repository is configured; otherwise
// falls back to a full ListUsers call.
func (j *DirectorySyncJob) fetchUsers(ctx context.Context, tenantID string) ([]agent.DiscoveredUser, error) {
	dc, ok := j.cfg.Directory.(agent.DeltaSyncCapable)
	if !ok || j.cfg.SyncCheckpoints == nil {
		return j.cfg.Directory.ListUsers(ctx, tenantID)
	}

	// Determine provider name for checkpoint key.
	provider := "unknown"
	switch j.cfg.Directory.(type) {
	case interface{ Kind() string }:
		provider = j.cfg.Directory.(interface{ Kind() string }).Kind()
	default:
		// Heuristic: package path would distinguish, but using a
		// simple type name suffix for now.
		provider = fmt.Sprintf("%T", j.cfg.Directory)
	}

	var deltaToken string
	cp, err := j.cfg.SyncCheckpoints.Get(ctx, tenantID, provider)
	if err == nil {
		deltaToken = cp.DeltaToken
	}

	users, newToken, err := dc.ListUsersDelta(ctx, tenantID, deltaToken)
	if err != nil {
		// Delta failed — fall back to full sync.
		j.cfg.Logger.Warn("directory sync: delta sync failed, falling back to full",
			slog.String("tenant_id", tenantID),
			slog.String("err", err.Error()))
		return j.cfg.Directory.ListUsers(ctx, tenantID)
	}

	// Persist the new delta token.
	if newToken != "" {
		_ = j.cfg.SyncCheckpoints.Upsert(ctx, &repository.SyncCheckpoint{
			TenantID:   tenantID,
			Provider:   provider,
			DeltaToken: newToken,
		})
	}

	return users, nil
}

// classifyGroupRisk maps a group name to a risk_class value stored in
// the groups table. Uses case-insensitive substring matching against
// known industry-vertical keywords.
func classifyGroupRisk(name string) string {
	n := strings.ToLower(name)
	type rule struct {
		keywords []string
		class    string
	}
	rules := []rule{
		{[]string{"engineering", "devops", "sre", "infrastructure", "platform"}, "engineering"},
		{[]string{"medical", "clinical", "pharmacy", "nursing"}, "medical"},
		{[]string{"research", "r&d", "patent"}, "research"},
		{[]string{"m&a", "corporate development", "strategy", "board of"}, "strategy"},
		{[]string{"finance", "treasury", "accounts payable"}, "finance"},
		{[]string{"exec", "c-suite", "leadership"}, "executive"},
		{[]string{"hr ", "human resource", "people ops"}, "hr"},
		{[]string{"legal", "compliance"}, "legal"},
		{[]string{"it admin", "sysadmin", "security"}, "it"},
	}
	for _, r := range rules {
		for _, kw := range r.keywords {
			if strings.Contains(n, kw) {
				return r.class
			}
		}
	}
	return "standard"
}
