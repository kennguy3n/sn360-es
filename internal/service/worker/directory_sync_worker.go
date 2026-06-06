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
	// Binder pins a Postgres conn to cross-tenant scope so the
	// fan-out queries below — each gated by an explicit
	// `WHERE tenant_id = $1` predicate — are not silently
	// zero-filtered by the RLS policy installed in
	// `migrations/0018_row_level_security.up.sql`. Nil is a valid
	// no-op for in-memory tests.
	Binder TenantBinder

	// Source selects where the user roster comes from. Empty is
	// treated as SourceNative (the existing per-provider directory
	// client). When SourceIAMCore, fetchUsers pulls the authoritative
	// user list from the iam-core Management API via IAMCore. Groups,
	// memberships and group-based classification context still come
	// from the native provider (Directory) — iam-core exposes neither
	// native group IDs nor an admin flag — and are matched back to the
	// iam-core users by email. Sensitivity classification and the
	// org-graph snapshot are produced locally in both modes. A native
	// Directory is therefore required even when Source is SourceIAMCore.
	Source DirectorySource
	// IAMCore is the iam-core Management API user source. Required
	// when Source is SourceIAMCore; ignored otherwise.
	IAMCore agent.IAMCoreUserSource
}

// DirectorySource selects the directory-sync user roster source. It
// mirrors config.DirectorySyncSource but is redeclared here so the
// worker package does not depend on the config package.
type DirectorySource string

const (
	// SourceNative pulls users from the per-provider directory client
	// (GWS / MS Graph) with delta sync when supported. Default.
	SourceNative DirectorySource = "native"
	// SourceIAMCore pulls users from iam-core's Management API.
	SourceIAMCore DirectorySource = "iam-core"
)

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
	// Fail loud on an iam-core source with no Management API client
	// wired — silently falling back to the native provider would make
	// an operator believe iam-core is the source of truth when it is
	// not.
	if cfg.Source == SourceIAMCore && cfg.IAMCore == nil {
		return nil, fmt.Errorf("worker: directory sync source %q requires an IAMCore user source", cfg.Source)
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
//
// Uses keyset-paginated iteration so peak memory is O(batchSize) ×
// tenant-row-size, not O(tenant_count). Per-tenant syncTenant calls
// happen inside the batch callback so a slow tenant cannot stall the
// query connection (the batch query returns before any syncTenant
// starts).
func (j *DirectorySyncJob) Run(ctx context.Context) error {
	var lastErr error

	// tenant-lint:cross-tenant — directory-sync worker walks every
	// tenant; per-tenant filtering is enforced in the SQL predicate.
	if j.cfg.Binder != nil {
		boundCtx, release, berr := j.cfg.Binder.WithCrossTenant(ctx)
		if berr != nil {
			return fmt.Errorf("directory sync: cross-tenant scope: %w", berr)
		}
		defer func() { _ = release() }()
		ctx = boundCtx
	}

	iterErr := j.cfg.Tenants.IterateActive(ctx, 0, func(batch []repository.Tenant) error {
		for _, t := range batch {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := j.syncTenant(ctx, t.ID); err != nil {
				j.cfg.Logger.Error("directory sync: tenant failed",
					slog.String("tenant_id", t.ID),
					slog.String("err", err.Error()))
				lastErr = err
				continue
			}
		}
		return nil
	})
	if iterErr != nil {
		return fmt.Errorf("directory sync: iterate tenants: %w", iterErr)
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

	// Group memberships and group-based classification context always
	// come from the native provider — iam-core's Management API exposes
	// neither sn360's native group IDs nor an admin flag. In native mode
	// this is exactly the roster we already fetched. In iam-core mode the
	// user *list* is authoritative from iam-core, but we still pull the
	// native roster here and match it to the iam-core users by email so
	// memberships and classification keep their group/admin context.
	// Without this, iam-core users carry empty GroupIDs and the
	// membership loop below would call ReplaceForGroup with an empty set,
	// silently wiping every group's memberships on each sync.
	membershipRoster := users
	if j.cfg.Source == SourceIAMCore {
		nativeUsers, nerr := j.cfg.Directory.ListUsers(ctx, tenantID)
		if nerr != nil {
			return fmt.Errorf("list native users for group context: %w", nerr)
		}
		membershipRoster = nativeUsers
	}
	groupCtxByEmail := make(map[string]agent.DiscoveredUser, len(membershipRoster))
	for _, mu := range membershipRoster {
		groupCtxByEmail[strings.ToLower(mu.Email)] = mu
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
			// Group/admin context is sourced from the native provider
			// (see membershipRoster above), matched to this user by
			// email. In native mode gctx is the same record as u.
			gctx := groupCtxByEmail[strings.ToLower(u.Email)]
			groupNames := make([]string, 0)
			for _, g := range groups {
				for _, gid := range gctx.GroupIDs {
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
				IsAdmin:     gctx.IsAdmin,
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
			// Memberships are derived from the native provider's roster
			// (membershipRoster), which carries GroupIDs; the DB UUID is
			// resolved by email hash against the persisted user list.
			for _, mu := range membershipRoster {
				for _, gid := range mu.GroupIDs {
					if gid == g.ID {
						if h, hErr := j.cfg.Hasher(tenantID, mu.Email); hErr == nil {
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
	// iam-core source: the authoritative user list comes from the
	// Management API. The caller (syncTenant) still classifies
	// sensitivity, builds the org-graph snapshot, and sources
	// groups/memberships from the native provider — only the user list
	// source changes here.
	if j.cfg.Source == SourceIAMCore {
		return j.cfg.IAMCore.ListUsers(ctx, tenantID)
	}

	dc, ok := j.cfg.Directory.(agent.DeltaSyncCapable)
	if !ok || j.cfg.SyncCheckpoints == nil {
		return j.cfg.Directory.ListUsers(ctx, tenantID)
	}

	// Determine provider name for checkpoint key.
	var provider string
	if kinder, ok := j.cfg.Directory.(interface{ Kind() string }); ok {
		provider = kinder.Kind()
	} else {
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
