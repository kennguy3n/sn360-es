package onboarding

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kennguy3n/sn360-es/internal/service/agent"
)

// AgentBridge wraps the AI Onboarding agent so the onboarding Service
// can call it as PostConsentTrigger without taking a direct dependency
// on the agent package's concrete types.
type AgentBridge struct {
	Onboarding *agent.OnboardingAgent
	Locale     string
	Log        *slog.Logger
	// WG, when non-nil, is incremented before and decremented after
	// the background goroutine so the application can wait for
	// in-flight onboarding runs during shutdown.
	WG *sync.WaitGroup
}

// StartOnboarding implements PostConsentTrigger.
func (b *AgentBridge) StartOnboarding(ctx context.Context, tenantID string, provider ProviderType) error {
	if b == nil || b.Onboarding == nil {
		return errors.New("onboarding: agent not configured")
	}
	tctx := agent.TenantContext{
		TenantID:  tenantID,
		Provider:  agentProvider(provider),
		Locale:    b.Locale,
		StartedAt: time.Now().UTC(),
	}
	if b.WG != nil {
		b.WG.Add(1)
	}
	bgCtx := context.WithoutCancel(ctx)
	go func() {
		if b.WG != nil {
			defer b.WG.Done()
		}
		log := b.Log
		if log == nil {
			log = slog.Default()
		}
		if _, err := b.Onboarding.Onboard(bgCtx, tctx); err != nil {
			log.Error("onboarding.discovery: agent failed",
				slog.String("tenant_id", tenantID),
				slog.String("err", err.Error()))
		}
	}()
	return nil
}

func agentProvider(p ProviderType) agent.Provider {
	switch p {
	case ProviderGoogle:
		return agent.ProviderGoogle
	case ProviderMicrosoft:
		return agent.ProviderMicrosoft
	default:
		return agent.ProviderUnknown
	}
}

// GraphSource is the read-side of org-graph discovery; it abstracts
// over the GWS Directory and MS Graph clients so the same builder
// works for both.
type GraphSource interface {
	ListUsers(ctx context.Context, tenantID string) ([]agent.DiscoveredUser, error)
	ListGroups(ctx context.Context, tenantID string) ([]agent.DiscoveredGroup, error)
}

// OrgGraph captures the organisational hierarchy assembled from
// directory data.
type OrgGraph struct {
	TenantID    string
	BuiltAt     time.Time
	Employees   map[string]Employee
	Groups      map[string]Group
	Departments map[string][]string // department → user IDs
	HighRisk    []string            // user IDs flagged high-risk
}

// Employee is the projected node for a single user.
type Employee struct {
	ID          string
	Email       string
	DisplayName string
	Department  string
	JobTitle    string
	ManagerID   string
	Reports     []string
	Groups      []string
	IsHighRisk  bool
	Sensitivity agent.Sensitivity
}

// Group is the projected node for a directory group.
type Group struct {
	ID          string
	Name        string
	Description string
	MemberIDs   []string
	IsHighRisk  bool
}

// OrgGraphBuilder is the discovery orchestrator that calls the
// directory client and projects the response into an OrgGraph.
type OrgGraphBuilder struct {
	source GraphSource
	log    *slog.Logger
}

// NewOrgGraphBuilder constructs a builder.
func NewOrgGraphBuilder(source GraphSource, log *slog.Logger) (*OrgGraphBuilder, error) {
	if source == nil {
		return nil, errors.New("onboarding: graph source required")
	}
	if log == nil {
		log = slog.Default()
	}
	return &OrgGraphBuilder{source: source, log: log}, nil
}

// Build constructs the OrgGraph for tenantID by listing users + groups
// from the source and projecting them. The projection is pure-Go and
// safe to call concurrently.
func (b *OrgGraphBuilder) Build(ctx context.Context, tenantID string) (OrgGraph, error) {
	if tenantID == "" {
		return OrgGraph{}, errors.New("onboarding: tenantID required")
	}
	users, err := b.source.ListUsers(ctx, tenantID)
	if err != nil {
		return OrgGraph{}, fmt.Errorf("orggraph: list users: %w", err)
	}
	groups, err := b.source.ListGroups(ctx, tenantID)
	if err != nil {
		return OrgGraph{}, fmt.Errorf("orggraph: list groups: %w", err)
	}
	return Project(tenantID, users, groups), nil
}

// Project is the pure transformation; exported so tests can pin every
// edge of the projection.
func Project(tenantID string, users []agent.DiscoveredUser, groups []agent.DiscoveredGroup) OrgGraph {
	graph := OrgGraph{
		TenantID:    tenantID,
		BuiltAt:     time.Now().UTC(),
		Employees:   make(map[string]Employee, len(users)),
		Groups:      make(map[string]Group, len(groups)),
		Departments: map[string][]string{},
	}

	groupIndex := make(map[string]agent.DiscoveredGroup, len(groups))
	for _, g := range groups {
		groupIndex[g.ID] = g
	}

	// Pass 1: project employees and bucket by department.
	for _, u := range users {
		sens := agent.ClassifyUserSensitivity(u, groupIndex)
		isHigh := sens >= agent.SensitivityHigh
		emp := Employee{
			ID:          u.ID,
			Email:       u.Email,
			DisplayName: u.DisplayName,
			Department:  u.Department,
			JobTitle:    u.JobTitle,
			ManagerID:   u.ManagerID,
			Groups:      append([]string(nil), u.GroupIDs...),
			IsHighRisk:  isHigh,
			Sensitivity: sens,
		}
		graph.Employees[u.ID] = emp
		if u.Department != "" {
			graph.Departments[u.Department] = append(graph.Departments[u.Department], u.ID)
		}
		if isHigh {
			graph.HighRisk = append(graph.HighRisk, u.ID)
		}
	}

	// Pass 2: derive reports edges from ManagerID.
	for _, e := range graph.Employees {
		if e.ManagerID == "" {
			continue
		}
		mgr, ok := graph.Employees[e.ManagerID]
		if !ok {
			continue
		}
		mgr.Reports = append(mgr.Reports, e.ID)
		graph.Employees[e.ManagerID] = mgr
	}

	// Pass 3: project groups and flag high-risk groups.
	for _, g := range groups {
		members := make([]string, 0)
		for _, u := range users {
			for _, gid := range u.GroupIDs {
				if gid == g.ID {
					members = append(members, u.ID)
					break
				}
			}
		}
		graph.Groups[g.ID] = Group{
			ID:          g.ID,
			Name:        g.Name,
			Description: g.Description,
			MemberIDs:   members,
			IsHighRisk:  IsHighRiskGroupName(g.Name),
		}
	}
	return graph
}

// IsHighRiskGroupName returns true if name looks like a high-risk
// group (finance, exec, HR, IT admins). Exported for tests.
func IsHighRiskGroupName(name string) bool {
	n := lowerASCII(name)
	for _, t := range []string{"finance", "exec", "c-suite", "leadership", "hr ", "people ops", "legal", "it admin", "sysadmin", "security"} {
		if contains(n, t) {
			return true
		}
	}
	return false
}

func lowerASCII(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
