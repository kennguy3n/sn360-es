package onboarding

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/service/agent"
)

type stubGraphSource struct {
	users  []agent.DiscoveredUser
	groups []agent.DiscoveredGroup
	uErr   error
	gErr   error
}

func (s stubGraphSource) ListUsers(_ context.Context, _ string) ([]agent.DiscoveredUser, error) {
	return s.users, s.uErr
}

func (s stubGraphSource) ListGroups(_ context.Context, _ string) ([]agent.DiscoveredGroup, error) {
	return s.groups, s.gErr
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewOrgGraphBuilder_RequiresSource(t *testing.T) {
	if _, err := NewOrgGraphBuilder(nil, nil); err == nil {
		t.Fatal("expected error for nil source")
	}
}

func TestOrgGraphBuilder_Build_RequiresTenant(t *testing.T) {
	b, _ := NewOrgGraphBuilder(stubGraphSource{}, discardLogger())
	if _, err := b.Build(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty tenant")
	}
}

func TestOrgGraphBuilder_Build_PropagatesSourceErrors(t *testing.T) {
	b, _ := NewOrgGraphBuilder(stubGraphSource{uErr: errors.New("u")}, discardLogger())
	if _, err := b.Build(context.Background(), "acme"); err == nil {
		t.Fatal("expected ListUsers error")
	}
	b2, _ := NewOrgGraphBuilder(stubGraphSource{gErr: errors.New("g")}, discardLogger())
	if _, err := b2.Build(context.Background(), "acme"); err == nil {
		t.Fatal("expected ListGroups error")
	}
}

func TestOrgGraphBuilder_Build_Projects(t *testing.T) {
	src := stubGraphSource{
		users: []agent.DiscoveredUser{
			{ID: "u1", Email: "ceo@acme.com", JobTitle: "CEO", Department: "Executive", GroupIDs: []string{"g1"}},
			{ID: "u2", Email: "cfo@acme.com", JobTitle: "CFO", Department: "Finance", ManagerID: "u1"},
			{ID: "u3", Email: "eng@acme.com", JobTitle: "Engineer", Department: "Engineering", ManagerID: "u1"},
		},
		groups: []agent.DiscoveredGroup{
			{ID: "g1", Name: "C-suite"},
			{ID: "g2", Name: "Marketing Team"},
		},
	}
	b, _ := NewOrgGraphBuilder(src, discardLogger())
	graph, err := b.Build(context.Background(), "acme")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if graph.TenantID != "acme" {
		t.Fatalf("TenantID: %q", graph.TenantID)
	}
	if len(graph.Employees) != 3 {
		t.Fatalf("Employees: %d", len(graph.Employees))
	}
	if len(graph.Departments["Finance"]) != 1 || graph.Departments["Finance"][0] != "u2" {
		t.Fatalf("Finance bucket: %+v", graph.Departments)
	}
	// u1 manages u2 and u3.
	if reps := graph.Employees["u1"].Reports; len(reps) != 2 {
		t.Fatalf("u1.Reports: %+v", reps)
	}
	// CEO + CFO classified high risk; engineer not.
	hr := map[string]bool{}
	for _, id := range graph.HighRisk {
		hr[id] = true
	}
	if !hr["u1"] || !hr["u2"] {
		t.Fatalf("HighRisk should contain u1+u2: %+v", graph.HighRisk)
	}
	if hr["u3"] {
		t.Fatalf("u3 should not be high risk: %+v", graph.HighRisk)
	}
	// g1 (C-suite) is high-risk; g2 (Marketing) is not.
	if !graph.Groups["g1"].IsHighRisk {
		t.Fatalf("g1 should be high risk: %+v", graph.Groups["g1"])
	}
	if graph.Groups["g2"].IsHighRisk {
		t.Fatalf("g2 should not be high risk: %+v", graph.Groups["g2"])
	}
	// Membership inference: u1 is in g1.
	if len(graph.Groups["g1"].MemberIDs) != 1 || graph.Groups["g1"].MemberIDs[0] != "u1" {
		t.Fatalf("g1 members: %+v", graph.Groups["g1"].MemberIDs)
	}
}

func TestProject_HandlesEmptyInput(t *testing.T) {
	g := Project("acme", nil, nil)
	if g.TenantID != "acme" {
		t.Fatalf("TenantID: %q", g.TenantID)
	}
	if len(g.Employees) != 0 || len(g.Groups) != 0 || len(g.Departments) != 0 {
		t.Fatalf("non-empty maps: %+v", g)
	}
}

func TestProject_SkipsUnknownManager(t *testing.T) {
	users := []agent.DiscoveredUser{
		{ID: "u1", ManagerID: "ghost"},
		{ID: "u2"},
	}
	g := Project("acme", users, nil)
	if len(g.Employees["u1"].Reports) != 0 {
		t.Fatalf("u1 should have no reports: %+v", g.Employees["u1"])
	}
}

func TestIsHighRiskGroupName(t *testing.T) {
	cases := map[string]bool{
		"Finance Team":       true,
		"Executive Officers": true,
		"C-Suite":            true,
		"Leadership":         true,
		"hr team":            true,
		"People Ops":         true,
		"Legal":              true,
		"IT Admins":          true,
		"SysAdmin":           true,
		"Security":           true,
		"Marketing":          false,
		"Engineering":        false,
		"":                   false,
	}
	for in, want := range cases {
		if got := IsHighRiskGroupName(in); got != want {
			t.Fatalf("IsHighRiskGroupName(%q)=%v want %v", in, got, want)
		}
	}
}

func TestAgentBridge_StartOnboarding_NilAgent(t *testing.T) {
	b := &AgentBridge{}
	if err := b.StartOnboarding(context.Background(), "acme", ProviderGoogle); err == nil {
		t.Fatal("expected error for nil agent")
	}
}

func TestAgentProvider_Maps(t *testing.T) {
	cases := map[ProviderType]agent.Provider{
		ProviderGoogle:    agent.ProviderGoogle,
		ProviderMicrosoft: agent.ProviderMicrosoft,
		"":                agent.ProviderUnknown,
	}
	for in, want := range cases {
		if got := agentProvider(in); got != want {
			t.Fatalf("agentProvider(%q)=%q want %q", in, got, want)
		}
	}
}
