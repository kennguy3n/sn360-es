package agent

import (
	"testing"
)

func TestDeriveDepartmentPolicies_FinanceForceEscalate(t *testing.T) {
	employees := []OrgEmployee{
		{ID: "1", Department: "Finance", Sensitivity: SensitivityHigh},
		{ID: "2", Department: "Finance", Sensitivity: SensitivityElevated},
		{ID: "3", Department: "Engineering", Sensitivity: SensitivityDefault},
	}

	policies := DeriveDepartmentPolicies(employees)

	var financePolicy *DepartmentPolicy
	for i := range policies {
		if policies[i].Department == "Finance" {
			financePolicy = &policies[i]
			break
		}
	}
	if financePolicy == nil {
		t.Fatal("expected Finance department policy")
	}
	if !financePolicy.ForceEscalate {
		t.Error("Finance department should have ForceEscalate=true")
	}
}

func TestDeriveDepartmentPolicies_ExecutiveRequireMFA(t *testing.T) {
	employees := []OrgEmployee{
		{ID: "1", Department: "Executive", Sensitivity: SensitivityMax},
	}

	policies := DeriveDepartmentPolicies(employees)

	var execPolicy *DepartmentPolicy
	for i := range policies {
		if policies[i].Department == "Executive" {
			execPolicy = &policies[i]
			break
		}
	}
	if execPolicy == nil {
		t.Fatal("expected Executive department policy")
	}
	if !execPolicy.RequireMFA {
		t.Error("Executive department should have RequireMFA=true")
	}
}

func TestDeriveDepartmentPolicies_TreasuryForceEscalate(t *testing.T) {
	employees := []OrgEmployee{
		{ID: "1", Department: "Treasury", Sensitivity: SensitivityElevated},
	}

	policies := DeriveDepartmentPolicies(employees)

	var treasuryPolicy *DepartmentPolicy
	for i := range policies {
		if policies[i].Department == "Treasury" {
			treasuryPolicy = &policies[i]
			break
		}
	}
	if treasuryPolicy == nil {
		t.Fatal("expected Treasury department policy")
	}
	if !treasuryPolicy.ForceEscalate {
		t.Error("Treasury department should have ForceEscalate=true")
	}
}

func TestDeriveDepartmentPolicies_LegalHR(t *testing.T) {
	employees := []OrgEmployee{
		{ID: "1", Department: "Legal", Sensitivity: SensitivityElevated},
		{ID: "2", Department: "Human Resources", Sensitivity: SensitivityDefault},
	}

	policies := DeriveDepartmentPolicies(employees)

	for _, p := range policies {
		if p.Department == "Legal" || p.Department == "Human Resources" {
			if !p.ForceEscalate {
				t.Errorf("%s should have ForceEscalate=true", p.Department)
			}
		}
	}
}

func TestDeriveDepartmentPolicies_EmptyInput(t *testing.T) {
	policies := DeriveDepartmentPolicies(nil)
	if len(policies) != 0 {
		t.Errorf("expected empty policies for nil input, got %d", len(policies))
	}
}

func TestDeriveDepartmentPolicies_EmptyDepartment(t *testing.T) {
	employees := []OrgEmployee{
		{ID: "1", Department: "", Sensitivity: SensitivityMax},
	}

	policies := DeriveDepartmentPolicies(employees)
	if len(policies) != 0 {
		t.Errorf("expected no policies for empty department, got %d", len(policies))
	}
}
