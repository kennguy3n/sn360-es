package agent

import (
	"strings"
)

// DepartmentPolicy captures per-department security posture rules
// derived from org-graph analysis.
type DepartmentPolicy struct {
	Department         string
	DefaultSensitivity Sensitivity
	ForceEscalate      bool // first-contact external emails force Tier 1
	RequireMFA         bool // flag emails when DMARC != pass
}

// OrgEmployee is the projected node for policy derivation. Mirrors
// onboarding.Employee without importing the onboarding package
// (which would cause a cycle).
type OrgEmployee struct {
	ID          string
	Department  string
	Sensitivity Sensitivity
}

// DeriveDepartmentPolicies analyzes org employees and produces
// per-department policies. Finance/Treasury force-escalate first
// contacts; executive groups require MFA verification; HR/Legal
// get more conservative thresholds.
func DeriveDepartmentPolicies(employees []OrgEmployee) []DepartmentPolicy {
	deptSensitivity := make(map[string]Sensitivity)
	deptHasExec := make(map[string]bool)

	for _, emp := range employees {
		dept := emp.Department
		if dept == "" {
			continue
		}
		if emp.Sensitivity > deptSensitivity[dept] {
			deptSensitivity[dept] = emp.Sensitivity
		}
		if emp.Sensitivity >= SensitivityMax {
			deptHasExec[dept] = true
		}
	}

	var policies []DepartmentPolicy
	for dept, sens := range deptSensitivity {
		p := DepartmentPolicy{
			Department:         dept,
			DefaultSensitivity: sens,
		}
		lower := strings.ToLower(dept)
		if isFinanceDepartment(lower) || isTreasuryDepartment(lower) {
			p.ForceEscalate = true
		}
		if deptHasExec[dept] || isExecutiveDepartment(lower) {
			p.RequireMFA = true
		}
		if isLegalDepartment(lower) || isHRDepartment(lower) {
			p.ForceEscalate = true
		}
		policies = append(policies, p)
	}
	return policies
}

func isFinanceDepartment(s string) bool {
	return strings.Contains(s, "finance") || strings.Contains(s, "accounting") || strings.Contains(s, "treasury")
}

func isTreasuryDepartment(s string) bool {
	return strings.Contains(s, "treasury")
}

func isExecutiveDepartment(s string) bool {
	return strings.Contains(s, "executive") || strings.Contains(s, "c-suite") || strings.Contains(s, "leadership") || strings.Contains(s, "board")
}

func isLegalDepartment(s string) bool {
	return strings.Contains(s, "legal") || strings.Contains(s, "compliance")
}

func isHRDepartment(s string) bool {
	return s == "hr" || strings.Contains(s, "human resource") || strings.Contains(s, "people ops") || strings.Contains(s, "people operations")
}
