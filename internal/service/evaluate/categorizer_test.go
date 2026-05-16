package evaluate

import (
	"testing"

	"github.com/kennguy3n/sn360-es/internal/constant"
	"github.com/kennguy3n/sn360-es/internal/dto"
)

func TestRuleCategorizerBenignGatesShortCircuit(t *testing.T) {
	c := NewRuleCategorizer()

	cases := []struct {
		name    string
		signals dto.RiskSignals
		want    constant.Category
	}{
		{"internal", dto.RiskSignals{IsInternal: true}, constant.CategoryInternalTrusted},
		{"vendor", dto.RiskSignals{IsFromVendor: true}, constant.CategoryVendorTrusted},
		{"recurring", dto.RiskSignals{IsRecurringService: true}, constant.CategoryNewsletter},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := c.Decide(dto.EvaluateResult{Score: 99}, tc.signals)
			if dec.Primary != tc.want {
				t.Errorf("got %s, want %s", dec.Primary, tc.want)
			}
			if len(dec.Secondary) != 0 {
				t.Errorf("benign should not surface secondaries, got %v", dec.Secondary)
			}
		})
	}
}

func TestRuleCategorizerLookalikeDominates(t *testing.T) {
	c := NewRuleCategorizer()
	dec := c.Decide(dto.EvaluateResult{Score: 60}, dto.RiskSignals{
		IsExternal:         true,
		HasLookalikeDomain: true,
	})
	if dec.Primary != constant.CategoryLookalikeDomain {
		t.Fatalf("primary = %s, want LOOKALIKE_DOMAIN", dec.Primary)
	}
}

func TestRuleCategorizerInvoiceFraudStacksOnLookalike(t *testing.T) {
	c := NewRuleCategorizer()
	dec := c.Decide(dto.EvaluateResult{Score: 50}, dto.RiskSignals{
		IsExternal:         true,
		HasLookalikeDomain: true,
		HasInvoiceHint:     true,
	})
	// Invoice + lookalike = 2 + 2 = 4 — same weight as plain lookalike.
	// Lookalike still wins because of tie-break order (LOOKALIKE_DOMAIN
	// comes before INVOICE_FRAUD in AllCategories), but invoice should
	// appear as a secondary.
	if dec.Primary != constant.CategoryLookalikeDomain {
		t.Fatalf("primary = %s, want LOOKALIKE_DOMAIN", dec.Primary)
	}
	foundInvoice := false
	for _, c := range dec.Secondary {
		if c == constant.CategoryInvoiceFraud {
			foundInvoice = true
		}
	}
	if !foundInvoice {
		t.Errorf("INVOICE_FRAUD should be a secondary, got %v", dec.Secondary)
	}
}

func TestRuleCategorizerNoSignalsFallsBackToFirstContact(t *testing.T) {
	c := NewRuleCategorizer()
	dec := c.Decide(dto.EvaluateResult{Score: 5}, dto.RiskSignals{IsExternal: true})
	if dec.Primary != constant.CategoryFirstContactExternal {
		t.Fatalf("primary = %s, want FIRST_CONTACT_EXTERNAL", dec.Primary)
	}
}

func TestRuleCategorizerDeterministic(t *testing.T) {
	c := NewRuleCategorizer()
	r := dto.EvaluateResult{
		Score:       72,
		ReasonCodes: []string{"phishing-like", "credential-harvest"},
		Tier2: &dto.Tier2Outcome{Categories: []constant.Category{
			constant.CategoryBECImpersonation,
		}},
	}
	sig := dto.RiskSignals{IsExternal: true, HasSuspiciousURL: true, HasCredentialLex: true}

	first := c.Decide(r, sig)
	for i := 0; i < 5; i++ {
		next := c.Decide(r, sig)
		if next.Primary != first.Primary || len(next.Secondary) != len(first.Secondary) {
			t.Fatalf("non-deterministic decision at iteration %d", i)
		}
	}
}

func TestRuleCategoriseInterfaceShape(t *testing.T) {
	c := NewRuleCategorizer()
	primary, secondary, reasons := c.Categorise(
		dto.EvaluateResult{Score: 90},
		dto.RiskSignals{IsExternal: true, HasLookalikeDomain: true, HasSuspiciousURL: true},
	)
	if primary == "" {
		t.Error("primary must not be empty")
	}
	_ = secondary
	if len(reasons) == 0 {
		t.Error("reasons must not be empty for a non-benign verdict")
	}
}
