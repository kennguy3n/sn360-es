package agent

import (
	"testing"
	"time"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// TestDerivePriorityAndStatus pins the legacy v1 priority column
// mapping from escalation reason. The reason values are the only
// public signal of priority on the EscalationTicket DTO (the
// escalation service does not store priority explicitly), so this
// projection is what every Postgres-backed dashboard query reads.
//
// The ops_alert case is the regression Devin Review caught in
// round 17: EscalationReasonOpsAlert tickets are created exclusively
// from severity=critical Alertmanager alerts (see
// internal/service/ops/alert_router.go:263 for the no-remediator
// escalation branch and :401 for the remediation-failure fallback),
// so they MUST surface as critical priority. A drift here would
// silently store infrastructure-critical incidents at the schema
// default 'normal', under-prioritising them on any SOC dashboard
// that sorts by the legacy priority column.
func TestDerivePriorityAndStatus(t *testing.T) {
	tests := []struct {
		name         string
		reason       dto.EscalationReason
		resolvedAt   time.Time
		wantPriority string
		wantStatus   string
	}{
		{
			name:         "confirmed_breach maps to critical/open",
			reason:       dto.EscalationReasonConfirmedBreach,
			wantPriority: "critical",
			wantStatus:   "open",
		},
		{
			name:         "account_compromise maps to critical/open",
			reason:       dto.EscalationReasonAccountCompromise,
			wantPriority: "critical",
			wantStatus:   "open",
		},
		{
			name:         "ops_alert maps to critical (severity=critical Alertmanager invariant)",
			reason:       dto.EscalationReasonOpsAlert,
			wantPriority: "critical",
			wantStatus:   "open",
		},
		{
			name:         "zero_day_attachment maps to high",
			reason:       dto.EscalationReasonZeroDayAttachment,
			wantPriority: "high",
			wantStatus:   "open",
		},
		{
			name:         "low_confidence maps to normal (schema default)",
			reason:       dto.EscalationReasonLowConfidence,
			wantPriority: "normal",
			wantStatus:   "open",
		},
		{
			name:         "user_requested maps to normal (schema default)",
			reason:       dto.EscalationReasonUserRequested,
			wantPriority: "normal",
			wantStatus:   "open",
		},
		{
			name:         "resolved_at present flips status to resolved",
			reason:       dto.EscalationReasonConfirmedBreach,
			resolvedAt:   time.Now(),
			wantPriority: "critical",
			wantStatus:   "resolved",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ticket := dto.EscalationTicket{
				Reason:     tt.reason,
				ResolvedAt: tt.resolvedAt,
			}
			gotPriority, gotStatus := derivePriorityAndStatus(ticket)
			if gotPriority != tt.wantPriority {
				t.Errorf("priority = %q, want %q", gotPriority, tt.wantPriority)
			}
			if gotStatus != tt.wantStatus {
				t.Errorf("status = %q, want %q", gotStatus, tt.wantStatus)
			}
		})
	}
}
