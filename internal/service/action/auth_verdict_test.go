package action

import (
	"testing"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

func TestAggregateSenderAuth(t *testing.T) {
	cases := []struct {
		name string
		out  *dto.RspamdOutcome
		want AuthVerdict
	}{
		{
			name: "nil_outcome_unknown",
			out:  nil,
			want: AuthUnknown,
		},
		{
			name: "empty_symbols_unverified",
			out:  &dto.RspamdOutcome{Symbols: map[string]float64{}},
			want: AuthUnverified,
		},
		{
			name: "all_pass_verified",
			out: &dto.RspamdOutcome{Symbols: map[string]float64{
				"DMARC_POLICY_ALLOW": 0,
				"R_SPF_ALLOW":        0,
				"R_DKIM_ALLOW":       0,
			}},
			want: AuthVerified,
		},
		{
			name: "dmarc_reject_failed",
			out: &dto.RspamdOutcome{Symbols: map[string]float64{
				"DMARC_POLICY_REJECT": 1,
				"R_SPF_ALLOW":         0,
				"R_DKIM_ALLOW":        0,
			}},
			want: AuthFailed,
		},
		{
			name: "spf_fail_failed",
			out:  &dto.RspamdOutcome{Symbols: map[string]float64{"R_SPF_FAIL": 1}},
			want: AuthFailed,
		},
		{
			name: "dkim_permfail_unverified",
			out:  &dto.RspamdOutcome{Symbols: map[string]float64{"R_DKIM_PERMFAIL": 1}},
			want: AuthUnverified,
		},
		{
			name: "partial_signals_unverified",
			out:  &dto.RspamdOutcome{Symbols: map[string]float64{"R_DKIM_ALLOW": 0}},
			want: AuthUnverified,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AggregateSenderAuth(tc.out)
			if got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestAuthVerdictValid(t *testing.T) {
	for _, v := range []AuthVerdict{AuthVerified, AuthUnverified, AuthFailed, AuthUnknown} {
		if !v.Valid() {
			t.Errorf("%s should be valid", v)
		}
	}
	if AuthVerdict("Bogus").Valid() {
		t.Error("unknown verdict should not be valid")
	}
}
