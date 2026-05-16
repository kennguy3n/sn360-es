package relationship

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"time"
)

// SenderObservation summarises one external sender within the
// trailing-30-days window. It feeds the auto-discovery heuristic.
type SenderObservation struct {
	Domain           string
	InboundCount     int
	OutboundCount    int
	DistinctRecipients int
	FirstSeen        time.Time
	LastSeen         time.Time
}

// VendorProposal is the output of the discovery job: one row per
// candidate vendor with a confidence score.
type VendorProposal struct {
	Domain      string  `json:"domain"`
	Confidence  float64 `json:"confidence"`   // 0..1
	AutoApprove bool    `json:"auto_approve"` // confidence >= cfg.AutoApproveThreshold
	Bidirectional      bool `json:"bidirectional"`
	InboundCount       int  `json:"inbound_count"`
	OutboundCount      int  `json:"outbound_count"`
	DistinctRecipients int  `json:"distinct_recipients"`
	Reason             string `json:"reason"`
}

// VendorDiscoveryConfig wires the discovery heuristic.
type VendorDiscoveryConfig struct {
	MinInbound           int
	MinDistinctRecipients int
	MinWindowDays        int
	AutoApproveThreshold float64
	ExcludeFreeDomains   bool
	FreeDomains          map[string]struct{}
}

// DefaultVendorDiscoveryConfig returns the production defaults.
func DefaultVendorDiscoveryConfig() VendorDiscoveryConfig {
	return VendorDiscoveryConfig{
		MinInbound:           5,
		MinDistinctRecipients: 2,
		MinWindowDays:        14,
		AutoApproveThreshold: 0.80,
		ExcludeFreeDomains:   true,
		FreeDomains: map[string]struct{}{
			"gmail.com": {}, "outlook.com": {}, "yahoo.com": {},
			"hotmail.com": {}, "icloud.com": {}, "proton.me": {}, "protonmail.com": {},
		},
	}
}

// VendorDiscovery proposes new vendors from a tenant's 30-day inbound
// history.
type VendorDiscovery struct {
	cfg VendorDiscoveryConfig
	log *slog.Logger
	now func() time.Time
}

// NewVendorDiscovery constructs the service.
func NewVendorDiscovery(cfg VendorDiscoveryConfig, log *slog.Logger) *VendorDiscovery {
	if cfg.MinInbound == 0 && cfg.AutoApproveThreshold == 0 {
		cfg = DefaultVendorDiscoveryConfig()
	}
	if log == nil {
		log = slog.Default()
	}
	return &VendorDiscovery{cfg: cfg, log: log, now: func() time.Time { return time.Now().UTC() }}
}

// WithClock overrides the clock (mainly for tests).
func (v *VendorDiscovery) WithClock(clock func() time.Time) *VendorDiscovery {
	v.now = clock
	return v
}

// Propose runs the heuristic against the supplied observations and
// returns the deterministic list of vendor proposals (sorted by
// descending confidence).
func (v *VendorDiscovery) Propose(_ context.Context, tenantID string, observations []SenderObservation) ([]VendorProposal, error) {
	if tenantID == "" {
		return nil, errors.New("relationship: tenant_id is required")
	}
	out := make([]VendorProposal, 0, len(observations))
	for _, obs := range observations {
		p, ok := v.score(obs)
		if !ok {
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].Domain < out[j].Domain
	})
	return out, nil
}

func (v *VendorDiscovery) score(obs SenderObservation) (VendorProposal, bool) {
	domain := strings.ToLower(strings.TrimSpace(obs.Domain))
	if domain == "" {
		return VendorProposal{}, false
	}
	if v.cfg.ExcludeFreeDomains {
		if _, free := v.cfg.FreeDomains[domain]; free {
			return VendorProposal{}, false
		}
	}
	if obs.InboundCount < v.cfg.MinInbound {
		return VendorProposal{}, false
	}
	if obs.DistinctRecipients < v.cfg.MinDistinctRecipients {
		return VendorProposal{}, false
	}
	if v.cfg.MinWindowDays > 0 && !obs.FirstSeen.IsZero() {
		window := obs.LastSeen.Sub(obs.FirstSeen)
		if window < time.Duration(v.cfg.MinWindowDays)*24*time.Hour {
			return VendorProposal{}, false
		}
	}
	// Confidence: monotone-increasing in volume, distinct recipients,
	// and bidirectional behaviour. Capped at 1.0.
	conf := 0.0
	conf += min01(float64(obs.InboundCount) / 30.0 * 0.5)        // ≤ 0.5
	conf += min01(float64(obs.DistinctRecipients) / 10.0 * 0.25)  // ≤ 0.25
	bidirectional := obs.OutboundCount > 0
	if bidirectional {
		conf += 0.20
	}
	if obs.OutboundCount >= 3 {
		conf += 0.05 // strong bidirectional bump
	}
	if conf > 1 {
		conf = 1
	}
	reason := "recurring_inbound"
	if bidirectional {
		reason = "bidirectional"
	}
	return VendorProposal{
		Domain:             domain,
		Confidence:         round2(conf),
		AutoApprove:        conf >= v.cfg.AutoApproveThreshold,
		Bidirectional:      bidirectional,
		InboundCount:       obs.InboundCount,
		OutboundCount:      obs.OutboundCount,
		DistinctRecipients: obs.DistinctRecipients,
		Reason:             reason,
	}, true
}

func min01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func round2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100
}
