package relationship

import (
	"errors"
	"math"
	"sync"
	"time"
)

// TimingHistogram is the per-sender baseline of send times. Counts are
// indexed by hour-of-day (0..23) in the recipient's tenant timezone.
// The histogram is intentionally simple — production deployments will
// extend it with day-of-week / weekday-vs-weekend buckets.
type TimingHistogram struct {
	HourCounts [24]int
	Total      int
}

// Add records one send at the supplied timestamp.
func (h *TimingHistogram) Add(t time.Time) {
	hour := t.UTC().Hour()
	h.HourCounts[hour]++
	h.Total++
}

// Probability returns the probability mass of hour t.
func (h TimingHistogram) Probability(t time.Time) float64 {
	if h.Total == 0 {
		return 0
	}
	hour := t.UTC().Hour()
	return float64(h.HourCounts[hour]) / float64(h.Total)
}

// PeakHour returns the (hour, count) pair with the highest mass. When
// the histogram is empty PeakHour returns (0, 0).
func (h TimingHistogram) PeakHour() (int, int) {
	peak, count := 0, 0
	for i, c := range h.HourCounts {
		if c > count {
			peak, count = i, c
		}
	}
	return peak, count
}

// TimingSignal is the per-message timing-anomaly output.
type TimingSignal struct {
	IsAnomalous bool    `json:"is_anomalous"`
	Score       float64 `json:"score"` // 0 (typical) .. 1 (anomalous)
	BaselineN   int     `json:"baseline_n"`
	Reason      string  `json:"reason,omitempty"`
}

// TimingAnalyzerConfig tunes the analyzer.
type TimingAnalyzerConfig struct {
	// MinSamples is the minimum baseline size before the analyzer
	// returns a real signal. Below this threshold AnalyzeTiming returns
	// Score=0 and IsAnomalous=false.
	MinSamples int
	// AnomalyThreshold is the score above which IsAnomalous becomes
	// true. The default (0.7) corresponds to "well outside the
	// sender's normal send window".
	AnomalyThreshold float64
}

// DefaultTimingAnalyzerConfig returns the production defaults.
func DefaultTimingAnalyzerConfig() TimingAnalyzerConfig {
	return TimingAnalyzerConfig{MinSamples: 5, AnomalyThreshold: 0.7}
}

// TimingStore holds the per-sender histograms. The default
// implementation is in-memory; a Redis-backed implementation will use
// the same interface.
type TimingStore interface {
	Load(senderHash string) (TimingHistogram, error)
	Save(senderHash string, h TimingHistogram) error
}

// TimingAnalyzer detects messages sent outside a sender's historical
// pattern. It is goroutine-safe (provided the underlying store is).
type TimingAnalyzer struct {
	cfg   TimingAnalyzerConfig
	store TimingStore
}

// NewTimingAnalyzer constructs the analyzer. A nil store falls back to
// an in-memory store. A zero config falls back to defaults.
func NewTimingAnalyzer(cfg TimingAnalyzerConfig, store TimingStore) *TimingAnalyzer {
	if cfg.MinSamples == 0 && cfg.AnomalyThreshold == 0 {
		cfg = DefaultTimingAnalyzerConfig()
	}
	if store == nil {
		store = NewMemoryTimingStore()
	}
	return &TimingAnalyzer{cfg: cfg, store: store}
}

// Record updates the baseline for senderHash. Use it on every observed
// send (NOT just suspicious ones).
func (a *TimingAnalyzer) Record(senderHash string, t time.Time) error {
	if senderHash == "" {
		return errors.New("relationship: sender_hash is required")
	}
	hist, err := a.store.Load(senderHash)
	if err != nil {
		return err
	}
	hist.Add(t)
	return a.store.Save(senderHash, hist)
}

// AnalyzeTiming returns the anomaly signal for the supplied message
// timestamp without mutating the baseline.
func (a *TimingAnalyzer) AnalyzeTiming(senderHash string, t time.Time) (TimingSignal, error) {
	if senderHash == "" {
		return TimingSignal{}, errors.New("relationship: sender_hash is required")
	}
	hist, err := a.store.Load(senderHash)
	if err != nil {
		return TimingSignal{}, err
	}
	if hist.Total < a.cfg.MinSamples {
		return TimingSignal{BaselineN: hist.Total, Reason: "insufficient_baseline"}, nil
	}
	prob := hist.Probability(t)
	// Compute a distance-from-peak score: messages far from the peak
	// and with low local probability score high.
	score := anomalyScore(hist, t, prob)
	sig := TimingSignal{
		Score:     score,
		BaselineN: hist.Total,
	}
	if score >= a.cfg.AnomalyThreshold {
		sig.IsAnomalous = true
		sig.Reason = "outside_normal_window"
	} else {
		sig.Reason = "within_normal_window"
	}
	return sig, nil
}

func anomalyScore(hist TimingHistogram, t time.Time, prob float64) float64 {
	if hist.Total == 0 {
		return 0
	}
	hour := t.UTC().Hour()
	peakHour, _ := hist.PeakHour()
	// Circular hour distance: 0..12.
	d := hourDistance(hour, peakHour)
	dist := float64(d) / 12.0
	// Inverse probability mass: 0..1.
	freq := 1 - math.Min(prob*8.0, 1.0)
	score := 0.6*dist + 0.4*freq
	if score < 0 {
		return 0
	}
	if score > 1 {
		return 1
	}
	return score
}

func hourDistance(a, b int) int {
	if a < 0 {
		a += 24
	}
	if b < 0 {
		b += 24
	}
	d := a - b
	if d < 0 {
		d = -d
	}
	if d > 12 {
		d = 24 - d
	}
	return d
}

// --- Memory store -----------------------------------------------------------

// MemoryTimingStore is a goroutine-safe in-memory TimingStore.
type MemoryTimingStore struct {
	mu    sync.RWMutex
	items map[string]TimingHistogram
}

// NewMemoryTimingStore returns an empty store.
func NewMemoryTimingStore() *MemoryTimingStore {
	return &MemoryTimingStore{items: map[string]TimingHistogram{}}
}

// Load implements TimingStore.
func (s *MemoryTimingStore) Load(senderHash string) (TimingHistogram, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.items[senderHash], nil
}

// Save implements TimingStore.
func (s *MemoryTimingStore) Save(senderHash string, h TimingHistogram) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[senderHash] = h
	return nil
}
