package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/kennguy3n/sn360-es/internal/constant"
)

// ModelValidator drives the corpus through the real Tier 1 (XLM-RoBERTa
// encoder) and real Tier 2 (Ternary-Bonsai-8B via kennguy3n/llama.cpp)
// HTTP services and produces an agreement report.
//
// The validator does NOT mutate the corpus on disk — it only reads
// scripts/corpus/evaluation/*.json and emits a textual report to
// stdout. Both URLs default to the values used in deployments/encoder
// and deployments/llm.
type ModelValidator struct {
	Tier1URL string
	LLMURL   string
	Dir      string
	HTTP     *http.Client
}

// NewModelValidator returns a validator pointed at the two services.
func NewModelValidator(tier1URL, llmURL, dir string) *ModelValidator {
	return &ModelValidator{
		Tier1URL: strings.TrimRight(tier1URL, "/"),
		LLMURL:   strings.TrimRight(llmURL, "/"),
		Dir:      dir,
		HTTP:     &http.Client{Timeout: 90 * time.Second},
	}
}

// ModelReport captures per-category agreement statistics for Tier 1
// and Tier 2.
type ModelReport struct {
	Tier1Total       int
	Tier1Agree       int
	Tier1Disagree    []string // test_ids
	Tier2Total       int
	Tier2Agree       int
	Tier2Disagree    []string // test_ids
	PerCategoryTier1 map[constant.Category]agreementStats
	PerCategoryTier2 map[constant.Category]agreementStats
}

type agreementStats struct {
	Total int
	Agree int
}

// Render formats the report for human consumption.
func (r *ModelReport) Render() string {
	var b strings.Builder
	b.WriteString("Model validation report\n")
	b.WriteString("-----------------------\n")
	fmt.Fprintf(&b, "Tier 1 agreement: %d / %d (%.1f%%)\n", r.Tier1Agree, r.Tier1Total, pct(r.Tier1Agree, r.Tier1Total))
	fmt.Fprintf(&b, "Tier 2 agreement: %d / %d (%.1f%%)\n", r.Tier2Agree, r.Tier2Total, pct(r.Tier2Agree, r.Tier2Total))
	b.WriteString("Per-category Tier 1:\n")
	cats := sortedCats(r.PerCategoryTier1)
	for _, c := range cats {
		s := r.PerCategoryTier1[c]
		fmt.Fprintf(&b, "  %-30s %d / %d (%.1f%%)\n", c, s.Agree, s.Total, pct(s.Agree, s.Total))
	}
	b.WriteString("Per-category Tier 2:\n")
	cats = sortedCats(r.PerCategoryTier2)
	for _, c := range cats {
		s := r.PerCategoryTier2[c]
		fmt.Fprintf(&b, "  %-30s %d / %d (%.1f%%)\n", c, s.Agree, s.Total, pct(s.Agree, s.Total))
	}
	if n := len(r.Tier1Disagree); n > 0 {
		fmt.Fprintf(&b, "Tier 1 disagreement test_ids (first 20 of %d):\n", n)
		for i, id := range r.Tier1Disagree {
			if i >= 20 {
				break
			}
			fmt.Fprintf(&b, "  %s\n", id)
		}
	}
	if n := len(r.Tier2Disagree); n > 0 {
		fmt.Fprintf(&b, "Tier 2 disagreement test_ids (first 20 of %d):\n", n)
		for i, id := range r.Tier2Disagree {
			if i >= 20 {
				break
			}
			fmt.Fprintf(&b, "  %s\n", id)
		}
	}
	return b.String()
}

// Run loads the corpus and pushes each email through the relevant
// model(s). Network errors abort the run; per-message errors are
// counted as disagreements so a misbehaving service can be spotted
// without falsely inflating accuracy.
func (m *ModelValidator) Run() (*ModelReport, error) {
	emails, err := loadCorpus(m.Dir)
	if err != nil {
		return nil, err
	}
	rep := &ModelReport{
		PerCategoryTier1: make(map[constant.Category]agreementStats),
		PerCategoryTier2: make(map[constant.Category]agreementStats),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, e := range emails {
		if e.Tier0Bypass {
			continue // Tier 0 short-circuits the pipeline; nothing to check here.
		}

		// Tier 1 validation
		verdict, score, err := m.callTier1(ctx, e)
		s1 := rep.PerCategoryTier1[e.Category]
		s1.Total++
		rep.Tier1Total++
		if err == nil && verdict == e.ExpectedTier1Verdict {
			s1.Agree++
			rep.Tier1Agree++
		} else {
			rep.Tier1Disagree = append(rep.Tier1Disagree, fmt.Sprintf("%s (got=%s score=%d)", e.TestID, verdict, score))
		}
		rep.PerCategoryTier1[e.Category] = s1

		// Tier 2 validation (only when the email requires it).
		if !e.ExpectedTier2Needed {
			continue
		}
		cats, err := m.callTier2(ctx, e)
		s2 := rep.PerCategoryTier2[e.Category]
		s2.Total++
		rep.Tier2Total++
		if err == nil && containsCategory(cats, e.ExpectedTier2Categories) {
			s2.Agree++
			rep.Tier2Agree++
		} else {
			rep.Tier2Disagree = append(rep.Tier2Disagree, fmt.Sprintf("%s (got=%v)", e.TestID, cats))
		}
		rep.PerCategoryTier2[e.Category] = s2
	}
	return rep, nil
}

// callTier1 posts the email's subject/body to the XLM-RoBERTa
// encoder's /predict endpoint and maps the returned score through the
// Tier 1 threshold logic (pass<20, escalate 20-60, flag>60).
func (m *ModelValidator) callTier1(ctx context.Context, e TestEmail) (string, int, error) {
	reqBody := map[string]string{
		"subject":       e.Payload.Subject,
		"body":          e.Payload.BodyText,
		"sender_domain": senderDomain(e.Payload.From),
		"message_id":    e.TestID,
	}
	b, err := json.Marshal(reqBody)
	if err != nil {
		return "", 0, err
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, m.Tier1URL+"/predict", bytes.NewReader(b))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", 0, fmt.Errorf("tier1 %d", resp.StatusCode)
	}
	var out struct {
		Score int `json:"score"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", 0, err
	}
	switch {
	case out.Score < 20:
		return "pass", out.Score, nil
	case out.Score <= 60:
		return "escalate", out.Score, nil
	default:
		return "flag", out.Score, nil
	}
}

// callTier2 asks Ternary-Bonsai-8B (kennguy3n/llama.cpp) to classify
// the email. The model is prompted to return a JSON array of
// categories from the canonical 16; anything else is treated as a
// disagreement.
func (m *ModelValidator) callTier2(ctx context.Context, e TestEmail) ([]constant.Category, error) {
	prompt := fmt.Sprintf(
		"Classify this email into ALL applicable categories from the SN360 taxonomy. "+
			"Return ONLY a JSON array of category strings from this exact list: %v. "+
			"\n\nSubject: %s\n\nBody:\n%s",
		formatCategories(constant.AllCategories), e.Payload.Subject, e.Payload.BodyText,
	)
	reqBody := map[string]any{
		"model": "ternary-bonsai-8b",
		"messages": []map[string]string{
			{"role": "system", "content": "You are a strict email classifier. Reply with a JSON array only."},
			{"role": "user", "content": prompt},
		},
		"temperature": 0.0,
		"max_tokens":  256,
	}
	b, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	rctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, m.LLMURL+"/v1/chat/completions", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("tier2 %d", resp.StatusCode)
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if len(out.Choices) == 0 {
		return nil, fmt.Errorf("no choices")
	}
	return parseCategoryArray(out.Choices[0].Message.Content), nil
}

// senderDomain extracts the domain from an RFC 5322 mailbox.
func senderDomain(from string) string {
	at := strings.LastIndex(from, "@")
	if at < 0 {
		return ""
	}
	return strings.TrimRight(from[at+1:], "> ")
}

// formatCategories renders the 16-category list as a JSON array
// literal for prompt-injection-safe inclusion in user prompts.
func formatCategories(cats []constant.Category) string {
	out := make([]string, 0, len(cats))
	for _, c := range cats {
		out = append(out, fmt.Sprintf("%q", string(c)))
	}
	return "[" + strings.Join(out, ", ") + "]"
}

// parseCategoryArray pulls a JSON array of category strings from the
// model's reply, ignoring any wrapping prose / markdown / commentary.
func parseCategoryArray(content string) []constant.Category {
	content = strings.TrimSpace(content)
	start := strings.Index(content, "[")
	end := strings.LastIndex(content, "]")
	if start < 0 || end < start {
		return nil
	}
	var raw []string
	if err := json.Unmarshal([]byte(content[start:end+1]), &raw); err != nil {
		return nil
	}
	out := make([]constant.Category, 0, len(raw))
	for _, s := range raw {
		c := constant.Category(strings.TrimSpace(s))
		if c.Valid() {
			out = append(out, c)
		}
	}
	return out
}

// containsCategory returns true if any element of expected appears in
// got. Tier 2 is allowed to predict additional categories beyond the
// ground-truth ones; we only require the canonical category to be
// surfaced.
func containsCategory(got, expected []constant.Category) bool {
	if len(expected) == 0 {
		return true
	}
	idx := make(map[constant.Category]struct{}, len(got))
	for _, c := range got {
		idx[c] = struct{}{}
	}
	for _, c := range expected {
		if _, ok := idx[c]; ok {
			return true
		}
	}
	return false
}

func sortedCats(m map[constant.Category]agreementStats) []constant.Category {
	out := make([]constant.Category, 0, len(m))
	for c := range m {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i]) < string(out[j]) })
	return out
}

func pct(num, denom int) float64 {
	if denom == 0 {
		return 0
	}
	return float64(num) * 100 / float64(denom)
}
