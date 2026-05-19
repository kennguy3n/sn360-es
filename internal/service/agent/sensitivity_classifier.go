package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/blake2b"
)

// SensitivityClassifier classifies users into sensitivity tiers using
// a tiered approach: encoder (fast path) → Bonsai SLM (slow path) →
// keyword fallback.
type SensitivityClassifier interface {
	ClassifyBatch(ctx context.Context, users []UserClassifyInput) ([]ClassifyResult, error)
}

// UserClassifyInput is the input shape for batch classification.
type UserClassifyInput struct {
	JobTitle    string
	Department  string
	DisplayName string
	GroupNames  []string
	IsAdmin     bool
}

// KeywordClassifyInput applies the same keyword-based heuristic as
// ClassifyUserSensitivity but works with the batch-oriented
// UserClassifyInput shape. Suitable as the Fallback in
// TieredClassifierConfig for low-confidence encoder results.
func KeywordClassifyInput(u UserClassifyInput) Sensitivity {
	hay := strings.ToLower(u.JobTitle + " " + u.Department + " " + u.DisplayName)
	for _, g := range u.GroupNames {
		hay += " " + strings.ToLower(g)
	}
	switch {
	case containsAnyInput(hay, "ceo", "cfo", "coo", "cto", "ciso", "founder", "chief executive", "chief financial", "owner"):
		return SensitivityMax
	case containsAnyInput(hay, "finance", "treasury", "accounts payable", "accounts receivable", "controller", "bookkeep"):
		return SensitivityHigh
	case containsAnyInput(hay, "human resources", "people ops", "legal", "compliance", "general counsel"):
		return SensitivityHigh
	case containsAnyInput(hay, "executive assistant", "admin assistant", "office manager"):
		return SensitivityElevated
	case containsAnyInput(hay, "procurement", "vendor management", "supplier"):
		return SensitivityElevated
	default:
		return SensitivityDefault
	}
}

func containsAnyInput(haystack string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

// ClassifyResult is the output of sensitivity classification.
type ClassifyResult struct {
	Sensitivity Sensitivity
	Confidence  float64
	NeedsReview bool
}

// EncoderSensitivityClassifier uses the XLM-RoBERTa encoder service
// at the /classify/roles endpoint for fast multilingual classification.
type EncoderSensitivityClassifier struct {
	url     string
	client  *http.Client
	timeout time.Duration
	logger  *slog.Logger
}

// NewEncoderSensitivityClassifier constructs an encoder classifier.
func NewEncoderSensitivityClassifier(url string, client *http.Client, timeout time.Duration, logger *slog.Logger) *EncoderSensitivityClassifier {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &EncoderSensitivityClassifier{url: url, client: client, timeout: timeout, logger: logger}
}

type encoderRequest struct {
	Texts []string `json:"texts"`
	Task  string   `json:"task"`
}

type encoderResponse struct {
	Results []struct {
		Sensitivity string  `json:"sensitivity"`
		Confidence  float64 `json:"confidence"`
	} `json:"results"`
}

// ClassifyBatch sends a batch to the encoder /classify/roles endpoint.
func (c *EncoderSensitivityClassifier) ClassifyBatch(ctx context.Context, users []UserClassifyInput) ([]ClassifyResult, error) {
	if len(users) == 0 {
		return nil, nil
	}
	texts := make([]string, len(users))
	for i, u := range users {
		texts[i] = buildClassifyText(u)
	}
	body, err := json.Marshal(encoderRequest{Texts: texts, Task: "role_classify"})
	if err != nil {
		return nil, fmt.Errorf("sensitivity: marshal request: %w", err)
	}
	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.url+"/classify/roles", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("sensitivity: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sensitivity: encoder request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("sensitivity: encoder returned %d: %s", resp.StatusCode, string(respBody))
	}
	var result encoderResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("sensitivity: decode response: %w", err)
	}
	out := make([]ClassifyResult, len(users))
	for i := range users {
		if i < len(result.Results) {
			out[i] = ClassifyResult{
				Sensitivity: parseSensitivityString(result.Results[i].Sensitivity),
				Confidence:  result.Results[i].Confidence,
				NeedsReview: result.Results[i].Confidence < 0.5,
			}
		} else {
			out[i] = ClassifyResult{Sensitivity: SensitivityDefault, Confidence: 0, NeedsReview: true}
		}
	}
	return out, nil
}

// BonsaiSensitivityClassifier uses the Bonsai SLM for deeper
// reasoning on ambiguous titles (any language).
type BonsaiSensitivityClassifier struct {
	url     string
	client  *http.Client
	timeout time.Duration
	logger  *slog.Logger
}

// NewBonsaiSensitivityClassifier constructs a Bonsai classifier.
func NewBonsaiSensitivityClassifier(url string, client *http.Client, timeout time.Duration, logger *slog.Logger) *BonsaiSensitivityClassifier {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &BonsaiSensitivityClassifier{url: url, client: client, timeout: timeout, logger: logger}
}

type bonsaiRequest struct {
	Model       string        `json:"model"`
	Messages    []bonsaiMsg   `json:"messages"`
	Temperature float64       `json:"temperature"`
}

type bonsaiMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type bonsaiResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

type bonsaiClassifyResult struct {
	Results []struct {
		Index       int     `json:"index"`
		Sensitivity string  `json:"sensitivity"`
		Confidence  float64 `json:"confidence"`
	} `json:"results"`
}

// ClassifyBatch sends ambiguous users to Bonsai for classification.
func (c *BonsaiSensitivityClassifier) ClassifyBatch(ctx context.Context, users []UserClassifyInput) ([]ClassifyResult, error) {
	if len(users) == 0 {
		return nil, nil
	}
	prompt := buildBonsaiPrompt(users)
	body, err := json.Marshal(bonsaiRequest{
		Model:       "bonsai-8b",
		Messages:    []bonsaiMsg{{Role: "user", Content: prompt}},
		Temperature: 0.0,
	})
	if err != nil {
		return nil, fmt.Errorf("sensitivity: marshal bonsai request: %w", err)
	}
	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.url+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("sensitivity: build bonsai request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sensitivity: bonsai request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("sensitivity: bonsai returned %d: %s", resp.StatusCode, string(respBody))
	}
	var bResp bonsaiResponse
	if err := json.NewDecoder(resp.Body).Decode(&bResp); err != nil {
		return nil, fmt.Errorf("sensitivity: decode bonsai response: %w", err)
	}
	out := make([]ClassifyResult, len(users))
	for i := range out {
		out[i] = ClassifyResult{Sensitivity: SensitivityDefault, Confidence: 0, NeedsReview: true}
	}
	if len(bResp.Choices) > 0 {
		content := bResp.Choices[0].Message.Content
		content = extractJSON(content)
		var parsed bonsaiClassifyResult
		if err := json.Unmarshal([]byte(content), &parsed); err == nil {
			for _, r := range parsed.Results {
				if r.Index >= 0 && r.Index < len(out) {
					out[r.Index] = ClassifyResult{
						Sensitivity: parseSensitivityString(r.Sensitivity),
						Confidence:  r.Confidence,
						NeedsReview: r.Confidence < 0.5,
					}
				}
			}
		}
	}
	return out, nil
}

// TieredSensitivityClassifier combines encoder + Bonsai + fallback
// in a tiered architecture matching the detection pipeline pattern.
type TieredSensitivityClassifier struct {
	encoder         *EncoderSensitivityClassifier
	bonsai          *BonsaiSensitivityClassifier
	fallback        func(UserClassifyInput) Sensitivity
	cache           redis.Cmdable
	escalateBelow   float64
	logger          *slog.Logger
}

// TieredClassifierConfig configures the tiered classifier.
type TieredClassifierConfig struct {
	Encoder       *EncoderSensitivityClassifier
	Bonsai        *BonsaiSensitivityClassifier
	Fallback      func(UserClassifyInput) Sensitivity
	Cache         redis.Cmdable
	EscalateBelow float64
	Logger        *slog.Logger
}

// NewTieredSensitivityClassifier constructs the tiered classifier.
func NewTieredSensitivityClassifier(cfg TieredClassifierConfig) *TieredSensitivityClassifier {
	if cfg.EscalateBelow == 0 {
		cfg.EscalateBelow = 0.7
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &TieredSensitivityClassifier{
		encoder:       cfg.Encoder,
		bonsai:        cfg.Bonsai,
		fallback:      cfg.Fallback,
		cache:         cfg.Cache,
		escalateBelow: cfg.EscalateBelow,
		logger:        cfg.Logger,
	}
}

// ClassifyBatch implements SensitivityClassifier using the tiered approach.
func (c *TieredSensitivityClassifier) ClassifyBatch(ctx context.Context, users []UserClassifyInput) ([]ClassifyResult, error) {
	results := make([]ClassifyResult, len(users))

	// Check cache first.
	uncached := make([]int, 0, len(users))
	for i, u := range users {
		if c.cache != nil {
			key := classifyCacheKey(u)
			val, err := c.cache.Get(ctx, key).Result()
			if err == nil {
				var cached ClassifyResult
				if json.Unmarshal([]byte(val), &cached) == nil {
					results[i] = cached
					continue
				}
			}
		}
		uncached = append(uncached, i)
	}

	if len(uncached) == 0 {
		return applyAdminBoost(users, results), nil
	}

	// Build batch of uncached users.
	batch := make([]UserClassifyInput, len(uncached))
	for j, idx := range uncached {
		batch[j] = users[idx]
	}

	// Tier 1: Encoder (fast path).
	var encoderResults []ClassifyResult
	if c.encoder != nil {
		var err error
		encoderResults, err = c.encoder.ClassifyBatch(ctx, batch)
		if err != nil {
			c.logger.Warn("sensitivity: encoder failed, falling through",
				slog.String("err", err.Error()))
		}
	}

	// Identify users needing Bonsai escalation.
	needBonsai := make([]int, 0)
	for j := range batch {
		if j < len(encoderResults) && encoderResults[j].Confidence >= c.escalateBelow {
			results[uncached[j]] = encoderResults[j]
		} else {
			needBonsai = append(needBonsai, j)
		}
	}

	// Tier 2: Bonsai (slow path) for low-confidence results.
	if len(needBonsai) > 0 && c.bonsai != nil {
		bonsaiBatch := make([]UserClassifyInput, len(needBonsai))
		for k, j := range needBonsai {
			bonsaiBatch[k] = batch[j]
		}
		bonsaiResults, err := c.bonsai.ClassifyBatch(ctx, bonsaiBatch)
		if err != nil {
			c.logger.Warn("sensitivity: bonsai failed, using fallback",
				slog.String("err", err.Error()))
		} else {
			for k, j := range needBonsai {
				if k < len(bonsaiResults) {
					results[uncached[j]] = bonsaiResults[k]
					// Remove from needBonsai list for fallback.
					needBonsai[k] = -1
				}
			}
		}
	}

	// Keyword fallback for anything still unresolved.
	for j, idx := range uncached {
		if results[idx].Confidence == 0 && results[idx].Sensitivity == SensitivityDefault {
			if c.fallback != nil {
				sens := c.fallback(batch[j])
				results[idx] = ClassifyResult{
					Sensitivity: sens,
					Confidence:  0.6,
					NeedsReview: false,
				}
			} else {
				results[idx] = ClassifyResult{
					Sensitivity: SensitivityDefault,
					Confidence:  1.0,
					NeedsReview: false,
				}
			}
		}
	}

	// Cache results.
	if c.cache != nil {
		for _, idx := range uncached {
			key := classifyCacheKey(users[idx])
			val, _ := json.Marshal(results[idx])
			_ = c.cache.Set(ctx, key, string(val), 24*time.Hour).Err()
		}
	}

	return applyAdminBoost(users, results), nil
}

// applyAdminBoost ensures IsAdmin users are at least SensitivityElevated.
func applyAdminBoost(users []UserClassifyInput, results []ClassifyResult) []ClassifyResult {
	for i, u := range users {
		if u.IsAdmin && results[i].Sensitivity < SensitivityElevated {
			results[i].Sensitivity = SensitivityElevated
		}
	}
	return results
}

func classifyCacheKey(u UserClassifyInput) string {
	h, _ := blake2b.New256(nil)
	// Length-prefixed encoding prevents field-boundary collisions
	// (e.g. Title="VP|Finance" vs Title="VP", Dept="Finance").
	fmt.Fprintf(h, "%d:%s", len(u.JobTitle), u.JobTitle)
	fmt.Fprintf(h, "%d:%s", len(u.Department), u.Department)
	fmt.Fprintf(h, "%d:%s", len(u.DisplayName), u.DisplayName)
	for _, g := range u.GroupNames {
		fmt.Fprintf(h, "%d:%s", len(g), g)
	}
	if u.IsAdmin {
		h.Write([]byte("admin"))
	}
	return "sensitivity:classify:" + fmt.Sprintf("%x", h.Sum(nil))
}

func buildClassifyText(u UserClassifyInput) string {
	var sb strings.Builder
	if u.JobTitle != "" {
		sb.WriteString("Job: ")
		sb.WriteString(u.JobTitle)
	}
	if u.Department != "" {
		if sb.Len() > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString("Dept: ")
		sb.WriteString(u.Department)
	}
	if u.DisplayName != "" {
		if sb.Len() > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString("Name: ")
		sb.WriteString(u.DisplayName)
	}
	if len(u.GroupNames) > 0 {
		if sb.Len() > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString("Groups: ")
		sb.WriteString(strings.Join(u.GroupNames, "/"))
	}
	return sb.String()
}

func buildBonsaiPrompt(users []UserClassifyInput) string {
	var sb strings.Builder
	sb.WriteString(`You are a security role classifier. For each user below, classify their organizational sensitivity into one of: "max" (C-suite/board), "high" (VP/Director/Finance/Legal), "elevated" (senior/manager), or "default" (other). Return JSON only: {"results": [{"index": 0, "sensitivity": "...", "confidence": 0.0-1.0}, ...]}

Users:
`)
	for i, u := range users {
		fmt.Fprintf(&sb, "%d. Title: %q, Department: %q, Name: %q\n", i, u.JobTitle, u.Department, u.DisplayName)
	}
	return sb.String()
}

func parseSensitivityString(s string) Sensitivity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "max":
		return SensitivityMax
	case "high":
		return SensitivityHigh
	case "elevated":
		return SensitivityElevated
	default:
		return SensitivityDefault
	}
}

func extractJSON(s string) string {
	start := strings.Index(s, "{")
	if start < 0 {
		return s
	}
	depth := 0
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return s[start:]
}
