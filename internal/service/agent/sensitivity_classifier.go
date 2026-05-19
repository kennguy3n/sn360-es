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

// sensitivityKeywords maps sensitivity tiers to multilingual keyword
// lists. This is a best-effort fallback — the encoder (Tier 1) handles
// multilingual classification properly, and this only activates when
// ML is unavailable.
var sensitivityKeywords = map[Sensitivity][]string{
	SensitivityCritical: {
		// English — Infrastructure access roles
		"database administrator", "dba", "system administrator", "sysadmin",
		"domain admin", "cloud administrator", "infrastructure engineer",
		"devops lead", "sre lead", "network administrator",
		"security administrator", "platform engineer", "root access",
		// Japanese
		"データベース管理者", "システム管理者", "インフラエンジニア", "クラウド管理者",
		// Korean
		"데이터베이스 관리자", "시스템 관리자", "인프라 엔지니어", "클라우드 관리자",
		// Thai
		"ผู้ดูแลระบบฐานข้อมูล", "ผู้ดูแลระบบ",
		// Vietnamese
		"quản trị cơ sở dữ liệu", "quản trị hệ thống", "quản trị viên hạ tầng",
		// Chinese
		"数据库管理员", "系统管理员", "运维工程师", "云管理员", "基础设施工程师",
	},
	SensitivityMax: {
		// English
		"ceo", "cfo", "coo", "cto", "ciso", "founder", "chief executive", "chief financial", "owner",
		// Japanese
		"最高経営責任者", "最高財務責任者", "代表取締役", "社長", "創業者",
		// Korean
		"최고경영자", "최고재무책임자", "대표이사", "창업자",
		// Thai
		"ประธานเจ้าหน้าที่บริหาร", "ประธานเจ้าหน้าที่การเงิน",
		// Vietnamese
		"giám đốc điều hành", "giám đốc tài chính", "tổng giám đốc", "chủ tịch",
		// Chinese
		"首席执行官", "首席财务官", "总裁", "创始人", "董事长",
	},
	SensitivityHigh: {
		// English — Finance / HR / Legal (existing)
		"finance", "treasury", "accounts payable", "accounts receivable", "controller", "bookkeep",
		"human resources", "people ops", "legal", "compliance", "general counsel",

		// English — Technology (sensitive access, not infra-level)
		"site reliability engineer", "security engineer", "security analyst",
		"cloud engineer", "network engineer", "data engineer",

		// English — M&A / Strategy
		"mergers and acquisitions", "m&a", "corporate development", "corp dev",
		"investor relations", "board secretary", "corporate strategy",

		// English — Healthcare / Medical
		"doctor", "physician", "surgeon", "medical director", "chief medical",
		"pharmacist", "clinical director", "medical records", "health information",
		"chief nursing", "nurse manager",

		// English — R&D / Intellectual Property
		"research director", "r&d", "patent", "intellectual property",
		"chief scientist", "chief technology", "data scientist", "ml engineer",

		// Japanese — Finance / HR / Legal (existing)
		"財務", "経理", "人事", "法務", "コンプライアンス",
		// Japanese — Technology
		"データベースエンジニア", "セキュリティエンジニア", "クラウドエンジニア",
		// Japanese — Healthcare
		"医師", "薬剤師", "看護師長", "医療情報",
		// Japanese — M&A
		"経営企画", "事業開発", "投資家向け広報",

		// Korean — Finance / HR / Legal (existing)
		"재무", "회계", "인사", "법무", "컴플라이언스",
		// Korean — Technology
		"보안 엔지니어", "클라우드 엔지니어", "데이터 엔지니어",
		// Korean — Healthcare
		"의사", "약사", "간호부장",
		// Korean — M&A
		"경영기획", "사업개발", "투자자 관계",

		// Thai (existing)
		"การเงิน", "บัญชี", "ทรัพยากรบุคคล", "กฎหมาย",
		// Thai — Healthcare
		"แพทย์", "เภสัชกร", "หัวหน้าพยาบาล",

		// Vietnamese (existing)
		"tài chính", "kế toán", "nhân sự", "pháp lý",
		// Vietnamese — Healthcare
		"bác sĩ", "dược sĩ", "trưởng phòng y tế",
		// Vietnamese — M&A
		"phát triển doanh nghiệp", "quan hệ nhà đầu tư",

		// Chinese (existing)
		"财务", "会计", "人力资源", "法务", "合规",
		// Chinese — Technology
		"安全工程师", "云工程师", "数据工程师",
		// Chinese — Healthcare
		"医生", "药剂师", "护士长", "医疗信息",
		// Chinese — M&A
		"企业发展", "并购", "投资者关系", "董事会秘书",
	},
	SensitivityElevated: {
		// English (existing)
		"executive assistant", "admin assistant", "office manager",
		"procurement", "vendor management", "supplier",

		// English — Technology (supporting roles)
		"devops engineer", "devops", "junior dba", "help desk manager", "it support lead",

		// English — Healthcare (clinical support)
		"nurse", "lab technician", "radiologist", "physical therapist",
		"clinical research", "clinical coordinator",

		// English — Legal (extended)
		"paralegal", "litigation support", "privacy officer", "data protection officer",

		// English — Sales (customer data access)
		"sales director", "account executive", "customer success", "customer data",

		// Japanese (existing)
		"秘書", "調達", "購買", "事務長",
		// Japanese — Healthcare / Legal
		"看護師", "検査技師", "パラリーガル",

		// Korean (existing)
		"비서", "조달", "사무장",
		// Korean — Healthcare / Legal
		"간호사", "검사기사", "법률보조원",

		// Thai (existing)
		"ผู้ช่วยผู้บริหาร", "จัดซื้อ",
		// Thai — Healthcare
		"พยาบาล",

		// Vietnamese (existing)
		"trợ lý giám đốc", "mua sắm", "quản lý nhà cung cấp",
		// Vietnamese — Healthcare
		"y tá", "kỹ thuật viên xét nghiệm",

		// Chinese (existing)
		"行政助理", "采购", "供应商管理", "办公室经理",
		// Chinese — Healthcare / Legal
		"护士", "检验技师", "法律助理",
	},
}

// KeywordClassifyInput applies the same keyword-based heuristic as
// ClassifyUserSensitivity but works with the batch-oriented
// UserClassifyInput shape. Suitable as the Fallback in
// TieredClassifierConfig for low-confidence encoder results.
// Iterates the multilingual sensitivityKeywords map in tier-priority
// order (Max → High → Elevated) and returns the first match.
func KeywordClassifyInput(u UserClassifyInput) Sensitivity {
	hay := strings.ToLower(u.JobTitle + " " + u.Department + " " + u.DisplayName)
	for _, g := range u.GroupNames {
		hay += " " + strings.ToLower(g)
	}
	// Check tiers in descending priority order.
	for _, tier := range []Sensitivity{SensitivityCritical, SensitivityMax, SensitivityHigh, SensitivityElevated} {
		for _, kw := range sensitivityKeywords[tier] {
			if strings.Contains(hay, strings.ToLower(kw)) {
				return tier
			}
		}
	}
	return SensitivityDefault
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

type encoderRoleItem struct {
	Index       int      `json:"index"`
	JobTitle    string   `json:"job_title"`
	Department  string   `json:"department"`
	DisplayName string   `json:"display_name"`
	GroupNames  []string `json:"group_names"`
}

type encoderRoleRequest struct {
	Users []encoderRoleItem `json:"users"`
}

type encoderResponse struct {
	Results []struct {
		Index       int     `json:"index"`
		Sensitivity string  `json:"sensitivity"`
		Confidence  float64 `json:"confidence"`
		Reason      string  `json:"reason"`
	} `json:"results"`
}

// ClassifyBatch sends a batch to the encoder /classify/roles endpoint.
func (c *EncoderSensitivityClassifier) ClassifyBatch(ctx context.Context, users []UserClassifyInput) ([]ClassifyResult, error) {
	if len(users) == 0 {
		return nil, nil
	}
	items := make([]encoderRoleItem, len(users))
	for i, u := range users {
		items[i] = encoderRoleItem{
			Index:       i,
			JobTitle:    u.JobTitle,
			Department:  u.Department,
			DisplayName: u.DisplayName,
			GroupNames:  u.GroupNames,
		}
	}
	body, err := json.Marshal(encoderRoleRequest{Users: items})
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
	Model       string      `json:"model"`
	Messages    []bonsaiMsg `json:"messages"`
	Temperature float64     `json:"temperature"`
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
	encoder       *EncoderSensitivityClassifier
	bonsai        *BonsaiSensitivityClassifier
	fallback      func(UserClassifyInput) Sensitivity
	cache         redis.Cmdable
	escalateBelow float64
	logger        *slog.Logger
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

func buildBonsaiPrompt(users []UserClassifyInput) string {
	var sb strings.Builder
	sb.WriteString(`You are a security role classifier for an email security product. For each user below, classify their organizational sensitivity into one of:
- "critical" — Infrastructure-level access: DBA, System Admin, Domain Admin, Cloud Admin, DevOps Lead, SRE Lead, Network Admin, Security Admin
- "max" — C-suite, board members, founders, owners
- "high" — VP/Director, Finance, Legal, HR, Compliance, M&A, Medical Director, R&D Director, Security Engineer, Data Engineer
- "elevated" — Senior/Manager, Nurse, Paralegal, DevOps Engineer, IT Support Lead, Sales Director
- "default" — Other roles without elevated data access

Consider the user's job title, department, group memberships, and whether the role implies access to production systems, sensitive data, or strategic information. Return JSON only: {"results": [{"index": 0, "sensitivity": "...", "confidence": 0.0-1.0, "reason": "brief reason"}, ...]}

Users:
`)
	for i, u := range users {
		fmt.Fprintf(&sb, "%d. Title: %q, Department: %q, Name: %q\n", i, u.JobTitle, u.Department, u.DisplayName)
	}
	return sb.String()
}

func parseSensitivityString(s string) Sensitivity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SensitivityCritical
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
