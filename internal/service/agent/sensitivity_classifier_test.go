package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTieredSensitivityClassifier_EncoderOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := encoderResponse{
			Results: []struct {
				Sensitivity string  `json:"sensitivity"`
				Confidence  float64 `json:"confidence"`
			}{
				{Sensitivity: "max", Confidence: 0.95},
				{Sensitivity: "high", Confidence: 0.85},
				{Sensitivity: "default", Confidence: 0.92},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	encoder := NewEncoderSensitivityClassifier(srv.URL+"/classify/roles", nil, 5*time.Second, nil)
	classifier := NewTieredSensitivityClassifier(TieredClassifierConfig{
		Encoder: encoder,
	})

	inputs := []UserClassifyInput{
		{JobTitle: "最高財務責任者", Department: "Finance", DisplayName: "田中太郎"},
		{JobTitle: "Giám đốc tài chính", Department: "Finance", DisplayName: "Nguyen Van A"},
		{JobTitle: "Engineer", Department: "Engineering", DisplayName: "John Doe"},
	}

	results, err := classifier.ClassifyBatch(context.Background(), inputs)
	if err != nil {
		t.Fatalf("ClassifyBatch: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	if results[0].Sensitivity != SensitivityMax {
		t.Errorf("results[0].Sensitivity = %v, want max", results[0].Sensitivity)
	}
	if results[1].Sensitivity != SensitivityHigh {
		t.Errorf("results[1].Sensitivity = %v, want high", results[1].Sensitivity)
	}
}

func TestTieredSensitivityClassifier_FallbackOnly(t *testing.T) {
	fallback := func(input UserClassifyInput) Sensitivity {
		if input.IsAdmin {
			return SensitivityElevated
		}
		return SensitivityDefault
	}

	classifier := NewTieredSensitivityClassifier(TieredClassifierConfig{
		Fallback: fallback,
	})

	inputs := []UserClassifyInput{
		{JobTitle: "CEO", IsAdmin: true},
		{JobTitle: "Intern", IsAdmin: false},
	}

	results, err := classifier.ClassifyBatch(context.Background(), inputs)
	if err != nil {
		t.Fatalf("ClassifyBatch: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if results[0].Sensitivity != SensitivityElevated {
		t.Errorf("admin result = %v, want elevated", results[0].Sensitivity)
	}
	if results[1].Sensitivity != SensitivityDefault {
		t.Errorf("non-admin result = %v, want default", results[1].Sensitivity)
	}
}

func TestTieredSensitivityClassifier_IsAdminBoost(t *testing.T) {
	fallback := func(input UserClassifyInput) Sensitivity {
		return SensitivityDefault
	}

	classifier := NewTieredSensitivityClassifier(TieredClassifierConfig{
		Fallback: fallback,
	})

	inputs := []UserClassifyInput{
		{JobTitle: "IT Support", IsAdmin: true},
	}

	results, err := classifier.ClassifyBatch(context.Background(), inputs)
	if err != nil {
		t.Fatalf("ClassifyBatch: %v", err)
	}
	if results[0].Sensitivity < SensitivityElevated {
		t.Errorf("IsAdmin user sensitivity = %v, want >= elevated", results[0].Sensitivity)
	}
}

func TestTieredSensitivityClassifier_BonsaiEscalation(t *testing.T) {
	encoderSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := encoderResponse{
			Results: []struct {
				Sensitivity string  `json:"sensitivity"`
				Confidence  float64 `json:"confidence"`
			}{
				{Sensitivity: "default", Confidence: 0.4},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer encoderSrv.Close()

	bonsaiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := bonsaiResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{
				{Message: struct {
					Content string `json:"content"`
				}{Content: `{"results":[{"index":0,"sensitivity":"high","confidence":0.88}]}`}},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer bonsaiSrv.Close()

	encoder := NewEncoderSensitivityClassifier(encoderSrv.URL+"/classify/roles", nil, 5*time.Second, nil)
	bonsai := NewBonsaiSensitivityClassifier(bonsaiSrv.URL, nil, 30*time.Second, nil)
	classifier := NewTieredSensitivityClassifier(TieredClassifierConfig{
		Encoder: encoder,
		Bonsai:  bonsai,
	})

	inputs := []UserClassifyInput{
		{JobTitle: "ผู้อำนวยการฝ่ายการเงิน", Department: "Finance"},
	}

	results, err := classifier.ClassifyBatch(context.Background(), inputs)
	if err != nil {
		t.Fatalf("ClassifyBatch: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Sensitivity != SensitivityHigh {
		t.Errorf("bonsai escalation result = %v, want high", results[0].Sensitivity)
	}
}

func TestEncoderSensitivityClassifier_MultilingualTitles(t *testing.T) {
	tests := []struct {
		title    string
		language string
		want     Sensitivity
	}{
		{"最高財務責任者", "Japanese CFO", SensitivityMax},
		{"대표이사", "Korean CEO", SensitivityMax},
		{"المدير المالي", "Arabic CFO", SensitivityMax},
		{"Giám đốc tài chính", "Vietnamese CFO", SensitivityMax},
		{"ผู้อำนวยการฝ่ายการเงิน", "Thai Finance Director", SensitivityHigh},
	}

	for _, tt := range tests {
		t.Run(tt.language, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp := encoderResponse{
					Results: []struct {
						Sensitivity string  `json:"sensitivity"`
						Confidence  float64 `json:"confidence"`
					}{
						{Sensitivity: tt.want.String(), Confidence: 0.92},
					},
				}
				_ = json.NewEncoder(w).Encode(resp)
			}))
			defer srv.Close()

			encoder := NewEncoderSensitivityClassifier(srv.URL+"/classify/roles", nil, 5*time.Second, nil)
			results, err := encoder.ClassifyBatch(context.Background(), []UserClassifyInput{
				{JobTitle: tt.title, Department: "Finance"},
			})
			if err != nil {
				t.Fatalf("ClassifyBatch: %v", err)
			}
			if results[0].Sensitivity != tt.want {
				t.Errorf("got %v, want %v", results[0].Sensitivity, tt.want)
			}
		})
	}
}

func TestParseSensitivityString(t *testing.T) {
	tests := []struct {
		input string
		want  Sensitivity
	}{
		{"max", SensitivityMax},
		{"MAX", SensitivityMax},
		{"high", SensitivityHigh},
		{"elevated", SensitivityElevated},
		{"default", SensitivityDefault},
		{"unknown", SensitivityDefault},
		{"", SensitivityDefault},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseSensitivityString(tt.input)
			if got != tt.want {
				t.Errorf("parseSensitivityString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"wrapped", `here is the json: {"key":"val"}`, `{"key":"val"}`},
		{"bare", `{"a":1}`, `{"a":1}`},
		{"none", `no json here`, `no json here`},
		{"nested", `prefix {"nested":{"x":1}} suffix`, `{"nested":{"x":1}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractJSON(tt.input)
			if got != tt.want {
				t.Errorf("extractJSON(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
