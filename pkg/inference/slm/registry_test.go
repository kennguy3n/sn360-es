package slm

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// stubClient is a no-op Client for registry tests.
type stubClient struct{ label string }

func (s *stubClient) Evaluate(_ context.Context, _ dto.EvaluateRequest, _ dto.Tier1Outcome) (dto.Tier2Outcome, error) {
	return dto.Tier2Outcome{ModelName: s.label}, nil
}

func TestRegistry_NewLooksUpRegisteredProvider(t *testing.T) {
	defer resetForTest()
	resetForTest()

	Register("alpha", func(cfg ProviderConfig) (Client, error) {
		return &stubClient{label: "alpha-" + cfg.URL}, nil
	})

	c, err := New(ProviderConfig{Name: "alpha", URL: "https://example.test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	out, err := c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.ModelName != "alpha-https://example.test" {
		t.Fatalf("ModelName: got %q", out.ModelName)
	}
}

func TestRegistry_NewIsCaseInsensitive(t *testing.T) {
	defer resetForTest()
	resetForTest()

	Register("MixedCase", func(cfg ProviderConfig) (Client, error) {
		return &stubClient{label: cfg.Name}, nil
	})

	c, err := New(ProviderConfig{Name: "mixedcase"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	out, _ := c.Evaluate(context.Background(), dto.EvaluateRequest{}, dto.Tier1Outcome{})
	if out.ModelName != "mixedcase" {
		t.Fatalf("expected normalised name, got %q", out.ModelName)
	}
}

func TestRegistry_NewUnknownReturnsTypedError(t *testing.T) {
	defer resetForTest()
	resetForTest()

	Register("alpha", func(_ ProviderConfig) (Client, error) {
		return &stubClient{}, nil
	})

	_, err := New(ProviderConfig{Name: "nope"})
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
	if !errors.Is(err, ErrProviderNotRegistered) {
		t.Fatalf("expected ErrProviderNotRegistered, got %v", err)
	}
	if !strings.Contains(err.Error(), "alpha") {
		t.Errorf("error should list registered providers: %v", err)
	}
}

func TestRegistry_NewEmptyNameReturnsTypedError(t *testing.T) {
	defer resetForTest()
	resetForTest()

	_, err := New(ProviderConfig{Name: ""})
	if !errors.Is(err, ErrProviderNotRegistered) {
		t.Fatalf("expected ErrProviderNotRegistered for empty name, got %v", err)
	}
}

func TestRegistry_DoubleRegistrationPanics(t *testing.T) {
	defer resetForTest()
	resetForTest()

	Register("dupe", func(_ ProviderConfig) (Client, error) {
		return &stubClient{}, nil
	})

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on duplicate Register")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panic payload not a string: %v", r)
		}
		if !strings.Contains(msg, "dupe") {
			t.Errorf("panic message should mention provider name: %s", msg)
		}
	}()
	Register("dupe", func(_ ProviderConfig) (Client, error) {
		return &stubClient{}, nil
	})
}

func TestRegistry_RegisterEmptyNamePanics(t *testing.T) {
	defer resetForTest()
	resetForTest()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on empty name")
		}
	}()
	Register("", func(_ ProviderConfig) (Client, error) { return nil, nil })
}

func TestRegistry_RegisterNilFactoryPanics(t *testing.T) {
	defer resetForTest()
	resetForTest()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on nil factory")
		}
	}()
	Register("name", nil)
}

func TestRegistry_RegisteredListIsSorted(t *testing.T) {
	defer resetForTest()
	resetForTest()

	for _, name := range []string{"charlie", "alpha", "bravo"} {
		Register(name, func(_ ProviderConfig) (Client, error) { return &stubClient{}, nil })
	}
	got := Registered()
	want := []string{"alpha", "bravo", "charlie"}
	if len(got) != len(want) {
		t.Fatalf("len: got %d want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("[%d]: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestRegistry_IsRegistered(t *testing.T) {
	defer resetForTest()
	resetForTest()

	Register("alpha", func(_ ProviderConfig) (Client, error) { return &stubClient{}, nil })
	if !IsRegistered("alpha") {
		t.Error("alpha should be registered")
	}
	if !IsRegistered("ALPHA") {
		t.Error("IsRegistered should be case-insensitive")
	}
	if IsRegistered("beta") {
		t.Error("beta should not be registered")
	}
	if IsRegistered("") {
		t.Error("empty name should not match")
	}
}

func TestRegistry_FactoryErrorPropagates(t *testing.T) {
	defer resetForTest()
	resetForTest()

	sentinel := errors.New("factory bang")
	Register("bang", func(_ ProviderConfig) (Client, error) {
		return nil, sentinel
	})

	_, err := New(ProviderConfig{Name: "bang"})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel propagation, got %v", err)
	}
}

func TestParseProviderOpts(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want map[string]string
	}{
		{"empty", "", nil},
		{"whitespace only", "   \t  ", nil},
		{"single", "k=v", map[string]string{"k": "v"}},
		{"multi", "k1=v1,k2=v2", map[string]string{"k1": "v1", "k2": "v2"}},
		{"with whitespace", " k1 = v1 , k2 = v2 ", map[string]string{"k1": "v1", "k2": "v2"}},
		{"trailing comma", "k=v,", map[string]string{"k": "v"}},
		{"value contains equals", "url=https://example.com/v1", map[string]string{"url": "https://example.com/v1"}},
		{"empty key dropped", "=novalue,k=v", map[string]string{"k": "v"}},
		{"missing equals dropped", "broken,k=v", map[string]string{"k": "v"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseProviderOpts(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("[%s]: got %q want %q", k, got[k], v)
				}
			}
		})
	}
}
