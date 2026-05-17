package action

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestLoggingBannerInjector_InjectBanner_RecordsAndLogs(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	inj := NewLoggingBannerInjector(logger)

	req := BannerInjectRequest{
		Tenant:    "tenant-a",
		Provider:  LabelProviderGmail,
		Email:     "alice@example.com",
		MessageID: "msg-123",
		HTML:      []byte("<div>SN360</div>"),
	}
	if err := inj.InjectBanner(context.Background(), req); err != nil {
		t.Fatalf("InjectBanner: unexpected error %v", err)
	}

	records := inj.Records()
	if len(records) != 1 {
		t.Fatalf("Records: expected 1 record, got %d", len(records))
	}
	got := records[0]
	if got.Tenant != req.Tenant || got.Provider != req.Provider || got.Email != req.Email ||
		got.MessageID != req.MessageID || !bytes.Equal(got.HTML, req.HTML) {
		t.Fatalf("Records[0]: want %+v got %+v", req, got)
	}

	out := buf.String()
	for _, want := range []string{"tenant=tenant-a", "provider=gmail", "email=alice@example.com", "message_id=msg-123", "bytes=16"} {
		if !strings.Contains(out, want) {
			t.Errorf("log output missing %q; got %s", want, out)
		}
	}
}

func TestLoggingBannerInjector_InjectBanner_NilLoggerFallsBackToDefault(t *testing.T) {
	t.Parallel()

	inj := NewLoggingBannerInjector(nil)
	if inj.Logger == nil {
		t.Fatalf("NewLoggingBannerInjector(nil): logger should fall back to slog.Default()")
	}
	if err := inj.InjectBanner(context.Background(), BannerInjectRequest{
		Tenant:    "t",
		Provider:  LabelProviderOutlook,
		Email:     "u@example.com",
		MessageID: "m",
		HTML:      []byte("<p>x</p>"),
	}); err != nil {
		t.Fatalf("InjectBanner: %v", err)
	}
}

func TestLoggingBannerInjector_InjectBanner_RejectsInvalidRequest(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		req  BannerInjectRequest
		want string
	}{
		{
			name: "missing tenant",
			req:  BannerInjectRequest{MessageID: "m", HTML: []byte("x")},
			want: "tenant is required",
		},
		{
			name: "missing message id",
			req:  BannerInjectRequest{Tenant: "t", HTML: []byte("x")},
			want: "message_id is required",
		},
		{
			name: "missing html",
			req:  BannerInjectRequest{Tenant: "t", MessageID: "m"},
			want: "html is required",
		},
	}
	inj := NewLoggingBannerInjector(nil)
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := inj.InjectBanner(context.Background(), tc.req)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("InjectBanner: want error containing %q, got %v", tc.want, err)
			}
			if len(inj.Records()) != 0 && tc.name == "missing tenant" {
				t.Fatalf("Records: invalid request must not be recorded")
			}
		})
	}
}
