package action

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/kennguy3n/sn360-es/pkg/events"
)

type fakeReportPub struct {
	mu       sync.Mutex
	subjects []string
	payloads [][]byte
}

func (f *fakeReportPub) Publish(_ context.Context, subject string, data []byte, _ ...events.PublishOption) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subjects = append(f.subjects, subject)
	f.payloads = append(f.payloads, data)
	return nil
}

type fakeForcedEval struct {
	verdict ReportVerdict
	err     error
}

func (f *fakeForcedEval) ReEvaluateForced(_ context.Context, _, _ string) (ReportVerdict, error) {
	return f.verdict, f.err
}

type fakeRecipients struct{ list []string; err error }

func (f *fakeRecipients) Recipients(_ context.Context, _, _ string) ([]string, error) {
	return f.list, f.err
}

type fakeMultiQuar struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeMultiQuar) Quarantine(_ context.Context, _, _, recipient, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, recipient)
	return nil
}

func TestReportWorkflow_ConfirmedTriggersFanout(t *testing.T) {
	pub := &fakeReportPub{}
	eval := &fakeForcedEval{verdict: ReportVerdict{Confirmed: true, Tier: "high_risk", Score: 92}}
	rec := &fakeRecipients{list: []string{"u1", "u2", "u3"}}
	qu := &fakeMultiQuar{}
	wf, err := NewReportWorkflow(ReportWorkflowConfig{
		Publisher:   pub,
		ReEvaluator: eval,
		Recipients:  rec,
		Quarantiner: qu,
	})
	if err != nil {
		t.Fatalf("NewReportWorkflow: %v", err)
	}
	evt, err := wf.HandleReport(context.Background(), "acme", "msg-1", "rep-1", "trace-1")
	if err != nil {
		t.Fatalf("HandleReport: %v", err)
	}
	if !evt.Confirmed {
		t.Fatalf("expected confirmed")
	}
	if evt.Tier != "high_risk" {
		t.Fatalf("tier: %q", evt.Tier)
	}
	if len(qu.calls) != 3 {
		t.Fatalf("quarantine fan-out calls: %d (want 3)", len(qu.calls))
	}
	if pub.subjects[0] != "es.action.feedback.report_confirmed" {
		t.Fatalf("subject: %q", pub.subjects[0])
	}
}

func TestReportWorkflow_DismissedWhenLowConfidence(t *testing.T) {
	pub := &fakeReportPub{}
	wf, _ := NewReportWorkflow(ReportWorkflowConfig{Publisher: pub})
	evt, err := wf.HandleReport(context.Background(), "acme", "msg-1", "rep-1", "")
	if err != nil {
		t.Fatalf("HandleReport: %v", err)
	}
	if evt.Confirmed {
		t.Fatal("expected dismissed")
	}
	if pub.subjects[0] != "es.action.feedback.report_dismissed" {
		t.Fatalf("subject: %q", pub.subjects[0])
	}
}

func TestReportWorkflow_MultiReportAutoConfirms(t *testing.T) {
	pub := &fakeReportPub{}
	rec := &fakeRecipients{list: []string{"u1"}}
	qu := &fakeMultiQuar{}
	wf, _ := NewReportWorkflow(ReportWorkflowConfig{
		Publisher: pub, Recipients: rec, Quarantiner: qu, AutoConfirmCount: 3,
	})
	for i, who := range []string{"a", "b", "c"} {
		evt, err := wf.HandleReport(context.Background(), "acme", "msg-1", who, "")
		if err != nil {
			t.Fatalf("HandleReport[%d]: %v", i, err)
		}
		if i < 2 && evt.Confirmed {
			t.Fatalf("early confirm at i=%d", i)
		}
		if i == 2 && !evt.Confirmed {
			t.Fatalf("expected confirm at i=2")
		}
	}
}

func TestReportWorkflow_DuplicateReporterDoesNotInflateCount(t *testing.T) {
	wf, _ := NewReportWorkflow(ReportWorkflowConfig{Publisher: &fakeReportPub{}})
	_, _ = wf.HandleReport(context.Background(), "acme", "msg-1", "rep-1", "")
	_, _ = wf.HandleReport(context.Background(), "acme", "msg-1", "rep-1", "")
	n, _ := wf.reports.Get(context.Background(), "acme", "msg-1")
	if n != 1 {
		t.Fatalf("duplicate inflated count: %d", n)
	}
}

func TestReportWorkflow_RejectsInvalid(t *testing.T) {
	wf, _ := NewReportWorkflow(ReportWorkflowConfig{Publisher: &fakeReportPub{}})
	if _, err := wf.HandleReport(context.Background(), "", "msg", "rep", ""); err == nil {
		t.Fatal("expected error for missing tenant")
	}
	if _, err := wf.HandleReport(context.Background(), "acme", "", "rep", ""); err == nil {
		t.Fatal("expected error for missing message")
	}
}

func TestReportWorkflow_PublishesEvenWhenReevalFails(t *testing.T) {
	pub := &fakeReportPub{}
	wf, _ := NewReportWorkflow(ReportWorkflowConfig{
		Publisher: pub,
		ReEvaluator: &fakeForcedEval{err: errors.New("model down")},
	})
	evt, err := wf.HandleReport(context.Background(), "acme", "msg-1", "rep-1", "")
	if err != nil {
		t.Fatalf("HandleReport: %v", err)
	}
	if evt.Confirmed {
		t.Fatal("expected dismissed when re-eval fails and no quorum")
	}
}
