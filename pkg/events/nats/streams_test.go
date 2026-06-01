package nats

import "testing"

// TestStreamForSubject_CoversAllDefaultStreamSpecs pins the DLQ-replay
// routing table. The docstring on StreamForSubject states "must stay in
// sync with DefaultStreamSpecs" — without this test the contract was
// purely advisory, which is exactly how the WS-4a es.management.>
// stream landed in DefaultStreamSpecs without the matching switch arm
// in StreamForSubject. The asymmetry was caught in Devin Review on
// PR #61 round 2: failed es.management.comm_history.update messages
// would land in the DLQ but the DLQ-replay router would return ""
// (unrouted), silently dropping the replay.
//
// Every stream declared in DefaultStreamSpecs must have a
// representative subject below; new streams added to DefaultStreamSpecs
// must extend this table. The "unrouted" cases at the bottom prevent a
// future edit from accidentally widening the prefix match (e.g.
// matching "es.evaluate." instead of "es.evaluate.request." and
// silently steering result publishes to the request stream).
func TestStreamForSubject_CoversAllDefaultStreamSpecs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		subject string
		want    string
	}{
		{"dlq root", "es.dlq.foo", StreamDLQ},
		{"dlq nested", "es.dlq.evaluate.request", StreamDLQ},
		{"evaluate.result exact", "es.evaluate.result", StreamEvaluateResult},
		{"evaluate.result.<tenant>", "es.evaluate.result.tenant-1", StreamEvaluateResult},
		{"evaluate.request exact", "es.evaluate.request", StreamEvaluate},
		{"evaluate.request.<tenant>", "es.evaluate.request.tenant-1", StreamEvaluate},
		{"onboarding", "es.onboarding.tenant.created", StreamOnboarding},
		{"education", "es.education.send", StreamEducation},
		{"action", "es.action.deliver", StreamAction},
		{"management WS-4a comm_history.update", "es.management.comm_history.update", StreamManagement},
		{"management future subjects", "es.management.something.else", StreamManagement},

		// Negative cases: subjects outside the declared mapping must
		// return "" so DLQ replay surfaces the routing miss instead
		// of silently steering messages to a stream that won't accept
		// them.
		{"unrouted: bare es.evaluate", "es.evaluate", ""},
		{"unrouted: es.evaluate.status (hypothetical)", "es.evaluate.status", ""},
		{"unrouted: empty", "", ""},
		{"unrouted: foreign prefix", "foo.bar.baz", ""},
		{"unrouted: prefix collision (es.managementx)", "es.managementx.foo", ""},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := StreamForSubject(c.subject); got != c.want {
				t.Fatalf("StreamForSubject(%q) = %q, want %q", c.subject, got, c.want)
			}
		})
	}
}
