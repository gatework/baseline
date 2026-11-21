package report_test

import (
	"testing"
	"time"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/device"

	"github.com/gatework/baseline/report"
)

func TestDevice_Status(t *testing.T) {
	t.Parallel()
	d := report.Device{
		Rules: []assess.RuleOutcome{
			{Rule: "a", State: assess.RuleRan}, {Rule: "b", State: assess.RuleRan}, {Rule: "c", State: assess.RuleRan},
			{Rule: "d", State: assess.RuleSkipped}, {Rule: "e", State: assess.RuleDisabled}, {Rule: "f", State: assess.RuleFailed},
		},
		Results: []report.Result{
			{Finding: assess.Finding{Rule: "a", Severity: assess.SeverityHigh}},
			{Finding: assess.Finding{Rule: "b", Severity: assess.SeverityCritical}, Waiver: &report.Waiver{ID: "w"}},
		},
	}
	want := map[assess.RuleID]report.Status{"a": report.StatusFail, "b": report.StatusWaived, "c": report.StatusPass,
		"d": report.StatusUnsupported, "e": report.StatusDisabled, "f": report.StatusError}
	for id, s := range want {
		if got := d.Status(id); got != s {
			t.Errorf("%s: got %s, want %s", id, got, s)
		}
	}
	r := report.New(time.Unix(0, 0), []assess.Meta{{ID: "a"}}, []report.Device{d, {Device: device.Device{ID: "x"}, Error: "read_failed"}})
	if r.Highest() != assess.SeverityHigh || r.Compliant() != 0 || len(r.Failed()) != 1 {
		t.Errorf("highest %s compliant %d failed %d", r.Highest(), r.Compliant(), len(r.Failed()))
	}
}
