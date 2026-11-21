package workflow_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/config"
	"github.com/gatework/netops/device"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/check"
	"github.com/gatework/baseline/internal/workflow"
	"github.com/gatework/baseline/policy"
	"github.com/gatework/baseline/report"
)

type fakeSource map[string]string

func (f fakeSource) Devices(context.Context) ([]device.Device, error) {
	var out []device.Device
	i := 1
	for name := range f {
		out = append(out, device.Device{ID: name, Name: name, Mgmt: netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})})
		i++
	}
	return out, nil
}

func (f fakeSource) Config(_ context.Context, d device.Device) (string, error) {
	if text, ok := f[d.ID]; ok && text != "unreadable" {
		return text, nil
	}
	return "", errors.New("unreadable")
}

// fakeExtractor yields a posture with telnet on when the text says so.
type fakeExtractor struct{}

func (fakeExtractor) Vendor() string          { return "fake" }
func (fakeExtractor) Dialect() config.Dialect { return config.Comware() }
func (fakeExtractor) Extract(_ context.Context, d device.Device, doc *config.Document) (baseline.Extraction, error) {
	p := &baseline.Posture{Device: d, Config: doc}
	if len(doc.Normalized()) > 0 && doc.Normalized()[0] == "telnet server enable" {
		p.Services.Telnet.State = baseline.StateEnabled
	}
	return baseline.NewTally(d.ID, "fake", baseline.FacetService).Result(p), nil
}

type fakeVendors struct{}

func (fakeVendors) For(_ device.Device, text string) (baseline.Extractor, bool) {
	return fakeExtractor{}, text != "unknown"
}

func TestRunner_Check(t *testing.T) {
	t.Parallel()
	cat, err := check.New()
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Decode([]byte(`
layers: [{name: default}]
waivers: [{id: W, scope: [waived], checks: [service.telnet], reason: r, owner: o, expires: 2099-01-01}]
`))
	if err != nil {
		t.Fatal(err)
	}
	src := fakeSource{"open": "telnet server enable", "waived": "telnet server enable", "clean": "", "unknown": "unknown",
		"broken": "unreadable"}
	r, err := workflow.New(src, fakeVendors{}, pol, cat, workflow.Options{Now: func() time.Time { return time.Unix(0, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := r.Check(t.Context(), device.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]report.Status{"open": report.StatusFail, "waived": report.StatusWaived, "clean": report.StatusPass,
		"unknown": report.StatusError, "broken": report.StatusError}
	for _, d := range rep.Devices {
		if got := d.Status(assess.RuleID("service.telnet")); got != want[d.Device.ID] {
			t.Errorf("%s: %s, want %s", d.Device.ID, got, want[d.Device.ID])
		}
		if d.Device.ID == "clean" && d.Status("line.vty_aaa") != report.StatusUnsupported {
			t.Errorf("unsupported facet: %s", d.Status("line.vty_aaa"))
		}
	}
	if rep.Highest() != assess.SeverityHigh || len(rep.Failed()) != 2 {
		t.Errorf("highest %s failed %d", rep.Highest(), len(rep.Failed()))
	}
}

func TestNew_rejectsUnknownChecks(t *testing.T) {
	t.Parallel()
	cat, _ := check.New()
	pol, _ := policy.Decode([]byte("layers: [{name: a, checks: {bogus.check: {}}}]"))
	if _, err := workflow.New(fakeSource{}, fakeVendors{}, pol, cat, workflow.Options{}); !errors.Is(err, policy.ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
}
