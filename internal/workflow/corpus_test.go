package workflow_test

import (
	"os"
	"slices"
	"testing"

	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/internal/bootstrap"
)

// TestPrivateCorpus checks a real backup directory kept outside the
// repository (STANDARD TST-3): every configuration must be recognized and
// extracted, and the full-coverage vendors must decode every facet with no
// unrecognized management statement. It prints aggregates only.
func TestPrivateCorpus(t *testing.T) {
	dir := os.Getenv("BASELINE_CORPUS")
	if dir == "" {
		t.Skip("BASELINE_CORPUS not set")
	}
	app, err := bootstrap.Build(bootstrap.Config{Source: dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	xs, err := app.Runner.Extract(t.Context(), device.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	vendors := map[string]int{}
	issues := map[string]int{}
	for _, x := range xs {
		if x.Error != "" {
			t.Errorf("%s: %s", x.Device.Label(), x.Error)
			continue
		}
		vendors[x.Vendor]++
		full := slices.Contains([]string{"comware", "nxos"}, x.Vendor)
		for _, f := range baseline.Facets() {
			if s := x.Extraction.Coverage.Status(f); full && s != evidence.StatusComplete {
				t.Errorf("%s: %s %s", x.Device.Label(), f, s)
			}
		}
		for _, is := range x.Extraction.Issues {
			issues[x.Vendor+" "+is.Fields[1].Value]++
		}
	}
	t.Logf("devices %d, by extractor %v", len(xs), vendors)
	for k, n := range issues {
		t.Logf("unrecognized %6d %s", n, k)
	}
	rep, err := app.Runner.Check(t.Context(), device.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Devices) != len(xs) {
		t.Errorf("check covered %d devices, extract %d", len(rep.Devices), len(xs))
	}
	for _, s := range rep.ByCheck() {
		t.Logf("%-40s %v", s.Check.ID, s.Counts)
	}
}
