package policy_test

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/device"

	"github.com/gatework/baseline/policy"
)

var known = []assess.RuleID{"ntp.servers", "nac.domain", "nac.dot1x", "nac.ports", "service.telnet", "text.comware.stp"}

const doc = `
vars:
  ntp:
    by: region
    values: {tst: [10.0.0.1, 10.0.0.2], lab: [10.1.0.1]}
    default: [10.9.0.1]
layers:
  - name: default
    checks:
      ntp.servers: {params: {servers: "${ntp}", order: strict}}
      nac.domain: {params: {domain: "${region}"}}
  - name: datacenter
    scope: ["role=leaf", "role=border"]
    disable: ["nac.*"]
  - name: tst-lab
    scope: ["region=tst"]
    except: ["*-PROD-*"]
    checks:
      ntp.servers: {severity: low, params: {order: any}}
waivers:
  - id: W-1
    scope: ["TST2-FW*"]
    checks: ["service.*"]
    reason: legacy jump host
    owner: netops
    expires: 2026-12-31
  - id: W-2
    checks: ["text.comware.*"]
    subject: "*block:stp*"
    reason: old
    owner: netops
    expires: 2026-01-01
`

func decode(t *testing.T) *policy.Policy {
	t.Helper()
	p, err := policy.Decode([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(known); err != nil {
		t.Fatal(err)
	}
	return p
}

func dev(name, region, role string) device.Device {
	return device.Device{ID: name, Name: name, Mgmt: netip.MustParseAddr("192.0.2.1"), Role: role,
		Labels: map[string]string{"region": region}}
}

func TestPolicy_Resolve(t *testing.T) {
	t.Parallel()
	p := decode(t)
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		d        device.Device
		layers   []string
		servers  []any
		order    string
		domain   string
		nacOff   bool
		severity assess.Severity
	}{
		{"tst access", dev("TST2-1-SW01", "tst", "sw"), []string{"default", "tst-lab"}, []any{"10.0.0.1", "10.0.0.2"}, "any", "tst", false, assess.SeverityLow},
		{"tst prod excluded", dev("TST2-PROD-SW01", "tst", "sw"), []string{"default"}, []any{"10.0.0.1", "10.0.0.2"}, "strict", "tst", false, assess.SeverityUnset},
		{"lab leaf", dev("LAB3-LEF01", "lab", "leaf"), []string{"default", "datacenter"}, []any{"10.1.0.1"}, "strict", "lab", true, assess.SeverityUnset},
		{"unknown region", dev("X", "", ""), []string{"default"}, []any{"10.9.0.1"}, "strict", "", false, assess.SeverityUnset},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, err := p.Resolve(tt.d, now, known)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(r.Layers, tt.layers) {
				t.Errorf("layers %v", r.Layers)
			}
			ntp := r.Policy.Rules["ntp.servers"]
			if got, _ := ntp.Params["servers"].([]any); !slices.Equal(got, tt.servers) {
				t.Errorf("servers %v", ntp.Params["servers"])
			}
			if ntp.Params["order"] != tt.order || ntp.Severity != tt.severity {
				t.Errorf("ntp %+v", ntp)
			}
			if r.Policy.Rules["nac.domain"].Params["domain"] != tt.domain {
				t.Errorf("domain %v", r.Policy.Rules["nac.domain"].Params["domain"])
			}
			off := r.Policy.Rules["nac.dot1x"].Enabled != nil && !*r.Policy.Rules["nac.dot1x"].Enabled
			if off != tt.nacOff {
				t.Errorf("nac.dot1x disabled = %v", off)
			}
		})
	}
}

func TestResolved_Waiver(t *testing.T) {
	t.Parallel()
	p := decode(t)
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	fw := dev("TST2-FW01", "tst", "fw")
	r, err := p.Resolve(fw, now, known)
	if err != nil {
		t.Fatal(err)
	}
	if w, ok := r.Waiver(assess.Finding{Rule: "service.telnet", Subject: assess.NewSubject("device", "x")}); !ok || w.ID != "W-1" {
		t.Errorf("W-1 not applied: %v", ok)
	}
	if _, ok := r.Waiver(assess.Finding{Rule: "ntp.servers"}); ok {
		t.Error("waiver applied to another check")
	}
	if !slices.Equal(r.Expired, []string{"W-2"}) {
		t.Errorf("expired %v", r.Expired)
	}
	later, _ := p.Resolve(fw, now.AddDate(0, 2, 0), known)
	if _, ok := later.Waiver(assess.Finding{Rule: "service.telnet"}); ok {
		t.Error("expired waiver applied")
	}
}

func TestDecode_invalid(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"unknown field":     "layers: []\nbogus: 1\n",
		"duplicate layer":   "layers: [{name: a}, {name: a}]\n",
		"bad selector":      "layers: [{name: a, scope: ['frobnicate=x']}]\n",
		"waiver no reason":  "layers: []\nwaivers: [{id: w, checks: ['*'], owner: o, expires: 2026-01-01}]\n",
		"waiver bad date":   "layers: []\nwaivers: [{id: w, checks: ['*'], reason: r, owner: o, expires: soon}]\n",
		"lookup by unknown": "vars: {x: {by: colour, values: {}}}\nlayers: []\n",
		"text rule regexp":  "layers: []\ntext_rules: [{dialect: comware, rules: [{id: a, title: a, forbid: ['(']}]}]\n",
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := policy.Decode([]byte(body)); !errors.Is(err, policy.ErrInvalid) {
				t.Errorf("err = %v", err)
			}
		})
	}
}

func TestPolicy_Validate(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"unknown check": "layers: [{name: a, checks: {nope.x: {}}}]\n",
		"dead glob":     "layers: [{name: a, disable: ['nope.*']}]\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p, err := policy.Decode([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Validate(known); !errors.Is(err, policy.ErrInvalid) {
				t.Errorf("err = %v", err)
			}
		})
	}
}

func TestPolicy_TextRules(t *testing.T) {
	t.Parallel()
	p, err := policy.Decode([]byte("layers: []\ntext_rules: [{dialect: comware, rules: [{id: banner, title: banner, require: ['^header ']}]}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.TextRules()["comware"]; len(got) != 1 || got[0].ID != "banner" {
		t.Fatalf("text rules %+v", got)
	}
}
