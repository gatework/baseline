package comware_test

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gatework/netops/config"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/parse"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/vendors/comware"
)

func extract(tb testing.TB, text string) baseline.Extraction {
	tb.Helper()
	x := comware.New()
	doc, err := config.Parse(tb.Context(), text, x.Dialect(), parse.Limits{})
	if err != nil {
		tb.Fatal(err)
	}
	ex, err := x.Extract(tb.Context(), device.Device{ID: "sw1"}, doc)
	if err != nil {
		tb.Fatal(err)
	}
	return ex
}

func fixture(t *testing.T) baseline.Extraction {
	t.Helper()
	body, err := os.ReadFile("../../testdata/backup/LAB1-10-SW01-192.0.2.11.txt")
	if err != nil {
		t.Fatal(err)
	}
	return extract(t, string(body))
}

func TestExtractor_Extract(t *testing.T) {
	t.Parallel()
	ex := fixture(t)
	p := ex.Posture
	set, ok := p.AAA.Management("")
	tests := []struct {
		name string
		got  any
		want any
	}{
		{"hostname", p.Hostname, "LAB1-10-SW01"},
		{"default domain", p.AAA.Default, "ops"},
		{"management set found", ok, true},
		{"login methods", set.Login.String(), "tacacs:tac > local"},
		{"command accounting", set.CommandAccounting.String(), "tacacs:tac"},
		{"tacacs servers in rank order", baseline.Hosts(p.AAA.Servers(set.Login, "authentication")), []string{"198.51.100.1", "198.51.100.2"}},
		{"tacacs keyed", p.AAA.Servers(set.Login, "authentication")[0].Keyed, true},
		{"syslog in configured order", baseline.Hosts(p.Logging.Hosts), []string{"198.51.100.21", "198.51.100.20"}},
		{"syslog port", p.Logging.Hosts[0].Port, 5141},
		{"syslog source", p.Logging.Source, "Vlan-interface20"},
		{"ntp enabled", p.Time.NTPState, baseline.StateEnabled},
		{"ntp in configured order", baseline.Hosts(p.Time.NTP), []string{"198.51.100.11", "198.51.100.10"}},
		{"timezone", p.Time.Timezone.Offset, 8 * time.Hour},
		{"snmp versions", p.SNMP.Versions, []string{"v2c", "v3"}},
		{"snmp communities", len(p.SNMP.Communities), 2},
		{"snmp acl", p.SNMP.Communities[1].ACL, "2000"},
		{"trap host", baseline.Hosts(p.SNMP.TrapHosts), []string{"198.51.100.30"}},
		{"telnet", p.Services.Telnet.State, baseline.StateEnabled},
		{"ssh", p.Services.SSH.State, baseline.StateEnabled},
		{"http default off", p.Services.HTTP.State, baseline.StateDisabled},
		{"network-class users skipped", len(p.Accounts), 2},
		{"admin hashed", p.Accounts[0].Hashed, true},
		{"admin is admin", p.Accounts[0].Admin, true},
		{"test has no password", p.Accounts[1].PasswordSet, false},
		{"lines", len(p.Lines), 3},
		{"aux defaults to no auth", p.Lines[0].Auth, baseline.LineAuthNone},
		{"vty 0 4 scheme", p.Lines[1].Auth, baseline.LineAuthAAA},
		{"vty 0 4 ssh only", p.Lines[1].Protocols, []string{"ssh"}},
		{"vty 0 4 idle", p.Lines[1].Idle, 30 * time.Minute},
		{"vty 0 4 command authorization", p.Lines[1].CommandAuthorization, true},
		{"vty 5 63 locked", p.Lines[2].Usable(), false},
		{"dot1x", p.NAC.Dot1x, true},
		{"dot1x method", p.NAC.Method, "eap"},
		{"nac domains from ports", p.NAC.Domains, []string{"lab"}},
		{"interfaces", len(p.Interfaces), 3},
		{"edge port", p.Interfaces[0].Edge, true},
		{"vlan 1 default", p.Interfaces[1].AccessVLAN, 1},
		{"trunk", p.Interfaces[2].Mode, baseline.PortTrunk},
		{"acl", p.HasACL("2000"), true},
		{"dialect facet", ex.Coverage.Status(baseline.DialectFacet("comware")), evidence.StatusComplete},
		{"no issues", len(ex.Issues), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if !equal(tt.got, tt.want) {
				t.Errorf("got %v, want %v", tt.got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract_secondaryOnlyScheme(t *testing.T) {
	t.Parallel()
	p := fixture(t).Posture
	g, ok := p.AAA.Group("rad")
	if !ok || len(g.Servers) != 1 || g.Servers[0].Rank != baseline.RankSecondary {
		t.Fatalf("rad = %+v", g)
	}
}

func TestExtractor_Extract_unrecognized(t *testing.T) {
	t.Parallel()
	ex := extract(t, "#\n ntp-service frobnicate 192.0.2.1\n#\nline vty 0 4\n bogus-option secret\n#\n")
	if ex.Coverage.Status(baseline.FacetNTP) != evidence.StatusPartial || ex.Coverage.Status(baseline.FacetLine) != evidence.StatusPartial {
		t.Fatalf("coverage %v", ex.Coverage)
	}
	for _, is := range ex.Issues {
		for _, f := range is.Fields {
			if strings.Contains(f.Value, "192.0.2.1") || strings.Contains(f.Value, "secret") {
				t.Errorf("issue leaks a value: %+v", is)
			}
		}
	}
}

func TestExtractor_Extract_defaultSystemDomain(t *testing.T) {
	t.Parallel()
	p := extract(t, "#\n sysname x\n#\n").Posture
	set, ok := p.AAA.Management("")
	if !ok || set.Login.Remote() || !set.Login.Has(baseline.MethodLocal) {
		t.Fatalf("system domain %+v %v", set, ok)
	}
}

func TestRules(t *testing.T) {
	t.Parallel()
	rules, err := comware.Rules()
	if err != nil || len(rules) == 0 {
		t.Fatalf("rules %d %v", len(rules), err)
	}
}

func FuzzExtract(f *testing.F) {
	body, err := os.ReadFile("../../testdata/backup/LAB1-10-SW01-192.0.2.11.txt")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(body))
	f.Add("#\nline vty 0 4\n idle-timeout x y\n#\n")
	f.Fuzz(func(t *testing.T, text string) {
		ex := extract(t, text)
		if ex.Posture == nil {
			t.Fatal("nil posture")
		}
	})
}

func equal(a, b any) bool {
	switch x := a.(type) {
	case []string:
		y, ok := b.([]string)
		return ok && slices.Equal(x, y)
	}
	return a == b
}
