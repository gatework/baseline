package nxos_test

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gatework/netops/config"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/parse"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/vendors/nxos"
)

func extract(tb testing.TB, text string) *baseline.Posture {
	tb.Helper()
	x := nxos.New()
	doc, err := config.Parse(tb.Context(), text, x.Dialect(), parse.Limits{})
	if err != nil {
		tb.Fatal(err)
	}
	ex, err := x.Extract(tb.Context(), device.Device{ID: "leaf1"}, doc)
	if err != nil {
		tb.Fatal(err)
	}
	return ex.Posture
}

func TestExtractor_Extract(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("../../testdata/backup/LAB2-LEF01-192.0.2.21.txt")
	if err != nil {
		t.Fatal(err)
	}
	p := extract(t, string(body))
	set, _ := p.AAA.Management("")
	servers := p.AAA.Servers(set.Login, "authentication")
	tests := []struct {
		name string
		got  any
		want any
	}{
		{"hostname", p.Hostname, "LAB2-LEF01"},
		{"login falls back to local", set.Login.String(), "tacacs:3A > local"},
		{"commands", set.Commands.String(), "tacacs:3A > local"},
		{"accounting covers commands", set.CommandAccounting.String(), "tacacs:3A"},
		{"group order", strings.Join(baseline.Hosts(servers), ","), "198.51.100.1,198.51.100.2"},
		{"group vrf", servers[0].VRF, "management"},
		{"keyed", servers[0].Keyed, true},
		{"prefer ranks first", strings.Join(baseline.Hosts(p.Time.NTP), ","), "198.51.100.11,198.51.100.10"},
		{"timezone", p.Time.Timezone.Offset, time.Duration(0)},
		{"community merged", len(p.SNMP.Communities), 1},
		{"community acl", p.SNMP.Communities[0].ACL, "snmp-acl"},
		{"versions", strings.Join(p.SNMP.Versions, ","), "v2c,v3"},
		{"https via nxapi", p.Services.HTTPS.State, baseline.StateEnabled},
		{"telnet off", p.Services.Telnet.State, baseline.StateDisabled},
		{"accounts", len(p.Accounts), 2},
		{"ops has no password", p.Accounts[1].PasswordSet, false},
		{"vty ssh", strings.Join(p.LinesOf(baseline.LineVTY)[0].Protocols, ","), "ssh"},
		{"vty command authorization is global", p.LinesOf(baseline.LineVTY)[0].CommandAuthorization, true},
		{"console idle", p.LinesOf(baseline.LineConsole)[0].Idle, 5 * time.Minute},
		{"access port", p.Interfaces[0].Mode, baseline.PortAccess},
		{"edge", p.Interfaces[0].Edge, true},
		{"routed by default", p.Interfaces[1].Mode, baseline.PortRouted},
		{"up", p.Interfaces[1].Shutdown, false},
		{"acl", p.HasACL("snmp-acl"), true},
		{"syslog vrf", p.Logging.Hosts[0].VRF, "management"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.got != tt.want {
				t.Errorf("got %v, want %v", tt.got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract_localOnly(t *testing.T) {
	t.Parallel()
	p := extract(t, "hostname x\nusername admin password 5 $5$x role network-admin\n")
	set, ok := p.AAA.Management("")
	if !ok || set.Login.Remote() || !slices.Contains(set.Login, baseline.Method{Kind: baseline.MethodLocal}) {
		t.Fatalf("default set %+v %v", set, ok)
	}
}

func FuzzExtract(f *testing.F) {
	f.Add("aaa group server tacacs+ g\n  server 192.0.2.1\nline vty\n  exec-timeout x\n")
	f.Add("username a password 5 ! role network-admin\nsnmp-server community c group x\n")
	f.Fuzz(func(t *testing.T, text string) {
		if extract(t, text) == nil {
			t.Fatal("nil posture")
		}
	})
}
