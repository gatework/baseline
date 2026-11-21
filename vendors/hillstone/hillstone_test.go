package hillstone_test

import (
	"strings"
	"testing"

	"github.com/gatework/netops/config"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/parse"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/vendors/hillstone"
)

const sample = `show configuration running
# global configuration version: 1
hostname "fw1"
aaa-server "tacacs" type tacacs+
  host 198.51.100.1 vrouter "mgt-vr"
  backup1 198.51.100.2 vrouter "mgt-vr"
  secret EXAMPLEONLY
exit
admin authorization-mode aaa-server "tacacs"
admin host any telnet
admin host 198.51.100.0/24 ssh
admin user "ops"
  password EXAMPLEONLY
  role "admin"
  access ssh
exit
interface MGT0 local
  manage ssh
  manage telnet
exit
logging syslog "198.51.100.20" vrouter "mgt-vr" udp 5145 type event
ntp enable
ntp server "198.51.100.10" vrouter "mgt-vr" source MGT0 prefer
clock zone china
snmp-server manager
snmp-server host 198.51.100.30 version 2c community EXAMPLEONLY ro
End
`

func TestExtractor_Extract(t *testing.T) {
	t.Parallel()
	x := hillstone.New()
	doc, err := config.Parse(t.Context(), sample, x.Dialect(), parse.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	ex, err := x.Extract(t.Context(), device.Device{ID: "fw1"}, doc)
	if err != nil {
		t.Fatal(err)
	}
	p := ex.Posture
	set, _ := p.AAA.Management("")
	tests := []struct {
		name string
		got  any
		want any
	}{
		{"login", set.Login.String(), "tacacs:tacacs > local"},
		{"backup1 is secondary", p.AAA.Groups[0].Servers[1].Rank, baseline.RankSecondary},
		{"telnet managed", p.Services.Telnet.State, baseline.StateEnabled},
		{"telnet from any", p.Services.Telnet.ACL, ""},
		{"ssh restricted", p.Services.SSH.ACL, "admin-host"},
		{"community acl", p.SNMP.Communities[0].ACL, "snmp-manager"},
		{"timezone", p.Time.Timezone.Set, true},
		{"no secret in mask", strings.Contains(strings.Join(doc.Masked(), "\n"), "EXAMPLEONLY"), false},
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
