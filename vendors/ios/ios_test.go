package ios_test

import (
	"strings"
	"testing"

	"github.com/gatework/netops/config"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/parse"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/vendors/ios"
)

const sample = `Building configuration...
hostname core1
aaa new-model
aaa group server tacacs+ 3A
 server name t1
 server name t2
aaa authentication login default local
aaa authentication login VTY group 3A local
aaa authorization commands 15 VTY group 3A local
clock timezone CST 8 0
username admin privilege 15 secret 9 $9$EXAMPLEONLY
username old privilege 15 password 7 EXAMPLEONLY
no ip http server
ip ssh version 2
ip access-list standard mgmt
 permit 198.51.100.0 0.0.0.255
snmp-server community ops RO mgmt
snmp-server community rw RW
logging host 198.51.100.20 transport udp port 5141
ntp server 198.51.100.10 prefer
ntp server 198.51.100.11
tacacs server t1
 address ipv4 198.51.100.1
 key 7 EXAMPLEONLY
tacacs server t2
 address ipv4 198.51.100.2
 key 7 EXAMPLEONLY
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 20
 spanning-tree portfast
line con 0
line vty 0 4
 login authentication VTY
 transport input all
 access-class mgmt in
line vty 5 15
 transport input ssh
end
`

func TestExtractor_Extract(t *testing.T) {
	t.Parallel()
	x := ios.New()
	doc, err := config.Parse(t.Context(), sample, x.Dialect(), parse.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	ex, err := x.Extract(t.Context(), device.Device{ID: "c1"}, doc)
	if err != nil {
		t.Fatal(err)
	}
	p := ex.Posture
	vty := p.LinesOf(baseline.LineVTY)
	set, _ := p.AAA.Management(vty[0].MethodSet)
	tests := []struct {
		name string
		got  any
		want any
	}{
		{"vty method set", vty[0].MethodSet, "VTY"},
		{"login", set.Login.String(), "tacacs:3A > local"},
		{"servers resolved by name", strings.Join(baseline.Hosts(p.AAA.Servers(set.Login, "authentication")), ","), "198.51.100.1,198.51.100.2"},
		{"keyed", p.AAA.Servers(set.Login, "authentication")[0].Keyed, true},
		{"command authorization", vty[0].CommandAuthorization, true},
		{"telnet through transport all", p.Services.Telnet.State, baseline.StateEnabled},
		{"vty acl", vty[0].ACL, "mgmt"},
		{"sshv1 off", p.Services.SSHv1.State, baseline.StateDisabled},
		{"http off", p.Services.HTTP.State, baseline.StateDisabled},
		{"secret hashed", p.Accounts[0].Hashed, true},
		{"type 7 reversible", p.Accounts[1].Hashed, false},
		{"community acl", p.SNMP.Communities[0].ACL, "mgmt"},
		{"rw community", p.SNMP.Communities[1].Write, true},
		{"prefer first", p.Time.NTP[0].Rank, baseline.RankPrimary},
		{"edge", p.Interfaces[0].Edge, true},
		{"block keys masked", strings.Contains(strings.Join(doc.Masked(), "\n"), "EXAMPLEONLY"), false},
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

func FuzzExtract(f *testing.F) {
	f.Add(sample)
	f.Fuzz(func(t *testing.T, text string) {
		x := ios.New()
		doc, err := config.Parse(t.Context(), text, x.Dialect(), parse.Limits{})
		if err != nil {
			t.Skip()
		}
		if _, err := x.Extract(t.Context(), device.Device{ID: "c1"}, doc); err != nil {
			t.Fatal(err)
		}
	})
}
