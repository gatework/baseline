package alteon_test

import (
	"strings"
	"testing"

	"github.com/gatework/netops/config"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/parse"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/vendors/alteon"
)

const sample = "/cfg/dump\nscript start \"Alteon\" 4  /**** DO NOT EDIT THIS LINE!\n/c/sys/ntp\n\ton\n\tprisrv 198.51.100.10\n" +
	"\tsecsrv 198.51.100.11\n\ttzone +00:00\n/c/sys/access\n\tsnmp w\n/c/sys/access/mgmt/add 198.51.100.0 255.255.255.0 ssh|snmp\n" +
	"/c/sys/ssnmp\n\trcomm \"EXAMPLEONLY\"\n/c/sys/tacacs\n\tprisrv 198.51.100.1\n\tesecret EXAMPLEONLY\n\ton\n" +
	"/c/sys/syslog\n\thst1 198.51.100.20 6 6 all 514\n/c/sys/access/sshd/on\n/c/sys/access/tnet ena\nscript end\n"

func TestExtractor_Extract(t *testing.T) {
	t.Parallel()
	x := alteon.New()
	doc, err := config.Parse(t.Context(), sample, x.Dialect(), parse.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	ex, err := x.Extract(t.Context(), device.Device{ID: "lb1"}, doc)
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
		{"ntp secondary", p.Time.NTP[1].Rank, baseline.RankSecondary},
		{"utc timezone", p.Time.Timezone.Offset.String(), "0s"},
		{"write community applied after ssnmp", p.SNMP.Communities[0].Write, true},
		{"community acl", p.SNMP.Communities[0].ACL, "mgmt-access"},
		{"ssh acl", p.Services.SSH.ACL, "mgmt-access"},
		{"telnet", p.Services.Telnet.State, baseline.StateEnabled},
		{"syslog", p.Logging.Hosts[0].Port, 514},
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
