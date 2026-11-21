package panos_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gatework/netops/config"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/parse"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/vendors/panos"
)

func TestExtractor_Extract(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("../../testdata/backup/LAB2-FW01-192.0.2.31.txt")
	if err != nil {
		t.Fatal(err)
	}
	x := panos.New()
	doc, err := config.Parse(t.Context(), string(body), x.Dialect(), parse.Limits{})
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
		{"login", set.Login.String(), "tacacs:AAA > local"},
		{"ntp ranks", p.Time.NTP[1].Rank, baseline.RankSecondary},
		{"timezone", p.Time.Timezone.Offset, 8 * time.Hour},
		{"http enabled", p.Services.HTTP.State, baseline.StateEnabled},
		{"telnet disabled", p.Services.Telnet.State, baseline.StateDisabled},
		{"ssh acl", p.Services.SSH.ACL, "permitted-ip"},
		{"community acl", p.SNMP.Communities[0].ACL, "permitted-ip"},
		{"syslog", strings.Join(baseline.Hosts(p.Logging.Hosts), ","), "198.51.100.20"},
		{"line unsupported", ex.Coverage.Status(baseline.FacetLine), evidence.StatusUnsupported},
		{"nac unsupported", ex.Coverage.Status(baseline.FacetNAC), evidence.StatusUnsupported},
		{"secrets masked", strings.Contains(strings.Join(doc.Masked(), "\n"), "EXAMPLEONLY"), false},
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
