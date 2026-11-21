package check_test

import (
	"slices"
	"testing"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/secret"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/check"
)

func run(t *testing.T, p *baseline.Posture, cov evidence.Coverage, policy string) assess.Assessment {
	t.Helper()
	cat, err := check.New()
	if err != nil {
		t.Fatal(err)
	}
	pol, err := assess.DecodePolicy([]byte(policy))
	if err != nil {
		t.Fatal(err)
	}
	e, err := assess.NewEngine(cat, pol, assess.Options{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := e.Run(t.Context(), p, cov)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func full(t *testing.T) evidence.Coverage {
	t.Helper()
	return baseline.NewTally("d", "comware", baseline.Facets()...).Result(&baseline.Posture{}).Coverage
}

// posture is a compliant device; tests break one aspect at a time.
func posture() *baseline.Posture {
	tac := baseline.MethodList{{Kind: baseline.MethodGroup, Protocol: "tacacs", Group: "tac"}, {Kind: baseline.MethodLocal}}
	ordered := func(hosts ...string) []baseline.Server {
		out := make([]baseline.Server, len(hosts))
		for i, h := range hosts {
			out[i] = baseline.Server{Host: h, Rank: baseline.RankOrdered, Line: 10 + i}
		}
		return out
	}
	return &baseline.Posture{
		Device: device.Device{ID: "d", Name: "sw"},
		AAA: baseline.AAA{Default: "ops",
			Groups: []baseline.ServerGroup{{Name: "tac", Protocol: "tacacs", Servers: []baseline.Server{
				{Host: "10.0.0.1", Rank: baseline.RankPrimary, Keyed: true}, {Host: "10.0.0.2", Rank: baseline.RankSecondary, Keyed: true},
			}}},
			Sets: []baseline.MethodSet{{Name: "ops", Login: tac, Authorization: tac, Commands: tac, Accounting: tac, CommandAccounting: tac[:1]}},
		},
		Logging: baseline.Logging{State: baseline.StateEnabled, Hosts: ordered("10.0.1.1"), Source: "Vlan10"},
		Time: baseline.Time{NTPState: baseline.StateEnabled, NTP: ordered("10.0.2.1", "10.0.2.2"), Source: "Vlan10", Auth: true,
			Timezone: baseline.Timezone{Offset: 8 * 3600e9, Set: true}},
		SNMP: baseline.SNMP{State: baseline.StateEnabled, Versions: []string{"v3"}, Location: "dc1",
			Users: []baseline.SNMPUser{{Name: "ops", Auth: true, Privacy: true}}, TrapHosts: ordered("10.0.3.1")},
		Lines: []baseline.Line{
			{Kind: baseline.LineConsole, Auth: baseline.LineAuthAAA, Idle: 5 * 60e9, IdleSet: true},
			{Kind: baseline.LineVTY, Range: "0 4", Auth: baseline.LineAuthAAA, Protocols: []string{"ssh"}, Idle: 10 * 60e9, IdleSet: true,
				CommandAuthorization: true, CommandAccounting: true},
		},
		Services: baseline.Services{SSH: baseline.Service{State: baseline.StateEnabled, ACL: "2000"}},
		Accounts: []baseline.Account{{Name: "netadmin", PasswordSet: true, Hashed: true, Services: []string{"ssh"}}},
		NAC:      baseline.NAC{Dot1x: true, Method: "eap", Domains: []string{"sha"}},
		Interfaces: []baseline.Interface{
			{Name: "Gi1/0/1", Kind: baseline.InterfacePhysical, Mode: baseline.PortAccess, AccessVLAN: 20, Edge: true, Dot1x: true},
			{Name: "Gi1/0/48", Kind: baseline.InterfacePhysical, Mode: baseline.PortTrunk, Description: "uplink"},
		},
		ACLs: map[string]baseline.ACL{"2000": {Name: "2000", Rules: 1}},
	}
}

func rules(a assess.Assessment) []assess.RuleID {
	var out []assess.RuleID
	for _, f := range a.Findings {
		if !slices.Contains(out, f.Rule) {
			out = append(out, f.Rule)
		}
	}
	slices.Sort(out)
	return out
}

func TestRules_compliantPosture(t *testing.T) {
	t.Parallel()
	a := run(t, posture(), full(t), "")
	if len(a.Findings) != 0 {
		t.Fatalf("findings on a compliant posture: %+v", a.Findings)
	}
}

func TestRules_violations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(p *baseline.Posture)
		policy string
		want   []assess.RuleID
	}{
		{"telnet", func(p *baseline.Posture) { p.Services.Telnet.State = baseline.StateEnabled }, "", []assess.RuleID{"service.telnet"}},
		{"public community", func(p *baseline.Posture) {
			p.SNMP.Communities = []baseline.Community{{Name: secret.New("Public"), ACL: "2000"}}
			p.SNMP.Versions = []string{"v2c"}
		}, "rules: {snmp.v3_only: {enabled: false}}", []assess.RuleID{"snmp.default_community"}},
		{"ntp order", func(p *baseline.Posture) { p.Time.NTP[0], p.Time.NTP[1] = p.Time.NTP[1], p.Time.NTP[0] },
			"rules: {ntp.servers: {params: {servers: [10.0.2.1, 10.0.2.2]}}}", []assess.RuleID{"ntp.servers"}},
		{"ntp order any", func(p *baseline.Posture) { p.Time.NTP[0], p.Time.NTP[1] = p.Time.NTP[1], p.Time.NTP[0] },
			"rules: {ntp.servers: {params: {servers: [10.0.2.1, 10.0.2.2], order: any}}}", nil},
		{"login local first", func(p *baseline.Posture) {
			p.AAA.Sets[0].Login = baseline.MethodList{{Kind: baseline.MethodLocal}}
		}, "", []assess.RuleID{"aaa.login_remote", "aaa.servers"}},
		{"no local fallback", func(p *baseline.Posture) { p.AAA.Sets[0].Login = p.AAA.Sets[0].Login[:1] }, "", []assess.RuleID{"aaa.login_fallback"}},
		{"secondary only", func(p *baseline.Posture) {
			p.AAA.Groups = append(p.AAA.Groups, baseline.ServerGroup{Name: "rad", Servers: []baseline.Server{
				{Host: "x", Rank: baseline.RankSecondary, Function: "authentication"}}})
		}, "", []assess.RuleID{"aaa.server_rank"}},
		{"vty telnet", func(p *baseline.Posture) { p.Lines[1].Protocols = []string{"ssh", "telnet"} }, "", []assess.RuleID{"line.vty_ssh_only"}},
		{"ssh without acl", func(p *baseline.Posture) { p.Services.SSH.ACL = "" }, "", []assess.RuleID{"service.ssh_acl"}},
		{"undefined acl", func(p *baseline.Posture) { p.Services.SSH.ACL = "3000" }, "", []assess.RuleID{"service.ssh_acl"}},
		{"idle never", func(p *baseline.Posture) { p.Lines[0].Idle = 0 }, "", []assess.RuleID{"line.idle_timeout"}},
		{"timezone", func(p *baseline.Posture) { p.Time.Timezone.Offset = 0 }, "", []assess.RuleID{"clock.timezone"}},
		{"forbidden account", func(p *baseline.Posture) { p.Accounts[0].Name = "test123" }, "", []assess.RuleID{"account.forbidden"}},
		{"plain password", func(p *baseline.Posture) { p.Accounts[0].Hashed = false }, "", []assess.RuleID{"account.password_hash"}},
		{"cannot login without password", func(p *baseline.Posture) {
			p.Accounts[0].PasswordSet, p.Accounts[0].Services = false, []string{}
		}, "", nil},
		{"nac domain by region", func(p *baseline.Posture) {}, "rules: {nac.domain: {params: {domain: ckg}}}", []assess.RuleID{"nac.domain"}},
		{"port without nac", func(p *baseline.Posture) { p.Interfaces[0].Dot1x = false }, "", []assess.RuleID{"nac.ports"}},
		{"port exempt by description", func(p *baseline.Posture) {
			p.Interfaces[0].Dot1x, p.Interfaces[0].Description = false, "AP-uplink"
		}, "rules: {nac.ports: {params: {exempt_descriptions: ['ap-*']}}}", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := posture()
			tt.mutate(p)
			if got := rules(run(t, p, full(t), tt.policy)); !slices.Equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRules_unsupportedFacetSkips(t *testing.T) {
	t.Parallel()
	p := posture()
	p.Lines = nil
	cov := baseline.NewTally("d", "panos", baseline.FacetAAA, baseline.FacetService, baseline.FacetACL).Result(p).Coverage
	a := run(t, p, cov, "")
	for _, o := range a.Rules {
		if o.Rule == "line.vty_aaa" && o.State != assess.RuleSkipped {
			t.Fatalf("line.vty_aaa %s, want skipped", o.State)
		}
	}
	for _, f := range a.Findings {
		if f.Rule == "nac.dot1x" {
			t.Fatal("nac.dot1x reported on a vendor without 802.1X")
		}
	}
}

func TestText(t *testing.T) {
	t.Parallel()
	rules, err := check.Text("comware", nil)
	if err != nil || len(rules) != 0 {
		t.Fatalf("empty pack: %v %v", rules, err)
	}
}
