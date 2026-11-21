package hillstone

import (
	"context"
	"slices"
	"strings"

	"github.com/gatework/netops/config"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/parse"
	"github.com/gatework/netops/secret"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/internal/mgmt"
	"github.com/gatework/baseline/internal/token"
	"github.com/gatework/baseline/internal/tz"
)

// Name is the vendor key of this extractor.
const Name = "hillstone"

// aclAdminHost is the pseudo ACL that "admin host" entries form.
const aclAdminHost = "admin-host"

// zones maps StoneOS clock zone names to offsets.
var zones = map[string]string{"china": "+08:00", "beijing": "+08:00", "utc": "+00:00", "gmt": "+00:00"}

// Extractor decodes StoneOS configurations. It is stateless and safe for
// concurrent use.
type Extractor struct{}

// New returns a Hillstone extractor.
func New() *Extractor { return &Extractor{} }

// Vendor returns "hillstone".
func (*Extractor) Vendor() string { return Name }

// Dialect returns the StoneOS dialect: blocks end in "exit", "#" starts a
// comment.
func (*Extractor) Dialect() config.Dialect {
	d := config.Cisco()
	d.Name = Name
	d.Comments = []string{"!", "#"}
	d.Terminators = []string{"exit", "End", "end"}
	d.Sensitive = append(d.Sensitive, mgmt.Sensitive("secret", "community", "password", "key", "value")...)
	return d
}

// Extract builds the posture of d from doc.
func (*Extractor) Extract(ctx context.Context, d device.Device, doc *config.Document) (baseline.Extraction, error) {
	p := &baseline.Posture{Device: d, Config: doc, ACLs: map[string]baseline.ACL{}}
	p.AAA.Default = "admin"
	p.Logging.State = baseline.StateEnabled
	p.Time.NTPState = baseline.StateDisabled
	p.SNMP.State = baseline.StateDisabled
	tally := baseline.NewTally(d.ID, Name, mgmt.Facets()...)
	x := &extraction{p: p, hosts: map[string][]string{}, manage: map[string]int{}}
	for i, n := range doc.Root().Children {
		if i%256 == 0 && ctx.Err() != nil {
			return baseline.Extraction{}, ctx.Err()
		}
		x.statement(n)
	}
	x.finish()
	return tally.Result(p), nil
}

type extraction struct {
	p      *baseline.Posture
	hosts  map[string][]string // admin host sources by protocol
	manage map[string]int      // protocol to the line of an interface managing it
	authz  string              // aaa-server used for admin logins
}

func (x *extraction) statement(n *parse.Node) {
	w := token.Split(n.Text)
	switch {
	case w.Prefix("hostname"):
		x.p.Hostname = w.At(1)
	case w.Prefix("Version"), w.Prefix("version"):
		x.p.Version = w.At(1)
	case w.Prefix("aaa-server") && len(n.Children) > 0:
		x.aaaServer(n, w)
	case w.Prefix("admin", "authorization-mode", "aaa-server"), w.Prefix("admin", "auth-server"):
		x.authz = w.At(len(w) - 1)
	case w.Prefix("admin", "host"):
		x.hosts[w.At(3)] = append(x.hosts[w.At(3)], w.At(2))
	case w.Prefix("admin", "user"):
		x.account(n, w)
	case w.Prefix("interface"):
		for _, c := range n.Children {
			if cw := token.Split(c.Text); cw.Prefix("manage") {
				x.manage[cw.At(1)] = c.Line.Number
			}
		}
	case w.Prefix("logging", "syslog"):
		host := w.At(2)
		if !slices.ContainsFunc(x.p.Logging.Hosts, func(s baseline.Server) bool { return s.Host == host }) {
			s := baseline.Server{Host: host, Rank: baseline.RankOrdered, Line: n.Line.Number}
			s.VRF, _ = w.After("vrouter")
			s.Port = w.Int("udp")
			x.p.Logging.Hosts = append(x.p.Logging.Hosts, s)
		}
	case w.Prefix("ntp", "enable"):
		x.p.Time.NTPState = baseline.StateEnabled
	case w.Prefix("ntp", "server"):
		s := baseline.Server{Host: w.At(2), Rank: baseline.RankOrdered, Keyed: w.Has("key"), Line: n.Line.Number}
		s.VRF, _ = w.After("vrouter")
		s.Source, _ = w.After("source")
		if w.Has("prefer") {
			s.Rank = baseline.RankPrimary
		}
		x.p.Time.NTP = append(x.p.Time.NTP, s)
	case w.Prefix("ntp", "authentication"):
		x.p.Time.Auth = true
	case w.Prefix("clock", "zone"):
		if off, ok := zones[strings.ToLower(w.At(2))]; ok {
			d, _ := tz.ParseFormat(off)
			x.p.Time.Timezone = baseline.Timezone{Name: w.At(2), Offset: d, Set: true, Line: n.Line.Number}
		}
	case w.Prefix("snmp-server"):
		x.snmp(n, w)
	}
}

// aaaServer decodes "aaa-server NAME type T" blocks: host is the primary,
// backup1 the secondary, backup2 the next.
func (x *extraction) aaaServer(n *parse.Node, w token.Words) {
	kind, _ := w.After("type")
	proto := strings.TrimSuffix(kind, "+")
	if proto != "tacacs" && proto != "radius" {
		return
	}
	g := baseline.ServerGroup{Name: w.At(1), Protocol: proto, Line: n.Line.Number}
	keyed := false
	for _, c := range n.Children {
		cw := token.Split(c.Text)
		rank := map[string]baseline.Rank{"host": baseline.RankPrimary, "backup1": baseline.RankSecondary, "backup2": baseline.RankOrdered}
		if r, ok := rank[cw.At(0)]; ok {
			s := baseline.Server{Host: cw.At(1), Rank: r, Line: c.Line.Number}
			s.VRF, _ = cw.After("vrouter")
			g.Servers = append(g.Servers, s)
		}
		keyed = keyed || cw.At(0) == "secret"
	}
	for i := range g.Servers {
		g.Servers[i].Keyed = keyed
	}
	x.p.AAA.Groups = append(x.p.AAA.Groups, g)
}

// account decodes "admin user NAME" blocks.
func (x *extraction) account(n *parse.Node, w token.Words) {
	a := baseline.Account{Name: w.At(2), Services: []string{}, Line: n.Line.Number}
	for _, c := range n.Children {
		cw := token.Split(c.Text)
		switch cw.At(0) {
		case "password":
			a.PasswordSet, a.Hashed = true, true
		case "role":
			a.Roles = append(a.Roles, cw.At(1))
			a.Admin = a.Admin || cw.At(1) == "admin"
		case "access":
			a.Services = append(a.Services, cw.At(1))
		}
	}
	x.p.Accounts = append(x.p.Accounts, a)
}

// snmp decodes snmp-server statements; "host" entries are the managers
// allowed to poll, which form the community's ACL.
func (x *extraction) snmp(n *parse.Node, w token.Words) {
	s := &x.p.SNMP
	switch {
	case w.Prefix("snmp-server", "manager"):
		s.State = baseline.StateEnabled
	case w.Prefix("snmp-server", "host"):
		v, _ := w.After("version")
		name, _ := w.After("community")
		if v == "" {
			v = "v3"
		}
		if !strings.HasPrefix(v, "v") {
			v = "v" + v
		}
		if !slices.Contains(s.Versions, v) {
			s.Versions = append(s.Versions, v)
		}
		if name != "" && !slices.ContainsFunc(s.Communities, func(c baseline.Community) bool { return c.Name.Reveal() == name }) {
			s.Communities = append(s.Communities, baseline.Community{
				Name: secret.New(name), Write: w.Has("rw"), ACL: "snmp-manager", Line: n.Line.Number,
			})
		}
		acl := x.p.ACLs["snmp-manager"]
		acl.Name, acl.Rules, acl.Line = "snmp-manager", acl.Rules+1, n.Line.Number
		x.p.ACLs["snmp-manager"] = acl
	case w.Prefix("snmp-server", "trap-host"):
		s.TrapHosts = append(s.TrapHosts, baseline.Server{Host: w.At(2), Rank: baseline.RankOrdered, Line: n.Line.Number})
	case w.Prefix("snmp-server", "user"):
		s.Users = append(s.Users, baseline.SNMPUser{Name: w.At(2), Auth: w.Has("authentication"), Privacy: w.Has("encryption"),
			Line: n.Line.Number})
	case w.Prefix("snmp-server", "location"):
		s.Location = strings.Join(w.From(2), " ")
	case w.Prefix("snmp-server", "contact"):
		s.Contact = strings.Join(w.From(2), " ")
	}
}

func (x *extraction) finish() {
	if x.authz != "" {
		if g, ok := x.p.AAA.Group(x.authz); ok {
			list := baseline.MethodList{{Kind: baseline.MethodGroup, Protocol: g.Protocol, Group: g.Name}, {Kind: baseline.MethodLocal}}
			x.p.AAA.Sets = append(x.p.AAA.Sets, baseline.MethodSet{Name: "admin", Login: list, Authorization: list})
		}
	}
	if _, ok := x.p.AAA.Set("admin"); !ok {
		x.p.AAA.Sets = append(x.p.AAA.Sets, baseline.MethodSet{Name: "admin", Login: baseline.MethodList{{Kind: baseline.MethodLocal}}})
	}
	svc := &x.p.Services
	for proto, s := range map[string]*baseline.Service{"telnet": &svc.Telnet, "ssh": &svc.SSH, "http": &svc.HTTP,
		"https": &svc.HTTPS, "netconf": &svc.NETCONF} {
		s.State = baseline.StateDisabled
		if line, ok := x.manage[proto]; ok {
			s.State, s.Line = baseline.StateEnabled, line
		}
		if hosts := x.hosts[proto]; len(hosts) > 0 && !slices.Contains(hosts, "any") {
			s.ACL = aclAdminHost
			x.p.ACLs[aclAdminHost] = baseline.ACL{Name: aclAdminHost, Rules: len(hosts)}
		}
	}
	svc.SSHv1.State = baseline.StateDisabled
}
