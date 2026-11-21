package panos

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
const Name = "panos"

const aclPermitted = "permitted-ip"

// Extractor decodes PAN-OS set-format configurations. It is stateless
// and safe for concurrent use.
type Extractor struct{}

// New returns a PAN-OS extractor.
func New() *Extractor { return &Extractor{} }

// Vendor returns "panos".
func (*Extractor) Vendor() string { return Name }

// Dialect returns the flat set-format dialect.
func (*Extractor) Dialect() config.Dialect {
	return config.Dialect{
		Name: Name,
		Sensitive: mgmt.Sensitive("phash", "password", "secret", "snmp-community-string", "authpwd", "privpwd",
			"key", "auth-key", "api-key", "preshared-key"),
	}
}

// Extract builds the posture of d from doc.
func (*Extractor) Extract(ctx context.Context, d device.Device, doc *config.Document) (baseline.Extraction, error) {
	p := &baseline.Posture{Device: d, Config: doc, ACLs: map[string]baseline.ACL{}}
	p.AAA.Default = "system"
	p.Logging.State = baseline.StateEnabled
	p.SNMP.State = baseline.StateEnabled
	svc := &p.Services
	svc.Telnet.State, svc.HTTP.State, svc.SSHv1.State, svc.NETCONF.State = baseline.StateDisabled,
		baseline.StateDisabled, baseline.StateDisabled, baseline.StateDisabled
	svc.SSH.State, svc.HTTPS.State = baseline.StateEnabled, baseline.StateEnabled
	x := &extraction{p: p, profiles: map[string]baseline.Method{}, servers: map[string]map[string]*baseline.Server{},
		users: map[string]int{}}
	for i, n := range doc.Root().Children {
		if i%256 == 0 && ctx.Err() != nil {
			return baseline.Extraction{}, ctx.Err()
		}
		x.statement(n)
	}
	x.finish()
	return baseline.NewTally(d.ID, Name, mgmt.Facets()...).Result(p), nil
}

type extraction struct {
	p           *baseline.Posture
	systemAuth  string                                 // authentication profile of administrators
	profiles    map[string]baseline.Method             // authentication profile to its server profile
	servers     map[string]map[string]*baseline.Server // server profile to servers by name
	order       map[string][]string                    // server names by profile, in order
	users       map[string]int
	permitted   int
	communities []string
}

func (x *extraction) statement(n *parse.Node) {
	w := token.Split(n.Text)
	if w.At(0) != "set" {
		return
	}
	w = w.From(1)
	switch {
	case w.Prefix("deviceconfig", "system"):
		x.system(n, w.From(2))
	case w.Prefix("shared", "authentication-profile") && w.At(3) == "method":
		proto := map[string]string{"tacplus": "tacacs", "radius": "radius"}[w.At(4)]
		if prof, ok := w.After("server-profile"); ok && proto != "" {
			x.profiles[w.At(2)] = baseline.Method{Kind: baseline.MethodGroup, Protocol: proto, Group: prof}
		} else if w.At(4) == "local-database" {
			x.profiles[w.At(2)] = baseline.Method{Kind: baseline.MethodLocal}
		}
	case w.Prefix("shared", "server-profile", "tacplus"), w.Prefix("shared", "server-profile", "radius"):
		x.serverProfile(n, w)
	case w.Prefix("shared", "log-settings", "syslog") && w.At(4) == "server" && w.At(6) == "server":
		x.p.Logging.Hosts = append(x.p.Logging.Hosts, baseline.Server{Host: w.At(7), Rank: baseline.RankOrdered, Line: n.Line.Number})
	case w.Prefix("mgt-config", "users"):
		x.user(n, w)
	}
}

func (x *extraction) system(n *parse.Node, w token.Words) {
	p := x.p
	switch {
	case w.Prefix("hostname"):
		p.Hostname = w.At(1)
	case w.Prefix("timezone"):
		if d, ok := tz.Named(w.At(1)); ok {
			p.Time.Timezone = baseline.Timezone{Name: w.At(1), Offset: d, Set: true, Line: n.Line.Number}
		}
	case w.Prefix("authentication-profile"):
		x.systemAuth = w.At(1)
	case w.Prefix("service"):
		x.service(n, w)
	case w.Prefix("ntp-servers"):
		x.ntp(n, w)
	case w.Prefix("snmp-setting", "access-setting", "version"):
		x.snmpAccess(n, w)
	case w.Prefix("snmp-setting", "snmp-system", "location"):
		p.SNMP.Location = strings.Join(w.From(3), " ")
	case w.Prefix("snmp-setting", "snmp-system", "contact"):
		p.SNMP.Contact = strings.Join(w.From(3), " ")
	case w.Prefix("permitted-ip"):
		x.permitted++
	}
}

// service decodes "service disable-X yes|no".
func (x *extraction) service(n *parse.Node, w token.Words) {
	p := x.p
	state := baseline.StateEnabled
	if w.At(2) == "yes" {
		state = baseline.StateDisabled
	}
	target := map[string]*baseline.Service{"disable-telnet": &p.Services.Telnet, "disable-http": &p.Services.HTTP,
		"disable-https": &p.Services.HTTPS, "disable-ssh": &p.Services.SSH}[w.At(1)]
	if target != nil {
		target.State, target.Line = state, n.Line.Number
	}
	if w.At(1) == "disable-snmp" {
		p.SNMP.State = state
	}
}

// ntp decodes "ntp-servers primary-ntp-server|secondary-ntp-server ...".
func (x *extraction) ntp(n *parse.Node, w token.Words) {
	p := x.p
	switch w.At(2) {
	case "ntp-server-address":
		rank := baseline.RankPrimary
		if w.At(1) == "secondary-ntp-server" {
			rank = baseline.RankSecondary
		}
		p.Time.NTP = append(p.Time.NTP, baseline.Server{Host: w.At(3), Rank: rank, Line: n.Line.Number})
		p.Time.NTPState = baseline.StateEnabled
	case "authentication-type":
		p.Time.Auth = p.Time.Auth || w.At(3) != "none"
	}
}

// snmpAccess decodes "snmp-setting access-setting version v2c
// snmp-community-string X" and "... version v3 users U authpwd/privpwd".
func (x *extraction) snmpAccess(n *parse.Node, w token.Words) {
	s := &x.p.SNMP
	v := w.At(3)
	if !slices.Contains(s.Versions, v) {
		s.Versions = append(s.Versions, v)
	}
	if name, ok := w.After("snmp-community-string"); ok && !slices.Contains(x.communities, name) {
		x.communities = append(x.communities, name)
		s.Communities = append(s.Communities, baseline.Community{Name: secret.New(name), Line: n.Line.Number})
	}
	if v != "v3" || w.At(4) != "users" {
		return
	}
	i := slices.IndexFunc(s.Users, func(u baseline.SNMPUser) bool { return u.Name == w.At(5) })
	if i < 0 {
		i = len(s.Users)
		s.Users = append(s.Users, baseline.SNMPUser{Name: w.At(5), Line: n.Line.Number})
	}
	s.Users[i].Auth = s.Users[i].Auth || w.Has("authpwd")
	s.Users[i].Privacy = s.Users[i].Privacy || w.Has("privpwd")
}

// serverProfile decodes "shared server-profile tacplus|radius P server S
// address|ip-address|secret ...".
func (x *extraction) serverProfile(n *parse.Node, w token.Words) {
	prof := w.At(3)
	if w.At(4) != "server" || w.At(5) == "" {
		return
	}
	if x.servers[prof] == nil {
		x.servers[prof] = map[string]*baseline.Server{}
		if x.order == nil {
			x.order = map[string][]string{}
		}
	}
	name := w.At(5)
	s, ok := x.servers[prof][name]
	if !ok {
		s = &baseline.Server{Rank: baseline.RankOrdered, Line: n.Line.Number}
		x.servers[prof][name] = s
		x.order[prof] = append(x.order[prof], name)
	}
	switch w.At(6) {
	case "address", "ip-address":
		s.Host = w.At(7)
	case "secret":
		s.Keyed = true
	case "port":
		s.Port = w.Int("port")
	}
}

// user decodes "mgt-config users NAME ...".
func (x *extraction) user(n *parse.Node, w token.Words) {
	name := w.At(2)
	i, ok := x.users[name]
	if !ok {
		i = len(x.p.Accounts)
		x.users[name] = i
		x.p.Accounts = append(x.p.Accounts, baseline.Account{Name: name, Line: n.Line.Number})
	}
	a := &x.p.Accounts[i]
	switch {
	case w.At(3) == "phash", w.At(3) == "password":
		a.PasswordSet, a.Hashed = true, w.At(3) == "phash"
	case w.At(3) == "authentication-profile":
		// Remote administrators have no local login.
		a.Services = []string{}
	case w.Prefix("mgt-config", "users", name, "permissions", "role-based"):
		a.Roles = append(a.Roles, w.At(5))
		a.Admin = a.Admin || w.At(5) == "superuser"
	}
}

func (x *extraction) finish() {
	p := x.p
	for prof, names := range x.order {
		proto := "tacacs"
		for _, m := range x.profiles {
			if m.Group == prof {
				proto = m.Protocol
			}
		}
		g := baseline.ServerGroup{Name: prof, Protocol: proto}
		for _, name := range names {
			if s := x.servers[prof][name]; s.Host != "" {
				g.Servers = append(g.Servers, *s)
			}
		}
		p.AAA.Groups = append(p.AAA.Groups, g)
	}
	slices.SortFunc(p.AAA.Groups, func(a, b baseline.ServerGroup) int { return strings.Compare(a.Name, b.Name) })
	login := baseline.MethodList{{Kind: baseline.MethodLocal}}
	if m, ok := x.profiles[x.systemAuth]; ok && m.Kind == baseline.MethodGroup {
		// Local administrators (phash) still log in when the profile fails.
		login = baseline.MethodList{m, {Kind: baseline.MethodLocal}}
	}
	p.AAA.Sets = []baseline.MethodSet{{Name: "system", Login: login, Authorization: login}}
	if x.permitted > 0 {
		p.ACLs[aclPermitted] = baseline.ACL{Name: aclPermitted, Rules: x.permitted}
		p.Services.SSH.ACL, p.Services.HTTPS.ACL, p.Services.HTTP.ACL = aclPermitted, aclPermitted, aclPermitted
		for i := range p.SNMP.Communities {
			p.SNMP.Communities[i].ACL = aclPermitted
		}
	}
	if len(p.Time.NTP) == 0 {
		p.Time.NTPState = baseline.StateDisabled
	}
}
