package ios

import (
	"cmp"
	"context"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gatework/netops/config"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/parse"
	"github.com/gatework/netops/secret"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/internal/token"
	"github.com/gatework/baseline/internal/tz"
)

// echo is the command echo that starts a captured configuration.
var echo = regexp.MustCompile(`^show running-config`)

// Name is the vendor key of this extractor.
const Name = "ios"

var (
	// blockKey masks "key 7 X" inside tacacs/radius server blocks, which
	// the netops Cisco dialect does not cover.
	blockKey = regexp.MustCompile(`(?i)^\s*(?:key|pac key)\s+(?:\d\s+)?(\S+)`)
)

const defaultIdle = 10 * time.Minute

// Extractor decodes IOS configurations. It is stateless and safe for
// concurrent use.
type Extractor struct{}

// New returns an IOS extractor.
func New() *Extractor { return &Extractor{} }

// Vendor returns "ios".
func (*Extractor) Vendor() string { return Name }

// Dialect returns the Cisco dialect with block keys masked.
func (*Extractor) Dialect() config.Dialect {
	d := config.Cisco()
	d.Name = Name
	d.Sensitive = append(d.Sensitive, blockKey)
	d.Volatile = append(d.Volatile, echo)
	return d
}

// Extract builds the posture of d from doc.
func (*Extractor) Extract(ctx context.Context, d device.Device, doc *config.Document) (baseline.Extraction, error) {
	x := &extraction{
		p:     &baseline.Posture{Device: d, Config: doc, ACLs: map[string]baseline.ACL{}},
		tally: baseline.NewTally(d.ID, Name, baseline.Facets()...),
		hosts: map[string]baseline.Server{}, keyed: map[string]bool{}, users: map[string]int{},
	}
	p := x.p
	p.AAA.Default = "default"
	p.Logging.State = baseline.StateEnabled
	p.SNMP.State = baseline.StateDisabled
	p.Services.SSH.State = baseline.StateEnabled
	p.Services.SSHv1.State = baseline.StateEnabled
	for _, s := range []*baseline.Service{&p.Services.Telnet, &p.Services.HTTP, &p.Services.HTTPS, &p.Services.NETCONF} {
		s.State = baseline.StateDisabled
	}
	for _, n := range doc.Root().Children {
		if len(n.Children) > 0 && strings.HasPrefix(n.Text, "interface ") {
			x.switching = x.switching || slices.ContainsFunc(n.Children, func(c *parse.Node) bool {
				return strings.HasPrefix(c.Text, "switchport")
			})
		}
	}
	for i, n := range doc.Root().Children {
		if i%256 == 0 && ctx.Err() != nil {
			return baseline.Extraction{}, ctx.Err()
		}
		x.statement(n)
	}
	x.finish()
	return x.tally.Result(p), nil
}

type extraction struct {
	p         *baseline.Posture
	tally     *baseline.Tally
	hosts     map[string]baseline.Server // server definitions by name or address
	keyed     map[string]bool            // global key per protocol
	users     map[string]int
	members   []member
	lines     []*parse.Node
	newModel  bool
	switching bool
	sshV2     bool
}

type member struct {
	group, host string
	line        int
}

func (x *extraction) statement(n *parse.Node) {
	w := token.Split(n.Text)
	no := w.At(0) == "no"
	if no {
		w = w.From(1)
	}
	switch w.At(0) {
	case "hostname":
		x.p.Hostname = w.At(1)
	case "version":
		x.p.Version = w.At(1)
	case "aaa":
		x.aaa(n, w, no)
	case "tacacs", "radius":
		x.serverBlock(n, w)
	case "tacacs-server", "radius-server":
		x.legacyServer(n, w, no)
	case "username":
		x.account(n, w)
	case "line":
		x.lines = append(x.lines, n)
	case "logging":
		x.logging(n, w, no)
	case "ntp":
		x.ntp(n, w, no)
	case "clock":
		x.clock(n, w)
	case "snmp-server":
		x.snmp(n, w, no)
	case "ip":
		x.ip(n, w, no)
	case "access-list":
		key := w.At(1)
		acl := x.p.ACLs[key]
		acl.Name, acl.Rules = key, acl.Rules+1
		if acl.Line == 0 {
			acl.Line = n.Line.Number
		}
		x.p.ACLs[key] = acl
	case "interface":
		x.iface(n, w)
	case "dot1x":
		if w.Prefix("dot1x", "system-auth-control") {
			x.p.NAC.Dot1x, x.p.NAC.Line = !no, n.Line.Number
		}
	}
}

func (x *extraction) finish() {
	for _, m := range x.members {
		i := slices.IndexFunc(x.p.AAA.Groups, func(g baseline.ServerGroup) bool { return g.Name == m.group })
		if i < 0 {
			continue
		}
		g := &x.p.AAA.Groups[i]
		s, ok := x.hosts[m.host]
		if !ok {
			s = baseline.Server{Host: m.host}
		}
		s.Rank, s.Line = baseline.RankOrdered, m.line
		s.Keyed = s.Keyed || x.keyed[g.Protocol]
		g.Servers = append(g.Servers, s)
	}
	if !x.newModel {
		// Without aaa new-model, lines authenticate on their own and
		// there are no method lists.
		x.p.AAA.Sets = nil
	}
	if _, ok := x.p.AAA.Set("default"); !ok {
		x.p.AAA.Sets = append(x.p.AAA.Sets, baseline.MethodSet{Name: "default", Login: baseline.MethodList{{Kind: baseline.MethodLocal}}})
	}
	for i := range x.p.AAA.Sets {
		for _, l := range []baseline.MethodList{x.p.AAA.Sets[i].Login, x.p.AAA.Sets[i].Authorization,
			x.p.AAA.Sets[i].Commands, x.p.AAA.Sets[i].Accounting, x.p.AAA.Sets[i].CommandAccounting} {
			for j := range l {
				if g, ok := x.p.AAA.Group(l[j].Group); ok {
					l[j].Protocol = g.Protocol
				}
			}
		}
	}
	for _, n := range x.lines {
		l := x.decodeLine(n)
		set, _ := x.p.AAA.Management(l.MethodSet)
		l.CommandAuthorization = l.CommandAuthorization || set.Commands.Remote()
		l.CommandAccounting = l.CommandAccounting || set.CommandAccounting.Remote()
		x.p.Lines = append(x.p.Lines, l)
		if l.Kind == baseline.LineVTY && l.Usable() && l.Allows("telnet") {
			x.p.Services.Telnet.State, x.p.Services.Telnet.Line = baseline.StateEnabled, l.Line
		}
	}
	if x.sshV2 {
		x.p.Services.SSHv1.State = baseline.StateDisabled
	}
	if len(x.p.Time.NTP) > 0 {
		x.p.Time.NTPState = baseline.StateEnabled
	} else {
		x.p.Time.NTPState = baseline.StateDisabled
	}
	for _, i := range x.p.Interfaces {
		x.p.NAC.AddDomain(i.Domain)
	}
}

// aaa decodes aaa new-model, groups and method lists.
func (x *extraction) aaa(n *parse.Node, w token.Words, no bool) {
	switch {
	case w.Prefix("aaa", "new-model"):
		x.newModel = !no
	case no:
	case w.Prefix("aaa", "group", "server"):
		g := baseline.ServerGroup{Name: w.At(4), Protocol: protocol(w.At(3)), Line: n.Line.Number}
		for _, c := range n.Children {
			cw := token.Split(c.Text)
			switch {
			case cw.Prefix("server", "name"):
				x.members = append(x.members, member{group: g.Name, host: cw.At(2), line: c.Line.Number})
			case cw.Prefix("server-private"):
				s := baseline.Server{Host: cw.At(1), Keyed: cw.Has("key"), Line: c.Line.Number}
				x.hosts[s.Host] = s
				x.members = append(x.members, member{group: g.Name, host: s.Host, line: c.Line.Number})
			case cw.Prefix("server"):
				x.members = append(x.members, member{group: g.Name, host: cw.At(1), line: c.Line.Number})
			}
		}
		x.p.AAA.Groups = append(x.p.AAA.Groups, g)
	case w.Prefix("aaa", "authentication", "login"):
		x.set(w.At(3), n).Login = methods(w.From(4))
	case w.Prefix("aaa", "authorization", "exec"):
		x.set(w.At(3), n).Authorization = methods(w.From(4))
	case w.Prefix("aaa", "authorization", "commands"):
		if w.At(3) == "15" {
			x.set(w.At(4), n).Commands = methods(w.From(5))
		}
	case w.Prefix("aaa", "accounting", "exec"):
		x.set(w.At(3), n).Accounting = methods(w.From(4))
	case w.Prefix("aaa", "accounting", "commands"):
		if w.At(3) == "15" {
			x.set(w.At(4), n).CommandAccounting = methods(w.From(5))
		}
	}
}

func (x *extraction) set(name string, n *parse.Node) *baseline.MethodSet {
	for i := range x.p.AAA.Sets {
		if x.p.AAA.Sets[i].Name == name {
			return &x.p.AAA.Sets[i]
		}
	}
	x.p.AAA.Sets = append(x.p.AAA.Sets, baseline.MethodSet{Name: name, Line: n.Line.Number})
	return &x.p.AAA.Sets[len(x.p.AAA.Sets)-1]
}

// methods decodes "[start-stop] group G local none line enable".
func methods(w token.Words) baseline.MethodList {
	var out baseline.MethodList
	for i := 0; i < len(w); i++ {
		switch w[i] {
		case "group":
			if i+1 < len(w) {
				i++
				out = append(out, baseline.Method{Kind: baseline.MethodGroup, Protocol: protocol(w[i]), Group: w[i]})
			}
		case "local", "local-case":
			out = append(out, baseline.Method{Kind: baseline.MethodLocal})
		case "none":
			out = append(out, baseline.Method{Kind: baseline.MethodNone})
		}
	}
	return out
}

// serverBlock decodes "tacacs server NAME" and "radius server NAME"
// blocks, which define a server named NAME.
func (x *extraction) serverBlock(n *parse.Node, w token.Words) {
	if w.At(1) != "server" {
		return
	}
	s := baseline.Server{Host: w.At(2), Line: n.Line.Number}
	for _, c := range n.Children {
		cw := token.Split(c.Text)
		switch {
		case cw.Prefix("address"):
			s.Host = cw.At(2)
		case cw.Prefix("key"), cw.Prefix("pac", "key"):
			s.Keyed = true
		case cw.Prefix("port"):
			s.Port = cw.Int("port")
		}
	}
	x.hosts[w.At(2)] = s
}

// legacyServer decodes "tacacs-server host A [key K]" and global keys.
func (x *extraction) legacyServer(n *parse.Node, w token.Words, no bool) {
	proto := protocol(w.At(0))
	switch {
	case no:
	case w.At(1) == "host":
		x.hosts[w.At(2)] = baseline.Server{Host: w.At(2), Keyed: w.Has("key"), Port: w.Int("port"), Line: n.Line.Number}
	case w.At(1) == "key":
		x.keyed[proto] = true
	}
}

func protocol(word string) string {
	switch {
	case strings.HasPrefix(word, "tacacs"):
		return "tacacs"
	case strings.HasPrefix(word, "radius"):
		return "radius"
	}
	return word
}

// decodeLine decodes "line con 0" and "line vty 0 4" blocks.
func (x *extraction) decodeLine(n *parse.Node) baseline.Line {
	w := token.Split(n.Text)
	l := baseline.Line{Range: strings.Join(w.From(2), " "), Idle: defaultIdle, IdleSet: true, Line: n.Line.Number}
	switch w.At(1) {
	case "vty":
		l.Kind = baseline.LineVTY
		l.Protocols = []string{"ssh", "telnet"}
	case "aux":
		l.Kind = baseline.LineAux
	default:
		l.Kind = baseline.LineConsole
	}
	login, local, password := false, false, false
	for _, c := range n.Children {
		cw := token.Split(c.Text)
		switch {
		case cw.Prefix("login", "authentication"):
			l.MethodSet = cw.At(2)
		case cw.Prefix("login", "local"):
			login, local = true, true
		case cw.Prefix("login"):
			login = true
		case cw.Prefix("password"), cw.Prefix("line-password"):
			password = true
		case cw.Prefix("transport", "input"):
			l.Protocols = transports(cw.From(2))
		case cw.Prefix("exec-timeout"):
			m, err1 := strconv.Atoi(cw.At(1))
			s, err2 := strconv.Atoi(cmp.Or(cw.At(2), "0"))
			if err1 != nil || err2 != nil {
				x.tally.Unrecognized(baseline.FacetLine, c.Line.Number, token.Keyword(c, x.p.Config.Dialect()))
				continue
			}
			l.Idle = time.Duration(m)*time.Minute + time.Duration(s)*time.Second
		case cw.Prefix("access-class"):
			l.ACL = cw.At(1)
		case cw.Prefix("authorization", "commands"):
			if set, ok := x.p.AAA.Set(cw.At(3)); ok {
				l.CommandAuthorization = set.Commands.Remote()
			}
		case cw.Prefix("accounting", "commands"):
			if set, ok := x.p.AAA.Set(cw.At(3)); ok {
				l.CommandAccounting = set.CommandAccounting.Remote()
			}
		}
	}
	switch {
	case x.newModel:
		l.Auth = baseline.LineAuthAAA
	case local:
		// "login local" without new-model checks the local database.
		l.Auth = baseline.LineAuthAAA
	case login:
		l.Auth, l.PasswordSet = baseline.LineAuthPassword, password
	default:
		l.Auth = baseline.LineAuthNone
	}
	return l
}

func transports(w token.Words) []string {
	out := []string{}
	for _, t := range w {
		switch t {
		case "all":
			return []string{"ssh", "telnet"}
		case "ssh", "telnet":
			out = append(out, t)
		}
	}
	return out
}

// account decodes "username NAME [privilege N] [password|secret T X]".
func (x *extraction) account(n *parse.Node, w token.Words) {
	name := w.At(1)
	i, ok := x.users[name]
	if !ok {
		i = len(x.p.Accounts)
		x.users[name] = i
		x.p.Accounts = append(x.p.Accounts, baseline.Account{Name: name, Line: n.Line.Number})
	}
	a := &x.p.Accounts[i]
	if lvl, ok := w.After("privilege"); ok {
		a.Roles = append(a.Roles, "level-"+lvl)
		a.Admin = a.Admin || lvl == "15"
	}
	if w.Has("secret") {
		a.PasswordSet, a.Hashed = true, true
	} else if t, ok := w.After("password"); ok {
		a.PasswordSet = true
		a.Hashed = t == "5" || t == "8" || t == "9"
	}
	if w.Has("nopassword") {
		a.PasswordSet = false
	}
}

func (x *extraction) logging(n *parse.Node, w token.Words, no bool) {
	l := &x.p.Logging
	switch {
	case w.Prefix("logging", "on"):
		l.State = baseline.StateEnabled
		if no {
			l.State = baseline.StateDisabled
		}
	case no:
	case w.Prefix("logging", "host"), w.Prefix("logging", "server", "address"):
		rest := w.From(2)
		if w.At(1) == "server" {
			rest = w.From(3)
		}
		s := baseline.Server{Rank: baseline.RankOrdered, Port: rest.Int("port"), Line: n.Line.Number}
		s.VRF, _ = rest.After("vrf")
		for _, t := range rest {
			if t != "vrf" && t != "ipv6" && t != "mgmt-if" && t != "inband" && s.Host == "" {
				s.Host = t
			}
			if t == "vrf" {
				break
			}
		}
		if s.Host == "" {
			x.tally.Unrecognized(baseline.FacetLogging, n.Line.Number, token.Keyword(n, x.p.Config.Dialect()))
			return
		}
		l.Hosts = append(l.Hosts, s)
	case w.Prefix("logging", "source-interface"):
		l.Source = w.At(2)
	}
}

func (x *extraction) ntp(n *parse.Node, w token.Words, no bool) {
	t := &x.p.Time
	switch {
	case no:
	case w.Prefix("ntp", "server"), w.Prefix("ntp", "peer"):
		rest := w.From(2)
		s := baseline.Server{Rank: baseline.RankOrdered, Keyed: rest.Has("key"), Line: n.Line.Number}
		if rest.At(0) == "vrf" {
			s.VRF, rest = rest.At(1), rest.From(2)
		}
		if rest.At(0) == "mgmt-if" || rest.At(0) == "inband" || rest.At(0) == "ip" {
			rest = rest.From(1)
		}
		s.Host = rest.At(0)
		s.Source, _ = rest.After("source")
		if rest.Has("prefer") {
			s.Rank = baseline.RankPrimary
		}
		t.NTP = append(t.NTP, s)
	case w.Prefix("ntp", "source"):
		t.Source = w.At(2)
	case w.Prefix("ntp", "authenticate"):
		t.Auth = true
	}
}

func (x *extraction) clock(n *parse.Node, w token.Words) {
	if !w.Prefix("clock", "timezone") {
		return
	}
	d, ok := tz.Hours(w.At(3), w.At(4))
	if !ok {
		x.tally.Unrecognized(baseline.FacetClock, n.Line.Number, token.Keyword(n, x.p.Config.Dialect()))
		return
	}
	x.p.Time.Timezone = baseline.Timezone{Name: w.At(2), Offset: d, Set: true, Line: n.Line.Number}
}

func (x *extraction) snmp(n *parse.Node, w token.Words, no bool) {
	s := &x.p.SNMP
	switch {
	case no:
	case w.Prefix("snmp-server", "community"):
		s.Communities = append(s.Communities, community(n, w))
		s.State = baseline.StateEnabled
		addVersion(s, "v2c")
	case w.Prefix("snmp-server", "user"):
		u := baseline.SNMPUser{Name: w.At(2), Auth: w.Has("auth"), Privacy: w.Has("priv"), Line: n.Line.Number}
		if w.Has("v3") {
			s.Users = append(s.Users, u)
			addVersion(s, "v3")
		}
		s.State = baseline.StateEnabled
	case w.Prefix("snmp-server", "host"):
		s.TrapHosts = append(s.TrapHosts, baseline.Server{Host: w.At(2), Rank: baseline.RankOrdered, Line: n.Line.Number})
	case w.Prefix("snmp-server", "location"):
		s.Location = strings.Join(w.From(2), " ")
	case w.Prefix("snmp-server", "contact"):
		s.Contact = strings.Join(w.From(2), " ")
	case w.Prefix("snmp-server", "enable"), w.Prefix("snmp-server", "manager"):
		s.State = baseline.StateEnabled
	}
}

// community decodes "snmp-server community NAME [view V] [RO|RW|read-only|
// read-write] [ipv6 ACL] [ACL]".
func community(n *parse.Node, w token.Words) baseline.Community {
	c := baseline.Community{Name: secret.New(w.At(2)), Line: n.Line.Number}
	rest := w.From(3)
	for i := 0; i < len(rest); i++ {
		switch strings.ToLower(rest[i]) {
		case "view", "ipv6":
			i++
		case "rw", "read-write":
			c.Write = true
		case "ro", "read-only":
		default:
			c.ACL = rest[i]
		}
	}
	return c
}

func addVersion(s *baseline.SNMP, v string) {
	if !slices.Contains(s.Versions, v) {
		s.Versions = append(s.Versions, v)
		slices.Sort(s.Versions)
	}
}

// ip decodes ip http/ssh switches and named access lists.
func (x *extraction) ip(n *parse.Node, w token.Words, no bool) {
	svc := &x.p.Services
	state := baseline.StateEnabled
	if no {
		state = baseline.StateDisabled
	}
	switch {
	case w.Prefix("ip", "http", "server"):
		svc.HTTP.State, svc.HTTP.Line = state, n.Line.Number
	case w.Prefix("ip", "http", "secure-server"):
		svc.HTTPS.State, svc.HTTPS.Line = state, n.Line.Number
	case w.Prefix("ip", "http", "access-class"):
		svc.HTTP.ACL = w.At(len(w) - 1)
		svc.HTTPS.ACL = svc.HTTP.ACL
	case w.Prefix("ip", "ssh", "version"):
		x.sshV2 = w.At(3) == "2"
	case w.Prefix("ip", "access-list") && !no:
		name := w.At(3)
		if w.At(2) != "standard" && w.At(2) != "extended" {
			name = w.At(2)
		}
		x.p.ACLs[name] = baseline.ACL{Name: name, Rules: len(n.Children), Line: n.Line.Number}
	}
}

// iface decodes an "interface NAME" block.
func (x *extraction) iface(n *parse.Node, w token.Words) {
	name := strings.Join(w.From(1), " ")
	i := baseline.Interface{Name: name, Kind: interfaceKind(name), Line: n.Line.Number}
	switch i.Kind {
	case baseline.InterfacePhysical, baseline.InterfaceAggregate:
		i.Mode = baseline.PortRouted
		if x.switching {
			i.Mode = baseline.PortAccess
		}
	case baseline.InterfaceVLAN, baseline.InterfaceLoopback, baseline.InterfaceMgmt:
		i.Mode = baseline.PortRouted
	case baseline.InterfaceOther:
	}
	for _, c := range n.Children {
		cw := token.Split(c.Text)
		switch {
		case cw.Prefix("shutdown"):
			i.Shutdown = true
		case cw.Prefix("description"):
			i.Description = strings.Join(cw.From(1), " ")
		case cw.Prefix("no", "switchport"):
			i.Mode = baseline.PortRouted
		case cw.Prefix("switchport", "mode", "trunk"):
			i.Mode = baseline.PortTrunk
		case cw.Prefix("switchport", "mode", "access"):
			i.Mode = baseline.PortAccess
		case cw.Prefix("switchport", "access", "vlan"):
			i.AccessVLAN = cw.Int("vlan")
		case cw.Prefix("channel-group"):
			i.Member = true
		case cw.Prefix("spanning-tree", "portfast"):
			i.Edge = !cw.Has("disable")
		case cw.Prefix("dot1x", "pae", "authenticator"), cw.Prefix("authentication", "port-control"):
			i.Dot1x = true
		case cw.Prefix("mab"):
			i.MACAuth = true
		}
	}
	if i.Mode == baseline.PortAccess && i.AccessVLAN == 0 {
		i.AccessVLAN = 1
	}
	x.p.Interfaces = append(x.p.Interfaces, i)
}

func interfaceKind(name string) baseline.InterfaceKind {
	lower := strings.ToLower(name)
	switch {
	case strings.HasPrefix(lower, "port-channel"):
		return baseline.InterfaceAggregate
	case strings.HasPrefix(lower, "vlan"):
		return baseline.InterfaceVLAN
	case strings.HasPrefix(lower, "loopback"):
		return baseline.InterfaceLoopback
	case strings.HasPrefix(lower, "mgmt"), strings.HasPrefix(lower, "gigabitethernet0/0") && !strings.Contains(lower, "/0/"):
		return baseline.InterfaceMgmt
	case strings.Contains(lower, "ethernet"), strings.HasPrefix(lower, "eth-"), strings.HasPrefix(lower, "twe"),
		strings.HasPrefix(lower, "hu"), strings.HasPrefix(lower, "fo"):
		return baseline.InterfacePhysical
	}
	return baseline.InterfaceOther
}
