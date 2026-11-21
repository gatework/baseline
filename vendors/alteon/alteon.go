package alteon

import (
	"context"
	"regexp"
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
const Name = "alteon"

const aclMgmt = "mgmt-access"

var hostSlot = regexp.MustCompile(`^hst(\d+)$`)

// Extractor decodes Alteon configurations. It is stateless and safe for
// concurrent use.
type Extractor struct{}

// New returns an Alteon extractor.
func New() *Extractor { return &Extractor{} }

// Vendor returns "alteon".
func (*Extractor) Vendor() string { return Name }

// Dialect returns the Alteon dump dialect.
func (*Extractor) Dialect() config.Dialect {
	return config.Dialect{
		Name:     Name,
		Comments: []string{"/*", ">>"},
		Volatile: []*regexp.Regexp{regexp.MustCompile(`^(script (start|end)|/cfg/dump|Display private keys)`)},
		Sensitive: mgmt.Sensitive("rcomm", "wcomm", "tcomm", "esecret", "esecret2", "secret", "secret2", "admpw",
			"pswd", "passwd", "authpw", "privpw", "key"),
	}
}

// Extract builds the posture of d from doc.
func (*Extractor) Extract(ctx context.Context, d device.Device, doc *config.Document) (baseline.Extraction, error) {
	p := &baseline.Posture{Device: d, Config: doc, ACLs: map[string]baseline.ACL{}}
	p.AAA.Default = "system"
	p.Logging.State = baseline.StateEnabled
	p.Time.NTPState = baseline.StateDisabled
	p.SNMP.State = baseline.StateDisabled
	svc := &p.Services
	for _, s := range []*baseline.Service{&svc.Telnet, &svc.SSH, &svc.SSHv1, &svc.HTTP, &svc.HTTPS, &svc.NETCONF} {
		s.State = baseline.StateDisabled
	}
	// The administrator account always exists.
	p.Accounts = []baseline.Account{{Name: "admin", Admin: true, Roles: []string{"admin"}}}
	x := &extraction{p: p, local: true}
	for i, n := range doc.Root().Children {
		if i%256 == 0 && ctx.Err() != nil {
			return baseline.Extraction{}, ctx.Err()
		}
		x.section(n)
	}
	x.finish()
	return baseline.NewTally(d.ID, Name, mgmt.Facets()...).Result(p), nil
}

type extraction struct {
	p             *baseline.Posture
	mgmtProtos    []string // protocols that /c/sys/access/mgmt/add restricts
	tacacs, local bool     // TACACS+ on; local fallback enabled
	snmpWrite     bool     // "snmp w": communities are writable
}

// section dispatches one menu path.
func (x *extraction) section(n *parse.Node) {
	p, svc := x.p, &x.p.Services
	path := strings.Fields(n.Text)
	arg := ""
	if len(path) > 1 {
		arg = path[1]
	}
	switch path[0] {
	case "/c/sys/ntp":
		ntp(p, n)
	case "/c/sys/syslog":
		syslog(p, n)
	case "/c/sys/tacacs":
		x.tacacs, x.local = aaa(p, n, "tacacs")
	case "/c/sys/radius":
		aaa(p, n, "radius")
	case "/c/sys/ssnmp":
		snmp(p, n)
	case "/c/sys/access":
		x.snmpWrite = access(p, n)
	case "/c/sys/access/mgmt/add":
		x.mgmtProtos = append(x.mgmtProtos, strings.Split(path[len(path)-1], "|")...)
		acl := p.ACLs[aclMgmt]
		acl.Name, acl.Rules = aclMgmt, acl.Rules+1
		p.ACLs[aclMgmt] = acl
	case "/c/sys/access/sshd/on":
		svc.SSH.State, svc.SSH.Line = baseline.StateEnabled, n.Line.Number
	case "/c/sys/access/sshd/sshv1":
		toggle(&svc.SSHv1, arg, n)
	case "/c/sys/access/https/https":
		toggle(&svc.HTTPS, arg, n)
	case "/c/sys/access/http":
		toggle(&svc.HTTP, arg, n)
	case "/c/sys/access/tnet":
		toggle(&svc.Telnet, arg, n)
	case "/c/sys/access/user":
		for _, c := range n.Children {
			if strings.HasPrefix(c.Text, "admpw") {
				p.Accounts[0].PasswordSet, p.Accounts[0].Hashed = true, true
			}
		}
	}
}

// finish applies the management ACL and builds the login method set.
func (x *extraction) finish() {
	p, svc := x.p, &x.p.Services
	for proto, s := range map[string]*baseline.Service{"ssh": &svc.SSH, "https": &svc.HTTPS, "http": &svc.HTTP, "telnet": &svc.Telnet} {
		if slices.Contains(x.mgmtProtos, proto) {
			s.ACL = aclMgmt
		}
	}
	for j := range p.SNMP.Communities {
		if slices.Contains(x.mgmtProtos, "snmp") {
			p.SNMP.Communities[j].ACL = aclMgmt
		}
		p.SNMP.Communities[j].Write = p.SNMP.Communities[j].Write || x.snmpWrite
	}
	login := baseline.MethodList{{Kind: baseline.MethodLocal}}
	if g, ok := p.AAA.Group("tacacs"); ok && x.tacacs {
		login = baseline.MethodList{{Kind: baseline.MethodGroup, Protocol: "tacacs", Group: g.Name}}
		if x.local {
			login = append(login, baseline.Method{Kind: baseline.MethodLocal})
		}
	}
	p.AAA.Sets = []baseline.MethodSet{{Name: "system", Login: login, Authorization: login}}
}

// toggle enables s when arg starts with "e" (ena, enabled, e).
func toggle(s *baseline.Service, arg string, n *parse.Node) {
	if strings.HasPrefix(arg, "e") {
		s.State, s.Line = baseline.StateEnabled, n.Line.Number
	}
}

// access decodes /c/sys/access: "snmp r|w|d" sets SNMP read-only,
// read-write or disabled. It reports read-write, which applies to the
// communities defined later in /c/sys/ssnmp.
func access(p *baseline.Posture, n *parse.Node) (write bool) {
	for _, c := range n.Children {
		cw := token.Split(c.Text)
		if !cw.Prefix("snmp") || cw.At(1) == "d" {
			continue
		}
		p.SNMP.State = baseline.StateEnabled
		p.SNMP.Versions = []string{"v1", "v2c"}
		write = write || cw.At(1) == "w"
	}
	return write
}

func ntp(p *baseline.Posture, n *parse.Node) {
	for _, c := range n.Children {
		w := token.Split(c.Text)
		switch w.At(0) {
		case "on":
			p.Time.NTPState = baseline.StateEnabled
		case "prisrv", "secsrv":
			rank := baseline.RankPrimary
			if w.At(0) == "secsrv" {
				rank = baseline.RankSecondary
			}
			if w.At(1) != "" && w.At(1) != "0.0.0.0" {
				p.Time.NTP = append(p.Time.NTP, baseline.Server{Host: w.At(1), Rank: rank, Line: c.Line.Number})
			}
		case "tzone":
			if d, ok := tz.ParseFormat(w.At(1)); ok {
				p.Time.Timezone = baseline.Timezone{Name: w.At(1), Offset: d, Set: true, Line: c.Line.Number}
			}
		}
	}
}

func syslog(p *baseline.Posture, n *parse.Node) {
	for _, c := range n.Children {
		w := token.Split(c.Text)
		if hostSlot.MatchString(w.At(0)) && w.At(1) != "0.0.0.0" {
			s := baseline.Server{Host: w.At(1), Rank: baseline.RankOrdered, Line: c.Line.Number}
			if len(w) > 5 {
				s.Port = w.Int(w.At(4))
			}
			p.Logging.Hosts = append(p.Logging.Hosts, s)
		}
	}
}

// aaa decodes /c/sys/tacacs and /c/sys/radius; it returns whether the
// protocol is on and whether local fallback is enabled.
func aaa(p *baseline.Posture, n *parse.Node, proto string) (on, local bool) {
	g := baseline.ServerGroup{Name: proto, Protocol: proto, Line: n.Line.Number}
	keyed := false
	local = true
	for _, c := range n.Children {
		w := token.Split(c.Text)
		switch w.At(0) {
		case "on":
			on = true
		case "prisrv", "secsrv":
			rank := baseline.RankPrimary
			if w.At(0) == "secsrv" {
				rank = baseline.RankSecondary
			}
			if w.At(1) != "" && w.At(1) != "0.0.0.0" {
				g.Servers = append(g.Servers, baseline.Server{Host: w.At(1), Rank: rank, Line: c.Line.Number})
			}
		case "esecret", "secret":
			keyed = true
		case "local":
			local = w.At(1) != "disabled"
		}
	}
	for i := range g.Servers {
		g.Servers[i].Keyed = keyed
	}
	if len(g.Servers) > 0 {
		p.AAA.Groups = append(p.AAA.Groups, g)
	}
	return on, local
}

func snmp(p *baseline.Posture, n *parse.Node) {
	for _, c := range n.Children {
		w := token.Split(c.Text)
		switch w.At(0) {
		case "rcomm", "wcomm":
			if w.At(1) != "" {
				p.SNMP.Communities = append(p.SNMP.Communities, baseline.Community{
					Name: secret.New(w.At(1)), Write: w.At(0) == "wcomm", Line: c.Line.Number,
				})
			}
		case "locn":
			p.SNMP.Location = strings.Join(w.From(1), " ")
		case "cont":
			p.SNMP.Contact = strings.Join(w.From(1), " ")
		case "trsrc", "timeout", "auth", "linkt", "name":
		}
	}
}
