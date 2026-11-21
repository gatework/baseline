package nxos

import (
	"cmp"
	"context"
	"regexp"
	"slices"

	"github.com/gatework/netops/config"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/parse"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/internal/token"
)

// echo is the command echo that starts a captured configuration.
var echo = regexp.MustCompile(`^show running-config`)

// Name is the vendor key of this extractor.
const Name = "nxos"

// Extractor decodes NX-OS configurations. It is stateless and safe for
// concurrent use.
type Extractor struct{}

// New returns an NX-OS extractor.
func New() *Extractor { return &Extractor{} }

// Vendor returns "nxos".
func (*Extractor) Vendor() string { return Name }

// Dialect returns the Cisco configuration dialect.
func (*Extractor) Dialect() config.Dialect {
	d := config.Cisco()
	d.Name = Name
	d.Volatile = append(d.Volatile, echo)
	return d
}

// Extract builds the posture of d from doc.
func (e *Extractor) Extract(ctx context.Context, d device.Device, doc *config.Document) (baseline.Extraction, error) {
	x := &extraction{
		p:     &baseline.Posture{Device: d, Config: doc, ACLs: map[string]baseline.ACL{}},
		tally: baseline.NewTally(d.ID, Name, baseline.Facets()...),
		hosts: map[string]baseline.Server{},
		users: map[string]int{}, keyed: map[string]bool{}, groupOpts: map[string]groupOptions{},
	}
	p := x.p
	p.AAA.Default = "default"
	p.Logging.State = baseline.StateEnabled
	p.Services.SSH.State = baseline.StateEnabled
	for _, s := range []*baseline.Service{&p.Services.Telnet, &p.Services.SSHv1, &p.Services.HTTP,
		&p.Services.HTTPS, &p.Services.NETCONF} {
		s.State = baseline.StateDisabled
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
	p       *baseline.Posture
	tally   *baseline.Tally
	hosts   map[string]baseline.Server // tacacs-server/radius-server host by protocol+address
	users   map[string]int             // account index by name
	keyed   map[string]bool            // global key per protocol
	members []member
	// groupOpts holds the use-vrf and source-interface of each aaa group.
	groupOpts map[string]groupOptions
	lines     []*parse.Node
}

type groupOptions struct{ vrf, source string }

// member is one "server A" line of an aaa group, resolved in finish.
type member struct {
	group, protocol, host string
	line                  int
}

func (x *extraction) statement(n *parse.Node) {
	w := token.Split(n.Text)
	no := w.At(0) == "no"
	if no {
		w = w.From(1)
	}
	switch w.At(0) {
	case "hostname", "switchname":
		x.p.Hostname = w.At(1)
	case "version":
		x.p.Version = w.At(1)
	case "feature":
		x.feature(w, no)
	case "nxapi":
		if w.At(1) == "http" {
			x.p.Services.HTTP.State, x.p.Services.HTTP.Line = baseline.StateEnabled, n.Line.Number
		}
	case "ssh":
		if w.Prefix("ssh", "login-attempts") || w.Prefix("ssh", "key") || w.Prefix("ssh", "idle-timeout") {
			return
		}
	case "tacacs-server", "radius-server":
		x.aaaServer(n, w, no)
	case "aaa":
		x.aaa(n, w)
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
	case "interface":
		x.iface(n, w)
	case "ip", "ipv6":
		if w.At(1) == "access-list" {
			x.acl(n, w)
		}
		if w.At(1) == "tacacs" || w.At(1) == "radius" {
			return
		}
	case "dot1x":
		x.p.NAC.Dot1x = !no
	}
}

// feature records "[no] feature X" switches.
func (x *extraction) feature(w token.Words, no bool) {
	state := baseline.StateEnabled
	if no {
		state = baseline.StateDisabled
	}
	s := &x.p.Services
	switch w.At(1) {
	case "telnet":
		s.Telnet.State = state
	case "ssh":
		s.SSH.State = state
	case "nxapi":
		s.HTTPS.State = state
	case "netconf":
		s.NETCONF.State = state
	case "dot1x":
		x.p.NAC.Dot1x = !no
	}
}

func (x *extraction) finish() {
	x.resolveGroups()
	// Without "aaa authentication login default", logins are local.
	if _, ok := x.p.AAA.Set("default"); !ok {
		x.p.AAA.Sets = append(x.p.AAA.Sets, baseline.MethodSet{Name: "default", Login: baseline.MethodList{{Kind: baseline.MethodLocal}}})
	}
	// NX-OS command authorization and accounting are global: they apply
	// to every line once the method list is configured.
	set, _ := x.p.AAA.Set(x.p.AAA.Default)
	for _, n := range x.lines {
		l := x.decodeLine(n)
		l.CommandAuthorization = len(set.Commands) > 0
		l.CommandAccounting = len(set.CommandAccounting) > 0
		x.p.Lines = append(x.p.Lines, l)
	}
	if x.p.SNMP.State == baseline.StateUnset {
		x.p.SNMP.State = baseline.StateDisabled
	}
	if len(x.p.Time.NTP) > 0 {
		x.p.Time.NTPState = baseline.StateEnabled
	} else {
		x.p.Time.NTPState = baseline.StateDisabled
	}
	for i := range x.p.AAA.Sets {
		set := &x.p.AAA.Sets[i]
		if len(set.Authorization) == 0 {
			set.Authorization = set.Login
		}
		for _, l := range []baseline.MethodList{set.Login, set.Authorization, set.Commands, set.Accounting, set.CommandAccounting} {
			for j := range l {
				if g, ok := x.p.AAA.Group(l[j].Group); ok && l[j].Kind == baseline.MethodGroup {
					l[j].Protocol = g.Protocol
				}
			}
		}
	}
}

// resolveGroups builds the server groups from their member lines and the
// global host definitions, which carry ports and keys.
func (x *extraction) resolveGroups() {
	for _, m := range x.members {
		i := slices.IndexFunc(x.p.AAA.Groups, func(g baseline.ServerGroup) bool { return g.Name == m.group })
		if i < 0 {
			continue
		}
		s, ok := x.hosts[m.protocol+" "+m.host]
		if !ok {
			s = baseline.Server{Host: m.host}
		}
		s.Rank, s.Line = baseline.RankOrdered, m.line
		s.Keyed = s.Keyed || x.keyed[m.protocol]
		o := x.groupOpts[m.group]
		s.VRF, s.Source = cmp.Or(s.VRF, o.vrf), cmp.Or(s.Source, o.source)
		x.p.AAA.Groups[i].Servers = append(x.p.AAA.Groups[i].Servers, s)
	}
}

func (x *extraction) unknown(n *parse.Node, facet evidence.Dimension) {
	x.tally.Unrecognized(facet, n.Line.Number, token.Keyword(n, x.p.Config.Dialect()))
}
