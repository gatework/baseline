package nxos

import (
	"strconv"
	"strings"
	"time"

	"github.com/gatework/netops/parse"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/internal/token"
)

// decodeLine decodes "line console" and "line vty" blocks. NX-OS lines
// always authenticate through AAA; the console uses the "console" method
// set when one is configured.
func (x *extraction) decodeLine(n *parse.Node) baseline.Line {
	w := token.Split(n.Text)
	l := baseline.Line{Auth: baseline.LineAuthAAA, Line: n.Line.Number}
	switch w.At(1) {
	case "vty":
		l.Kind = baseline.LineVTY
		l.Protocols = []string{}
		if x.p.Services.SSH.State.Enabled() {
			l.Protocols = append(l.Protocols, "ssh")
		}
		if x.p.Services.Telnet.State.Enabled() {
			l.Protocols = append(l.Protocols, "telnet")
		}
	case "console":
		l.Kind = baseline.LineConsole
		if _, ok := x.p.AAA.Set("console"); ok {
			l.MethodSet = "console"
		}
	default:
		l.Kind = baseline.LineAux
	}
	for _, c := range n.Children {
		cw := token.Split(c.Text)
		switch cw.At(0) {
		case "exec-timeout":
			m, err := strconv.Atoi(cw.At(1))
			if err != nil {
				x.unknown(c, baseline.FacetLine)
				continue
			}
			l.Idle, l.IdleSet = time.Duration(m)*time.Minute, true
		case "access-class":
			l.ACL = cw.At(1)
		case "ipv6", "session-limit", "speed", "databits", "stopbits", "parity", "modem", "absolute-timeout":
		default:
			x.unknown(c, baseline.FacetLine)
		}
	}
	return l
}

// account decodes "username NAME [password 5 H] [role R] [passphrase ...]".
// One user may span several statements.
func (x *extraction) account(n *parse.Node, w token.Words) {
	name := w.At(1)
	i, ok := x.users[name]
	if !ok {
		i = len(x.p.Accounts)
		x.users[name] = i
		x.p.Accounts = append(x.p.Accounts, baseline.Account{Name: name, Line: n.Line.Number})
	}
	a := &x.p.Accounts[i]
	if pw, ok := w.After("password"); ok {
		hash, _ := w.After(pw)
		// "password 5 !" is a locked account with no usable password.
		a.PasswordSet = hash != "!" && hash != ""
		a.Hashed = pw == "5" || pw == "8" || pw == "9"
	}
	for j := range w {
		if w[j] == "role" && j+1 < len(w) {
			a.Roles = append(a.Roles, w[j+1])
			a.Admin = a.Admin || w[j+1] == "network-admin"
		}
	}
}

// acl decodes "ip access-list NAME" and counts its entries.
func (x *extraction) acl(n *parse.Node, w token.Words) {
	rules := 0
	for _, c := range n.Children {
		if c.Text != "" && c.Text[0] >= '0' && c.Text[0] <= '9' {
			rules++
		}
	}
	x.p.ACLs[w.At(2)] = baseline.ACL{Name: w.At(2), Rules: rules, Line: n.Line.Number}
}

// iface decodes an "interface NAME" block.
func (x *extraction) iface(n *parse.Node, w token.Words) {
	name := strings.Join(w.From(1), " ")
	i := baseline.Interface{Name: name, Kind: interfaceKind(name), Line: n.Line.Number}
	physical := i.Kind == baseline.InterfacePhysical
	if physical || i.Kind == baseline.InterfaceAggregate || i.Kind == baseline.InterfaceVLAN ||
		i.Kind == baseline.InterfaceLoopback || i.Kind == baseline.InterfaceMgmt {
		i.Mode = baseline.PortRouted
	}
	// Ethernet ports are shut down by default; the configuration shows
	// "no shutdown" for every port that is up.
	i.Shutdown = physical
	for _, c := range n.Children {
		cw := token.Split(c.Text)
		switch {
		case cw.Prefix("shutdown"):
			i.Shutdown = true
		case cw.Prefix("no", "shutdown"):
			i.Shutdown = false
		case cw.Prefix("description"):
			i.Description = strings.Join(cw.From(1), " ")
		case len(cw) == 1 && cw.At(0) == "switchport":
			if i.Mode == baseline.PortRouted {
				i.Mode = baseline.PortAccess
			}
		case cw.Prefix("no", "switchport"):
			i.Mode = baseline.PortRouted
		case cw.Prefix("switchport", "mode"):
			switch cw.At(2) {
			case "trunk":
				i.Mode = baseline.PortTrunk
			case "access":
				i.Mode = baseline.PortAccess
			}
		case cw.Prefix("switchport", "access", "vlan"):
			i.AccessVLAN = cw.Int("vlan")
		case cw.Prefix("channel-group"):
			i.Member = true
		case cw.Prefix("spanning-tree", "port", "type") && strings.HasPrefix(cw.At(3), "edge"):
			i.Edge = true
		case cw.Prefix("dot1x"):
			i.Dot1x = true
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
	case strings.HasPrefix(lower, "mgmt"):
		return baseline.InterfaceMgmt
	case strings.HasPrefix(lower, "port-channel"):
		return baseline.InterfaceAggregate
	case strings.HasPrefix(lower, "vlan"):
		return baseline.InterfaceVLAN
	case strings.HasPrefix(lower, "loopback"):
		return baseline.InterfaceLoopback
	case strings.HasPrefix(lower, "ethernet"):
		return baseline.InterfacePhysical
	}
	return baseline.InterfaceOther
}
