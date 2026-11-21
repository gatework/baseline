package comware

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gatework/netops/parse"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/internal/token"
)

// defaultIdle is the Comware default idle timeout of every line.
const defaultIdle = 10 * time.Minute

// lineIgnored lists line options the model does not hold.
var lineIgnored = []string{
	"user-role", "screen-length", "history-command", "escape-key", "shell", "terminal", "auto-execute",
	"speed", "flow-control", "parity", "stopbits", "databits", "activation-key", "lock-key", "undo", "sendmode",
	"authorization-attribute", "user", "level", "protocol-link",
}

// line records a "line" or "user-interface" block; lines are decoded in
// finish, once every line class is known.
func (x *extraction) line(n *parse.Node, w token.Words) {
	if w.At(1) == "class" {
		if k, ok := lineKind(w.At(2)); ok {
			x.lineClass[k] = n
		}
		return
	}
	if _, ok := lineKind(w.At(1)); !ok {
		x.unknown(n, baseline.FacetLine)
		return
	}
	x.lines = append(x.lines, n)
}

// decodeLine applies Comware defaults, then the line class, then the
// line's own options.
func (x *extraction) decodeLine(n *parse.Node) baseline.Line {
	w := token.Split(n.Text)
	k, _ := lineKind(w.At(1))
	l := baseline.Line{Kind: k, Range: strings.Join(w.From(2), " "), Idle: defaultIdle, IdleSet: true, Line: n.Line.Number}
	switch k {
	case baseline.LineVTY:
		l.Auth = baseline.LineAuthPassword
		l.Protocols = []string{"ssh", "telnet"}
	case baseline.LineConsole, baseline.LineAux:
		l.Auth = baseline.LineAuthNone
	}
	if class, ok := x.lineClass[k]; ok {
		x.lineOptions(&l, class)
	}
	x.lineOptions(&l, n)
	return l
}

func (x *extraction) lineOptions(l *baseline.Line, n *parse.Node) {
	for _, c := range n.Children {
		w := token.Split(c.Text)
		switch {
		case w.Prefix("authentication-mode"):
			switch w.At(1) {
			case "none":
				l.Auth = baseline.LineAuthNone
			case "password":
				l.Auth = baseline.LineAuthPassword
			case "scheme":
				l.Auth = baseline.LineAuthAAA
			default:
				x.unknown(c, baseline.FacetLine)
			}
		case w.Prefix("set", "authentication", "password"):
			l.PasswordSet = true
		case w.Prefix("protocol", "inbound"):
			switch w.At(2) {
			case "all":
				l.Protocols = []string{"ssh", "telnet"}
			case "ssh", "telnet":
				l.Protocols = []string{w.At(2)}
			case "pad":
				l.Protocols = []string{}
			default:
				x.unknown(c, baseline.FacetLine)
			}
		case w.Prefix("idle-timeout"):
			minutes, err1 := strconv.Atoi(w.At(1))
			seconds, err2 := strconv.Atoi(cmp.Or(w.At(2), "0"))
			if err1 != nil || err2 != nil {
				x.unknown(c, baseline.FacetLine)
				continue
			}
			l.Idle = time.Duration(minutes)*time.Minute + time.Duration(seconds)*time.Second
		case w.Prefix("acl"):
			l.ACL = aclRef(w.From(1))
		case w.Prefix("command", "authorization"):
			l.CommandAuthorization = true
		case w.Prefix("command", "accounting"):
			l.CommandAccounting = true
		case slices.Contains(lineIgnored, w.At(0)), w.Prefix("set", "authentication"):
		default:
			x.unknown(c, baseline.FacetLine)
		}
	}
}

// service decodes ssh/telnet/http/https/netconf/sftp/scp switches.
func (x *extraction) service(n *parse.Node, w token.Words, undo bool) {
	s := &x.p.Services
	state := baseline.StateEnabled
	if undo {
		state = baseline.StateDisabled
	}
	set := func(svc *baseline.Service) {
		svc.State, svc.Line = state, n.Line.Number
	}
	switch {
	case w.Prefix("ssh", "server", "enable"), w.Prefix("stelnet", "server", "enable"):
		set(&s.SSH)
	case w.Prefix("ssh", "server", "compatible-ssh1x"):
		set(&s.SSHv1)
	case w.Prefix("ssh", "server", "acl"):
		s.SSH.ACL = aclRef(w.From(3))
	case w.Prefix("telnet", "server", "enable"):
		set(&s.Telnet)
	case w.Prefix("telnet", "server", "acl"):
		s.Telnet.ACL = aclRef(w.From(3))
	case w.Prefix("ip", "http", "enable"):
		set(&s.HTTP)
	case w.Prefix("ip", "http", "acl"):
		s.HTTP.ACL = aclRef(w.From(3))
	case w.Prefix("ip", "https", "enable"):
		set(&s.HTTPS)
	case w.Prefix("ip", "https", "acl"):
		s.HTTPS.ACL = aclRef(w.From(3))
	case w.Prefix("netconf") && w.At(len(w)-1) == "enable":
		set(&s.NETCONF)
	case w.Prefix("ssh", "server"), w.Prefix("ssh", "user"), w.Prefix("ssh", "client"), w.Prefix("ssh2"),
		w.Prefix("telnet", "client"), w.Prefix("sftp"), w.Prefix("scp"), w.Prefix("ip", "http"),
		w.Prefix("ip", "https"), w.Prefix("netconf"), w.Prefix("stelnet"):
	default:
		x.unknown(n, baseline.FacetService)
	}
}

// accountIgnored lists local-user options the model does not hold.
var accountIgnored = []string{
	"password-control", "undo", "access-limit", "state", "group", "description", "bind-attribute",
	"validity-datetime", "identity-group", "user-role", "level", "work-directory",
}

// account decodes "local-user NAME [class manage|network]". Network-class
// users are 802.1X/portal users and do not log in to the device.
func (x *extraction) account(n *parse.Node, w token.Words) {
	if class, ok := w.After("class"); ok && class != "manage" {
		return
	}
	// Comware allows no service until service-type names one.
	a := baseline.Account{Name: w.At(1), Services: []string{}, Line: n.Line.Number}
	for _, c := range n.Children {
		cw := token.Split(c.Text)
		switch {
		case cw.Prefix("password"):
			a.PasswordSet = true
			a.Hashed = cw.At(1) == "hash"
		case cw.Prefix("service-type"):
			a.Services = append(a.Services, cw.From(1)...)
		case cw.Prefix("authorization-attribute", "user-role"):
			a.Roles = append(a.Roles, cw.At(2))
			a.Admin = a.Admin || cw.At(2) == "network-admin" || cw.At(2) == "level-15"
		case cw.Prefix("authorization-attribute", "level"):
			a.Roles = append(a.Roles, "level-"+cw.At(2))
			a.Admin = a.Admin || cw.At(2) == "3"
		case cw.Prefix("authorization-attribute"), slices.Contains(accountIgnored, cw.At(0)):
		default:
			x.unknown(c, baseline.FacetAccount)
		}
	}
	x.p.Accounts = append(x.p.Accounts, a)
}

func lineKind(word string) (baseline.LineKind, bool) {
	switch word {
	case "vty":
		return baseline.LineVTY, true
	case "aux":
		return baseline.LineAux, true
	case "console", "con":
		return baseline.LineConsole, true
	}
	return "", false
}

// aclRef decodes "[ipv6] [mac] N|name X [inbound]" into the ACL key.
func aclRef(w token.Words) string {
	for len(w) > 0 && (w[0] == "ipv6" || w[0] == "mac" || w[0] == "number") {
		w = w.From(1)
	}
	if w.At(0) == "name" {
		return w.At(1)
	}
	return w.At(0)
}
