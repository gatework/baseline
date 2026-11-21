package comware

import (
	"strings"

	"github.com/gatework/netops/parse"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/internal/token"
)

// aaaScheme decodes "hwtacacs scheme NAME" and "radius scheme NAME"
// blocks. Other hwtacacs/radius statements (nas-ip, dynamic-author,
// session-control) are global options the model does not hold.
func (x *extraction) aaaScheme(n *parse.Node, w token.Words) {
	if w.At(1) != "scheme" {
		return
	}
	g := baseline.ServerGroup{Name: w.At(2), Protocol: protocol(w.At(0)), Line: n.Line.Number}
	keyed := map[string]bool{}
	var vrf string
	for _, c := range n.Children {
		cw := token.Split(c.Text)
		switch cw.At(0) {
		case "primary", "secondary":
			s, ok := schemeServer(cw)
			if !ok {
				x.unknown(c, baseline.FacetAAA)
				continue
			}
			s.Line = c.Line.Number
			g.Servers = append(g.Servers, s)
		case "key":
			keyed[cw.At(1)] = true
		case "vpn-instance":
			vrf = cw.At(1)
		case "nas-ip", "user-name-format", "timer", "accounting-on", "attribute", "retry", "data-flow-format",
			"response-pending-limit", "server-load-sharing", "stop-accounting-buffer", "security-policy-server":
		default:
			x.unknown(c, baseline.FacetAAA)
		}
	}
	for i := range g.Servers {
		s := &g.Servers[i]
		s.Keyed = s.Keyed || keyed[s.Function]
		if s.VRF == "" {
			s.VRF = vrf
		}
	}
	x.p.AAA.Groups = append(x.p.AAA.Groups, g)
}

// schemeServer decodes "primary|secondary FUNCTION [ipv6] HOST [port N]
// [vpn-instance V] [key ...]".
func schemeServer(w token.Words) (baseline.Server, bool) {
	s := baseline.Server{Rank: baseline.RankPrimary, Function: w.At(1)}
	if w.At(0) == "secondary" {
		s.Rank = baseline.RankSecondary
	}
	switch s.Function {
	case "authentication", "authorization", "accounting":
	default:
		return s, false
	}
	rest := w.From(2)
	if rest.At(0) == "ipv6" {
		rest = rest.From(1)
	}
	s.Host = rest.At(0)
	if s.Host == "" {
		return s, false
	}
	s.Port = rest.Int("port")
	s.VRF, _ = rest.After("vpn-instance")
	s.Keyed = rest.Has("key")
	return s, true
}

// domain decodes "domain NAME" blocks and "domain default enable NAME".
func (x *extraction) domain(n *parse.Node, w token.Words, undo bool) {
	if w.At(1) == "default" {
		if w.At(2) == "enable" && !undo {
			x.p.AAA.Default = w.At(3)
		}
		return
	}
	if undo || len(w) != 2 {
		return
	}
	set := baseline.MethodSet{Name: w.At(1), Line: n.Line.Number}
	var def struct{ authn, authz, acct baseline.MethodList }
	var cmdAcct baseline.MethodList
	for _, c := range n.Children {
		cw := token.Split(c.Text)
		var list baseline.MethodList
		if len(cw) >= 3 {
			list = methods(cw.From(2))
		}
		switch {
		case cw.Prefix("authentication", "login"):
			set.Login = list
		case cw.Prefix("authorization", "login"):
			set.Authorization = list
		case cw.Prefix("authorization", "command"):
			set.Commands = list
		case cw.Prefix("accounting", "login"):
			set.Accounting = list
		case cw.Prefix("accounting", "command"):
			cmdAcct = list
		case cw.Prefix("authentication", "default"):
			def.authn = list
		case cw.Prefix("authorization", "default"):
			def.authz = list
		case cw.Prefix("accounting", "default"):
			def.acct = list
		}
	}
	// Login-specific methods fall back to the domain's default methods.
	set.Login = or(set.Login, def.authn)
	set.Authorization = or(set.Authorization, def.authz)
	set.Commands = or(set.Commands, def.authz)
	set.Accounting = or(set.Accounting, def.acct)
	set.CommandAccounting = or(cmdAcct, def.acct)
	// Comware's own default is local for every function.
	local := baseline.MethodList{{Kind: baseline.MethodLocal}}
	set.Login = or(set.Login, local)
	set.Authorization = or(set.Authorization, local)
	set.Accounting = or(set.Accounting, local)
	x.p.AAA.Sets = append(x.p.AAA.Sets, set)
}

// methods decodes "hwtacacs-scheme tac radius-scheme rad local none".
func methods(w token.Words) baseline.MethodList {
	var out baseline.MethodList
	for i := 0; i < len(w); i++ {
		switch t := w[i]; {
		case t == "local":
			out = append(out, baseline.Method{Kind: baseline.MethodLocal})
		case t == "none":
			out = append(out, baseline.Method{Kind: baseline.MethodNone})
		case strings.HasSuffix(t, "-scheme") && i+1 < len(w):
			out = append(out, baseline.Method{
				Kind: baseline.MethodGroup, Protocol: protocol(strings.TrimSuffix(t, "-scheme")), Group: w[i+1],
			})
			i++
		}
	}
	return out
}

func protocol(word string) string {
	if word == "hwtacacs" {
		return "tacacs"
	}
	return word
}

func or(a, b baseline.MethodList) baseline.MethodList {
	if len(a) > 0 {
		return a
	}
	return b
}
