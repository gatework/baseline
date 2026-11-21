package nxos

import (
	"github.com/gatework/netops/parse"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/internal/token"
)

// aaaServer decodes "tacacs-server host A [key [0|7] K] [port N]",
// "radius-server host A ..." and the global "tacacs-server key".
func (x *extraction) aaaServer(n *parse.Node, w token.Words, no bool) {
	proto := protocol(w.At(0))
	switch {
	case no:
	case w.At(1) == "host":
		s := baseline.Server{Host: w.At(2), Keyed: w.Has("key"), Line: n.Line.Number}
		s.Port = w.Int("port")
		if s.Port == 0 {
			s.Port = w.Int("auth-port")
		}
		x.hosts[proto+" "+s.Host] = s
	case w.At(1) == "key":
		x.keyed[proto] = true
	case w.At(1) == "timeout", w.At(1) == "deadtime", w.At(1) == "directed-request", w.At(1) == "retransmit":
	default:
		x.unknown(n, baseline.FacetAAA)
	}
}

// aaa decodes aaa group server blocks and method lists.
func (x *extraction) aaa(n *parse.Node, w token.Words) {
	switch {
	case w.Prefix("aaa", "group", "server"):
		name := w.At(4)
		x.p.AAA.Groups = append(x.p.AAA.Groups, baseline.ServerGroup{
			Name: name, Protocol: protocol(w.At(3)), Line: n.Line.Number,
		})
		proto := protocol(w.At(3))
		var o groupOptions
		for _, c := range n.Children {
			cw := token.Split(c.Text)
			switch cw.At(0) {
			case "server":
				x.members = append(x.members, member{group: name, protocol: proto, host: cw.At(1), line: c.Line.Number})
			case "use-vrf":
				o.vrf = cw.At(1)
			case "source-interface":
				o.source = cw.At(1)
			case "deadtime":
			default:
				x.unknown(c, baseline.FacetAAA)
			}
		}
		x.groupOpts[name] = o
	case w.Prefix("aaa", "authentication", "login"):
		switch w.At(3) {
		case "default", "console":
			set := x.set(w.At(3), n)
			set.Login = methods(w.From(4), true)
		case "error-enable", "ascii-authentication", "mschap", "mschapv2", "chap":
		default:
			x.unknown(n, baseline.FacetAAA)
		}
	case w.Prefix("aaa", "authorization", "commands"), w.Prefix("aaa", "authorization", "config-commands"):
		if w.At(3) == "default" {
			set := x.set("default", n)
			if len(set.Commands) == 0 || w.At(2) == "commands" {
				set.Commands = methods(w.From(4), false)
			}
		}
	case w.Prefix("aaa", "accounting", "default"):
		set := x.set("default", n)
		set.Accounting = methods(w.From(3), false)
		set.CommandAccounting = set.Accounting
	case w.Prefix("aaa", "authorization"), w.Prefix("aaa", "user"), w.Prefix("aaa", "accounting"),
		w.Prefix("aaa", "authentication"):
	default:
		x.unknown(n, baseline.FacetAAA)
	}
}

// set returns the method set named name, creating it.
func (x *extraction) set(name string, n *parse.Node) *baseline.MethodSet {
	for i := range x.p.AAA.Sets {
		if x.p.AAA.Sets[i].Name == name {
			return &x.p.AAA.Sets[i]
		}
	}
	x.p.AAA.Sets = append(x.p.AAA.Sets, baseline.MethodSet{Name: name, Line: n.Line.Number})
	return &x.p.AAA.Sets[len(x.p.AAA.Sets)-1]
}

// methods decodes "group G1 G2 local none". With login, a list that does
// not end in none or local falls back to local, as NX-OS does when every
// server is unreachable.
func methods(w token.Words, login bool) baseline.MethodList {
	var out baseline.MethodList
	for i := 0; i < len(w); i++ {
		switch w[i] {
		case "group":
			for i+1 < len(w) && w[i+1] != "local" && w[i+1] != "none" {
				i++
				out = append(out, baseline.Method{Kind: baseline.MethodGroup, Group: w[i]})
			}
		case "local":
			out = append(out, baseline.Method{Kind: baseline.MethodLocal})
		case "none":
			out = append(out, baseline.Method{Kind: baseline.MethodNone})
		}
	}
	if login && out.Remote() && !out.Has(baseline.MethodNone) && !out.Has(baseline.MethodLocal) {
		out = append(out, baseline.Method{Kind: baseline.MethodLocal})
	}
	return out
}

func protocol(word string) string {
	switch word {
	case "tacacs-server", "tacacs+", "tacacs":
		return "tacacs"
	case "radius-server", "radius":
		return "radius"
	}
	return word
}
