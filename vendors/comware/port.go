package comware

import (
	"strings"

	"github.com/gatework/netops/parse"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/internal/token"
)

// nac decodes global dot1x and mac-authentication statements. Timers,
// retries and user-name formats are not part of the model.
func (x *extraction) nac(n *parse.Node, w token.Words, undo bool) {
	nac := &x.p.NAC
	switch {
	case len(w) == 1 && w.At(0) == "dot1x":
		nac.Dot1x, nac.Line = !undo, n.Line.Number
		if nac.Method == "" {
			nac.Method = "chap"
		}
	case len(w) == 1 && w.At(0) == "mac-authentication":
		nac.MACAuth = !undo
	case undo:
	case w.Prefix("dot1x", "authentication-method"):
		nac.Method = w.At(2)
	case w.Prefix("dot1x", "mandatory-domain"), w.Prefix("mac-authentication", "domain"):
		nac.AddDomain(w.At(2))
	}
}

// iface decodes an "interface NAME" block.
func (x *extraction) iface(n *parse.Node, w token.Words) {
	name := strings.Join(w.From(1), " ")
	i := baseline.Interface{Name: name, Kind: interfaceKind(name), Line: n.Line.Number}
	if i.Kind == baseline.InterfacePhysical || i.Kind == baseline.InterfaceAggregate {
		i.Mode = baseline.PortAccess
	}
	if i.Kind == baseline.InterfaceVLAN || i.Kind == baseline.InterfaceLoopback || i.Kind == baseline.InterfaceMgmt ||
		strings.HasPrefix(name, "Route-Aggregation") {
		i.Mode = baseline.PortRouted
	}
	for _, c := range n.Children {
		cw := token.Split(c.Text)
		switch {
		case cw.Prefix("shutdown"):
			i.Shutdown = true
		case cw.Prefix("description"):
			i.Description = strings.Join(cw.From(1), " ")
		case cw.Prefix("port", "link-mode", "route"):
			i.Mode = baseline.PortRouted
		case cw.Prefix("port", "link-type"):
			i.Mode = portMode(cw.At(2))
		case cw.Prefix("port", "access", "vlan"):
			i.AccessVLAN = cw.Int("vlan")
		case cw.Prefix("port", "link-aggregation", "group"):
			i.Member = true
		case cw.Prefix("stp", "edged-port"):
			i.Edge = true
		case len(cw) == 1 && cw.At(0) == "dot1x":
			i.Dot1x = true
		case len(cw) == 1 && cw.At(0) == "mac-authentication":
			i.MACAuth = true
		case cw.Prefix("dot1x", "mandatory-domain"), cw.Prefix("mac-authentication", "domain"):
			i.Domain = cw.At(2)
		case cw.Prefix("loopback-detection") && cw.At(1) != "action":
			i.LoopDetect = true
		}
	}
	if i.Mode == baseline.PortAccess && i.AccessVLAN == 0 {
		i.AccessVLAN = 1
	}
	x.p.Interfaces = append(x.p.Interfaces, i)
}

// acl decodes "acl number N [name X]", "acl basic|advanced|mac|ipv6 ...
// N|name X" and counts its rules.
func (x *extraction) acl(n *parse.Node, w token.Words) {
	rest := w.From(1)
	for rest.At(0) == "ipv6" || rest.At(0) == "basic" || rest.At(0) == "advanced" || rest.At(0) == "mac" ||
		rest.At(0) == "number" {
		rest = rest.From(1)
	}
	var keys []string
	if rest.At(0) == "name" {
		keys = append(keys, rest.At(1))
	} else if rest.At(0) != "" {
		keys = append(keys, rest.At(0))
		if name, ok := rest.After("name"); ok {
			keys = append(keys, name)
		}
	}
	rules := 0
	for _, c := range n.Children {
		if strings.HasPrefix(c.Text, "rule ") {
			rules++
		}
	}
	for _, k := range keys {
		x.p.ACLs[k] = baseline.ACL{Name: k, Rules: rules, Line: n.Line.Number}
	}
}

func interfaceKind(name string) baseline.InterfaceKind {
	switch {
	case strings.HasPrefix(name, "M-"):
		return baseline.InterfaceMgmt
	case strings.HasPrefix(name, "Bridge-Aggregation"), strings.HasPrefix(name, "Route-Aggregation"):
		return baseline.InterfaceAggregate
	case strings.HasPrefix(name, "Vlan-interface"):
		return baseline.InterfaceVLAN
	case strings.HasPrefix(name, "LoopBack"):
		return baseline.InterfaceLoopback
	case strings.Contains(name, "Ethernet"), strings.HasPrefix(name, "FortyGigE"), strings.HasPrefix(name, "HundredGigE"),
		strings.HasPrefix(name, "TwentyFiveGigE"), strings.HasPrefix(name, "Smartrate"):
		return baseline.InterfacePhysical
	}
	return baseline.InterfaceOther
}

func portMode(word string) baseline.PortMode {
	switch word {
	case "access":
		return baseline.PortAccess
	case "trunk":
		return baseline.PortTrunk
	case "hybrid":
		return baseline.PortHybrid
	}
	return baseline.PortUnknown
}
