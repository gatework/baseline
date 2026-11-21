package check

import (
	"slices"
	"strconv"
	"strings"

	"github.com/gatework/netops/assess"

	"github.com/gatework/baseline"
)

// maxListed bounds the ports named in one aggregated finding.
const maxListed = 10

func nacRules() []Rule {
	f := facets(baseline.FacetNAC)
	return []Rule{
		assess.Check(meta("nac.dot1x", titleNACDot1x, assess.SeverityMedium, assess.CategorySecurity, f),
			func(in Input) []assess.Finding {
				p := in.Model
				if p.NAC.Dot1x {
					return nil
				}
				return []assess.Finding{found(p, device(p).Child("nac", "dot1x"), 0, fixNAC, detailDisabled, "802.1X")}
			}),
		assess.Check(meta("nac.ports", titleNACPorts, assess.SeverityMedium, assess.CategorySecurity,
			facets(baseline.FacetNAC, baseline.FacetInterface), assess.List("exempt_descriptions"),
			assess.List("exempt_vlans")), nacPorts),
		assess.Check(meta("nac.domain", titleNACDomain, assess.SeverityMedium, assess.CategoryConfiguration, f,
			assess.Text("domain", "")), nacDomain),
		assess.Check(meta("nac.method", titleNACMethod, assess.SeverityLow, assess.CategorySecurity, f,
			assess.Text("method", "eap")), func(in Input) []assess.Finding {
			p := in.Model
			want := in.Params.Text("method")
			if !p.NAC.Dot1x || want == "" || strings.EqualFold(p.NAC.Method, want) {
				return nil
			}
			return []assess.Finding{found(p, device(p).Child("nac", "method"), p.NAC.Line, fixNAC, detailMethod, p.NAC.Method, want)}
		}),
	}
}

func interfaceRules() []Rule {
	f := facets(baseline.FacetInterface)
	return []Rule{
		assess.Check(meta("iface.edge", titleIfaceEdge, assess.SeverityLow, assess.CategoryConfiguration, f,
			assess.List("exempt_descriptions")), func(in Input) []assess.Finding {
			return ports(in, "edge", func(i baseline.Interface) bool { return i.EndHost() && !i.Edge })
		}),
		assess.Check(meta("iface.description", titleIfaceDescription, assess.SeverityInfo, assess.CategoryConfiguration, f,
			assess.List("exempt_descriptions")), func(in Input) []assess.Finding {
			return ports(in, "description", func(i baseline.Interface) bool {
				uplink := i.Kind == baseline.InterfacePhysical || i.Kind == baseline.InterfaceAggregate
				return uplink && !i.Shutdown && (i.Mode == baseline.PortTrunk || i.Mode == baseline.PortRouted) &&
					i.Description == ""
			})
		}),
		assess.Check(meta("iface.vlan1", titleIfaceVLAN1, assess.SeverityLow, assess.CategorySecurity, f,
			assess.List("exempt_descriptions")), func(in Input) []assess.Finding {
			return ports(in, "vlan1", func(i baseline.Interface) bool {
				return i.EndHost() && i.Mode == baseline.PortAccess && i.AccessVLAN == 1
			})
		}),
	}
}

func nacPorts(in Input) []assess.Finding {
	vlans := in.Params.List("exempt_vlans")
	return ports(in, "nac", func(i baseline.Interface) bool {
		if !i.EndHost() || i.Dot1x || i.MACAuth {
			return false
		}
		return i.AccessVLAN == 0 || !slices.Contains(vlans, strconv.Itoa(i.AccessVLAN))
	})
}

// ports aggregates the interfaces that bad selects, minus those whose
// description matches exempt_descriptions, into one finding per device.
func ports(in Input, kind string, bad func(baseline.Interface) bool) []assess.Finding {
	p := in.Model
	exempt := in.Params.List("exempt_descriptions")
	var names []string
	line := 0
	for _, i := range p.Interfaces {
		if !bad(i) || (i.Description != "" && anyGlob(exempt, i.Description)) {
			continue
		}
		if line == 0 {
			line = i.Line
		}
		names = append(names, i.Name)
	}
	if len(names) == 0 {
		return nil
	}
	f := found(p, device(p).Child("ports", kind), line, fixInterface, detailPorts, len(names), truncated(names, maxListed))
	f.Actual = strconv.Itoa(len(names))
	return []assess.Finding{f}
}

func nacDomain(in Input) []assess.Finding {
	p := in.Model
	want := in.Params.Text("domain")
	if want == "" || (!p.NAC.Dot1x && !p.NAC.MACAuth) {
		return nil
	}
	var out []assess.Finding
	for _, d := range p.NAC.Domains {
		if !strings.EqualFold(d, want) {
			f := found(p, device(p).Child("nac-domain", d), p.NAC.Line, fixNAC, detailDomain, d, want)
			f.Expected, f.Actual = want, d
			out = append(out, f)
		}
	}
	return out
}
