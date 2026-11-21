package check

import (
	"context"
	"slices"

	"github.com/gatework/netops/assess"

	"github.com/gatework/baseline"
)

func aaaRules() []Rule {
	// Lines only name method sets; without them the default set applies.
	aaa := facets(baseline.FacetAAA)
	return []Rule{
		assess.Check(meta("aaa.login_remote", titleAAALogin, assess.SeverityHigh, assess.CategorySecurity, aaa,
			assess.Text("protocol", "")), loginRemote),
		assess.Check(meta("aaa.login_fallback", titleAAAFallback, assess.SeverityHigh, assess.CategorySecurity, aaa),
			loginFallback),
		assess.Check(meta("aaa.command_authorization", titleAAACommandAuthz, assess.SeverityMedium,
			assess.CategorySecurity, aaa), commandAuthorization),
		assess.Check(meta("aaa.accounting", titleAAAAccounting, assess.SeverityMedium, assess.CategoryCompliance, aaa),
			accounting),
		assess.NewRule(meta("aaa.servers", titleAAAServers, assess.SeverityMedium, assess.CategoryConfiguration, aaa,
			serverParams(2)...), aaaServers),
		assess.Check(meta("aaa.server_rank", titleAAAServerRank, assess.SeverityMedium, assess.CategoryConfiguration,
			facets(baseline.FacetAAA)), serverRank),
		assess.Check(meta("aaa.server_key", titleAAAServerKey, assess.SeverityHigh, assess.CategorySecurity, aaa),
			serverKey),
	}
}

// managed is a management method set with the subject to report it under.
type managed struct {
	set     baseline.MethodSet
	subject assess.Subject
	found   bool
	name    string
}

// managementSets returns the distinct method sets that usable VTY lines
// use, or the default set when the device has no such line.
func managementSets(p *baseline.Posture) []managed {
	var names []string
	for _, l := range p.LinesOf(baseline.LineVTY) {
		if name := l.MethodSet; l.Usable() && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		names = []string{""}
	}
	out := make([]managed, 0, len(names))
	for _, name := range names {
		set, ok := p.AAA.Management(name)
		label := name
		if label == "" {
			label = p.AAA.Default
		}
		out = append(out, managed{set: set, found: ok, name: label, subject: device(p).Child("aaa", label)})
	}
	return out
}

func loginRemote(in Input) []assess.Finding {
	p := in.Model
	var out []assess.Finding
	for _, m := range managementSets(p) {
		switch {
		case !m.found:
			out = append(out, found(p, m.subject, 0, fixAAA, detailNoManagementSet, m.name))
		case !m.set.Login.Remote():
			out = append(out, found(p, m.subject, m.set.Line, fixAAA, detailLoginLocal, m.set.Login))
		case in.Params.Text("protocol") != "" && m.set.Login[0].Protocol != in.Params.Text("protocol"):
			out = append(out, found(p, m.subject, m.set.Line, fixAAA, detailLoginProtocol, m.set.Login, in.Params.Text("protocol")))
		}
	}
	return out
}

func loginFallback(in Input) []assess.Finding {
	p := in.Model
	var out []assess.Finding
	for _, m := range managementSets(p) {
		if !m.found {
			continue
		}
		for _, l := range []struct {
			name string
			list baseline.MethodList
		}{{"login", m.set.Login}, {"authorization", m.set.Authorization}, {"command", m.set.Commands}} {
			if l.list.Has(baseline.MethodNone) {
				out = append(out, found(p, m.subject, m.set.Line, fixAAA, detailMethodNone, l.name, l.list))
			}
		}
		if m.set.Login.Remote() && !m.set.Login.Has(baseline.MethodLocal) {
			out = append(out, found(p, m.subject, m.set.Line, fixAAA, detailNoFallback, m.set.Login))
		}
	}
	return out
}

func commandAuthorization(in Input) []assess.Finding {
	return lineSwitch(in.Model, "command", func(s baseline.MethodSet) baseline.MethodList { return s.Commands },
		func(l baseline.Line) bool { return l.CommandAuthorization }, "command authorization")
}

func accounting(in Input) []assess.Finding {
	p := in.Model
	out := lineSwitch(p, "accounting", func(s baseline.MethodSet) baseline.MethodList { return s.Accounting },
		func(l baseline.Line) bool { return true }, "")
	return append(out, lineSwitch(p, "command accounting",
		func(s baseline.MethodSet) baseline.MethodList { return s.CommandAccounting },
		func(l baseline.Line) bool { return l.CommandAccounting }, "command accounting")...)
}

// lineSwitch reports a management method list that is not remote, and
// usable VTY lines whose per-line switch is off.
func lineSwitch(p *baseline.Posture, name string, list func(baseline.MethodSet) baseline.MethodList,
	on func(baseline.Line) bool, switchName string,
) []assess.Finding {
	var out []assess.Finding
	for _, m := range managementSets(p) {
		if m.found && !list(m.set).Remote() {
			out = append(out, found(p, m.subject, m.set.Line, fixAAA, detailNotRemote, name, list(m.set)))
		}
	}
	for _, l := range p.LinesOf(baseline.LineVTY) {
		if l.Usable() && !on(l) {
			out = append(out, found(p, lineSubject(p, l), l.Line, fixAAA, detailLineSwitch, lineName(l), switchName))
		}
	}
	return out
}

func aaaServers(_ context.Context, in Input) ([]assess.Finding, error) {
	spec, err := serverSpec(in)
	if err != nil {
		return nil, err
	}
	p := in.Model
	var out []assess.Finding
	for _, m := range managementSets(p) {
		if !m.found {
			continue
		}
		servers := p.AAA.Servers(m.set.Login, "authentication")
		out = append(out, serverFindings(p, m.subject, firstLine(servers), fixAAA, spec, baseline.Hosts(servers))...)
	}
	return out, nil
}

func serverRank(in Input) []assess.Finding {
	p := in.Model
	var out []assess.Finding
	for _, g := range p.AAA.Groups {
		for _, fn := range []string{"authentication", "authorization", "accounting"} {
			var primary, secondary bool
			for _, s := range g.Servers {
				if s.Function != fn {
					continue
				}
				primary = primary || s.Rank == baseline.RankPrimary
				secondary = secondary || s.Rank == baseline.RankSecondary
			}
			if secondary && !primary {
				out = append(out, found(p, device(p).Child("aaa-group", g.Name), g.Line, fixAAA, detailNoPrimary, g.Name, fn))
			}
		}
	}
	return out
}

func serverKey(in Input) []assess.Finding {
	p := in.Model
	var out []assess.Finding
	seen := map[string]bool{}
	for _, m := range managementSets(p) {
		if !m.found {
			continue
		}
		for _, s := range p.AAA.Servers(m.set.Login, "authentication") {
			if !s.Keyed && !seen[s.Host] {
				seen[s.Host] = true
				out = append(out, found(p, m.subject, s.Line, fixAAA, detailNoKey, s.Host))
			}
		}
	}
	return out
}
