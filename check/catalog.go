package check

import (
	"fmt"
	"slices"
	"strings"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/evidence"

	"github.com/gatework/baseline"
)

// Rule is a check over one device posture.
type Rule = assess.Rule[*baseline.Posture]

// Input is what a check evaluates.
type Input = assess.Input[*baseline.Posture]

// Rules returns the vendor-neutral checks in report order.
func Rules() []Rule {
	return slices.Concat(aaaRules(), loggingRules(), timeRules(), snmpRules(), lineRules(), serviceRules(),
		accountRules(), nacRules(), interfaceRules())
}

// New returns the catalog of the vendor-neutral checks and the given
// extra rules (vendor text rules).
func New(extra ...Rule) (*assess.Catalog[*baseline.Posture], error) {
	return assess.NewCatalog(slices.Concat(Rules(), extra)...)
}

// meta declares a check.
func meta(id assess.RuleID, title string, sev assess.Severity, cat assess.Category,
	requires []evidence.Dimension, params ...assess.Param,
) assess.Meta {
	return assess.Meta{ID: id, Title: title, Severity: sev, Category: cat, Requires: requires, Params: params}
}

func facets(f ...evidence.Dimension) []evidence.Dimension { return f }

// device returns the subject of a device-level finding.
func device(p *baseline.Posture) assess.Subject { return assess.NewSubject("device", p.Device.Label()) }

// found builds one finding about subject; line, when positive, is cited as
// evidence in the device configuration.
func found(p *baseline.Posture, sub assess.Subject, line int, fix, detail string, args ...any) assess.Finding {
	f := assess.Finding{Subject: sub, Detail: fmt.Sprintf(detail, args...), Remediation: &assess.Remediation{Summary: fix}}
	if line > 0 {
		ref := evidence.SourceRef{Device: p.Device.ID, Command: "configuration", Line: line}
		if p.Config != nil {
			ref.Digest = p.Config.RawDigest()
		}
		f.Evidence = []evidence.SourceRef{ref}
	}
	return f
}

// serverParams are the parameters of a server-list check.
func serverParams(minimum int) []assess.Param {
	return []assess.Param{
		assess.List("servers"), assess.Text("order", string(OrderStrict)),
		assess.Bool("exclusive", false), assess.Integer("min", minimum),
	}
}

func serverSpec(in Input) (ServerSpec, error) {
	s := ServerSpec{
		Expected: in.Params.List("servers"), Order: Order(in.Params.Text("order")),
		Exclusive: in.Params.Bool("exclusive"), Min: in.Params.Integer("min"),
	}
	if !s.Order.Valid() {
		return s, fmt.Errorf("%w: order %q is not strict, primary or any", ErrParam, s.Order)
	}
	return s, nil
}

// serverFindings turns server-list problems into findings.
func serverFindings(p *baseline.Posture, sub assess.Subject, line int, fix string, spec ServerSpec, actual []string) []assess.Finding {
	var out []assess.Finding
	for _, pr := range spec.Compare(actual) {
		var f assess.Finding
		switch pr.Kind {
		case ProblemMissing:
			f = found(p, sub, line, fix, detailMissing, strings.Join(pr.Hosts, ", "))
		case ProblemUnexpected:
			f = found(p, sub, line, fix, detailUnexpected, strings.Join(pr.Hosts, ", "))
		case ProblemOrder:
			f = found(p, sub, line, fix, detailOrder, strings.Join(actual, " > "), strings.Join(spec.Expected, " > "))
		case ProblemTooFew:
			f = found(p, sub, line, fix, detailTooFew, pr.Detail)
		}
		f.Expected, f.Actual = strings.Join(spec.Expected, " > "), strings.Join(actual, " > ")
		f.Fields = []evidence.Field{{Key: "problem", Value: string(pr.Kind)}}
		out = append(out, f)
	}
	return out
}

// firstLine returns the configuration line of the first server, or 0.
func firstLine(servers []baseline.Server) int {
	if len(servers) == 0 {
		return 0
	}
	return servers[0].Line
}

// sourceCheck reports a missing source interface, or one not matching
// pattern (a path.Match glob, case-insensitive) when pattern is set.
func sourceCheck(p *baseline.Posture, sub assess.Subject, source, pattern, fix string) []assess.Finding {
	if source == "" {
		return []assess.Finding{found(p, sub, 0, fix, detailNoSource)}
	}
	if pattern != "" && !globMatch(pattern, source) {
		return []assess.Finding{found(p, sub, 0, fix, detailSourceMismatch, source, pattern)}
	}
	return nil
}

// truncated joins at most n items and an ellipsis.
func truncated(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + ", …"
}
