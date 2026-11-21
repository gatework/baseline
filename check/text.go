package check

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/gatework/netops/assess"
	textrule "github.com/gatework/netops/baseline"
	"github.com/gatework/netops/drift"
	"github.com/gatework/netops/evidence"

	"github.com/gatework/baseline"
)

var slugPattern = regexp.MustCompile(`[^a-z0-9_]+`)

// TextPrefix starts the ID of every text rule check.
const TextPrefix = "text."

// Text turns compiled netops text rules (required and forbidden commands
// within matching blocks) into checks of one dialect. Each check has ID
// "text.<dialect>.<rule id>" and requires the dialect facet, so it runs
// only on that dialect's devices.
func Text(dialect string, rules []textrule.Rule) ([]Rule, error) {
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		sev := assess.SeverityMedium
		if r.Severity != "" {
			s, err := assess.ParseSeverity(r.Severity)
			if err != nil {
				return nil, fmt.Errorf("check: text rule %s: %w", r.ID, err)
			}
			sev = s
		}
		id := assess.RuleID(TextPrefix + slug(dialect) + "." + slug(r.ID))
		m := meta(id, fmt.Sprintf(textRuleTitle, r.Title), sev, assess.CategoryCompliance,
			facets(baseline.DialectFacet(dialect)))
		out = append(out, assess.Check(m, func(in Input) []assess.Finding { return textFindings(in.Model, r) }))
	}
	return out, nil
}

func textFindings(p *baseline.Posture, r textrule.Rule) []assess.Finding {
	if p.Config == nil {
		return nil
	}
	resolved := textrule.Resolved{Rules: []textrule.Rule{r}}
	var out []assess.Finding
	for _, v := range resolved.CheckConfig(p.Config) {
		sub := device(p)
		for _, b := range v.Block {
			sub = sub.Child("block", p.Config.Dialect().Mask(b))
		}
		var f assess.Finding
		if v.Kind == drift.KindMissing {
			f = found(p, sub, v.Line, fixInterface, textMissing, v.Pattern)
			f.Expected = v.Pattern
		} else {
			f = found(p, sub, v.Line, fixInterface, textForbidden)
			f.Actual = v.Text
		}
		f.Remediation = nil
		f.Fields = []evidence.Field{{Key: "kind", Value: string(v.Kind)}}
		out = append(out, f)
	}
	return out
}

func slug(s string) string {
	s = slugPattern.ReplaceAllString(strings.ToLower(s), "_")
	return strings.Trim(s, "_")
}
