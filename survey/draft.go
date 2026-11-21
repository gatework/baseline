package survey

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// draftDoc mirrors the policy document layout.
type draftDoc struct {
	Layers []draftLayer `yaml:"layers"`
}

type draftLayer struct {
	Name   string                `yaml:"name"`
	Scope  []string              `yaml:"scope,omitempty"`
	Checks map[string]draftCheck `yaml:"checks,omitempty"`
}

type draftCheck struct {
	Params map[string]any `yaml:"params"`
}

// Draft renders a policy whose default layer expects every global
// consensus, whose region layers expect the regional consensus where it
// differs from the global one, and whose site layers expect the site
// consensus where it differs from its region's. When every region's
// consensus of a setting is the region's own name, the default layer uses
// "${region}" instead. Local settings are not drafted.
func (s Survey) Draft() ([]byte, error) {
	doc := draftDoc{Layers: []draftLayer{{Name: "default", Checks: map[string]draftCheck{}}}}
	regional := map[string]map[string]draftCheck{}
	for _, k := range Keys() {
		if k.Local {
			continue
		}
		g, _ := s.Lookup(k.Check, "global")
		if s.regionNamed(k) {
			doc.Layers[0].Checks[k.Check] = draftCheck{Params: map[string]any{k.Param: "${region}"}}
			continue
		}
		if g.Reached {
			doc.Layers[0].Checks[k.Check] = draftCheck{Params: params(k, g.Consensus)}
		}
		for _, d := range s.Distributions {
			if d.Check != k.Check || d.Scope == "global" || !d.Reached {
				continue
			}
			if parent := s.parent(k, d.Scope, g); parent.Reached && parent.Consensus == d.Consensus {
				continue
			}
			if regional[d.Scope] == nil {
				regional[d.Scope] = map[string]draftCheck{}
			}
			regional[d.Scope][k.Check] = draftCheck{Params: params(k, d.Consensus)}
		}
	}
	scopes := slices.SortedFunc(maps.Keys(regional), compareScopes)
	for _, scope := range scopes {
		name := strings.ReplaceAll(scope, "=", "-")
		doc.Layers = append(doc.Layers, draftLayer{Name: name, Scope: []string{scope}, Checks: regional[scope]})
	}
	body, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("survey: draft: %w", err)
	}
	header := fmt.Sprintf("# Draft baseline policy from %d devices at quorum %.2f.\n"+
		"# Review every expectation before use; outliers are listed by `baseline survey`.\n", s.Devices, s.Quorum)
	return append([]byte(header), body...), nil
}

// parent returns the distribution a scope's layer overrides: the global one
// for a region, the region's for a site (the global one when the region
// has no consensus).
func (s Survey) parent(k Key, scope string, global Distribution) Distribution {
	site, ok := strings.CutPrefix(scope, "site=")
	if !ok {
		return global
	}
	if region := regionOf(site); region != "" {
		if d, ok := s.Lookup(k.Check, "region="+region); ok && d.Reached {
			return d
		}
	}
	return global
}

// regionOf is the region of a site named "<REGION><campus>".
func regionOf(site string) string {
	end := strings.IndexFunc(site, func(r rune) bool { return r >= '0' && r <= '9' })
	if end < 0 {
		end = len(site)
	}
	return strings.ToLower(site[:end])
}

// regionNamed reports whether, in every region with a consensus on k, the
// consensus is the region's name.
func (s Survey) regionNamed(k Key) bool {
	if k.Param != "domain" {
		return false
	}
	n := 0
	for _, d := range s.Distributions {
		region, ok := strings.CutPrefix(d.Scope, "region=")
		if d.Check != k.Check || !ok || !d.Reached {
			continue
		}
		if d.Consensus != region {
			return false
		}
		n++
	}
	return n > 1
}

func params(k Key, value string) map[string]any {
	if k.Param != "servers" {
		return map[string]any{k.Param: value}
	}
	servers := Split(value)
	return map[string]any{"servers": servers, "order": "strict", "min": len(servers)}
}
