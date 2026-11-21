package policy

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/gatework/netops/assess"
	textrule "github.com/gatework/netops/baseline"
	"github.com/gatework/netops/device"
)

// ErrInvalid reports an invalid policy document.
var ErrInvalid = errors.New("policy: invalid")

// dateLayout is the waiver expiry format.
const dateLayout = "2006-01-02"

// Policy is a decoded, validated baseline policy. It is immutable after
// Decode and safe for concurrent use.
type Policy struct {
	vars      map[string]Lookup
	layers    []Layer
	waivers   []Waiver
	textRules map[string][]textrule.Rule
}

// Lookup is a policy variable whose value depends on a device variable,
// such as NTP servers by region.
type Lookup struct {
	By      string         `yaml:"by"`
	Values  map[string]any `yaml:"values"`
	Default any            `yaml:"default,omitempty"`
}

// Layer is one level of the policy.
type Layer struct {
	Name    string                              `yaml:"name"`
	Scope   []string                            `yaml:"scope,omitempty"`
	Except  []string                            `yaml:"except,omitempty"`
	Enable  []string                            `yaml:"enable,omitempty"`
	Disable []string                            `yaml:"disable,omitempty"`
	Checks  map[assess.RuleID]assess.RulePolicy `yaml:"checks,omitempty"`

	scope, except device.Selector
}

// Waiver accepts violations until it expires.
type Waiver struct {
	ID      string   `yaml:"id"`
	Scope   []string `yaml:"scope,omitempty"`
	Checks  []string `yaml:"checks"`
	Subject string   `yaml:"subject,omitempty"` // glob on the finding subject
	Reason  string   `yaml:"reason"`
	Owner   string   `yaml:"owner"`
	Expires string   `yaml:"expires"` // YYYY-MM-DD, inclusive

	scope   device.Selector
	expires time.Time
}

// document is the YAML form.
type document struct {
	Vars      map[string]Lookup `yaml:"vars,omitempty"`
	Layers    []Layer           `yaml:"layers"`
	Waivers   []Waiver          `yaml:"waivers,omitempty"`
	TextRules []textPack        `yaml:"text_rules,omitempty"`
}

// textPack is custom text rules of one dialect, in netops baseline.Rule
// form.
type textPack struct {
	Dialect string      `yaml:"dialect"`
	Rules   []yaml.Node `yaml:"rules"`
}

// Decode parses and validates a policy. Unknown fields, malformed
// selectors, duplicate IDs and bad dates are errors; rule IDs are checked
// later by Validate, once the catalog is known.
func Decode(body []byte) (*Policy, error) {
	var doc document
	dec := yaml.NewDecoder(bytes.NewReader(body))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	p := &Policy{vars: doc.Vars, textRules: map[string][]textrule.Rule{}}
	for name, v := range doc.Vars {
		if _, builtin := builtins[name]; builtin || !varName.MatchString(name) {
			return nil, fmt.Errorf("%w: variable %q", ErrInvalid, name)
		}
		if _, ok := builtins[v.By]; !ok && !strings.HasPrefix(v.By, "label.") {
			return nil, fmt.Errorf("%w: variable %s: by %q is not a device variable", ErrInvalid, name, v.By)
		}
	}
	names := map[string]bool{}
	for i, l := range doc.Layers {
		if l.Name == "" || names[l.Name] {
			return nil, fmt.Errorf("%w: layer %d: missing or duplicate name %q", ErrInvalid, i, l.Name)
		}
		names[l.Name] = true
		var err error
		if l.scope, err = selector(l.Scope); err != nil {
			return nil, fmt.Errorf("%w: layer %s: %w", ErrInvalid, l.Name, err)
		}
		if l.except, err = selector(l.Except); err != nil {
			return nil, fmt.Errorf("%w: layer %s: %w", ErrInvalid, l.Name, err)
		}
		p.layers = append(p.layers, l)
	}
	ids := map[string]bool{}
	for _, w := range doc.Waivers {
		switch {
		case w.ID == "" || ids[w.ID]:
			return nil, fmt.Errorf("%w: waiver: missing or duplicate id %q", ErrInvalid, w.ID)
		case len(w.Checks) == 0 || w.Reason == "" || w.Owner == "":
			return nil, fmt.Errorf("%w: waiver %s needs checks, reason and owner", ErrInvalid, w.ID)
		}
		ids[w.ID] = true
		var err error
		if w.expires, err = time.Parse(dateLayout, w.Expires); err != nil {
			return nil, fmt.Errorf("%w: waiver %s: expires %q is not YYYY-MM-DD", ErrInvalid, w.ID, w.Expires)
		}
		if w.scope, err = selector(w.Scope); err != nil {
			return nil, fmt.Errorf("%w: waiver %s: %w", ErrInvalid, w.ID, err)
		}
		p.waivers = append(p.waivers, w)
	}
	for _, pack := range doc.TextRules {
		rules, err := compileText(pack)
		if err != nil {
			return nil, err
		}
		p.textRules[pack.Dialect] = append(p.textRules[pack.Dialect], rules...)
	}
	return p, nil
}

// TextRules returns the custom text rules by dialect.
func (p *Policy) TextRules() map[string][]textrule.Rule {
	out := make(map[string][]textrule.Rule, len(p.textRules))
	for k, v := range p.textRules {
		out[k] = slices.Clone(v)
	}
	return out
}

// Layers returns the layer names in order.
func (p *Policy) Layers() []string {
	out := make([]string, len(p.layers))
	for i, l := range p.layers {
		out[i] = l.Name
	}
	return out
}

// Validate reports policy entries that name no known check: explicit
// check IDs must exist, and every glob in enable, disable and waivers must
// match at least one check.
func (p *Policy) Validate(known []assess.RuleID) error {
	matches := func(glob string) bool {
		return slices.ContainsFunc(known, func(id assess.RuleID) bool { return idMatch(glob, id) })
	}
	for _, l := range p.layers {
		for _, id := range slices.Sorted(maps.Keys(l.Checks)) {
			if !slices.Contains(known, id) {
				return fmt.Errorf("%w: layer %s names unknown check %s", ErrInvalid, l.Name, id)
			}
		}
		for _, g := range slices.Concat(l.Enable, l.Disable) {
			if !matches(g) {
				return fmt.Errorf("%w: layer %s: %q matches no check", ErrInvalid, l.Name, g)
			}
		}
	}
	for _, w := range p.waivers {
		for _, g := range w.Checks {
			if !matches(g) {
				return fmt.Errorf("%w: waiver %s: %q matches no check", ErrInvalid, w.ID, g)
			}
		}
	}
	return nil
}

func compileText(pack textPack) ([]textrule.Rule, error) {
	if pack.Dialect == "" {
		return nil, fmt.Errorf("%w: text_rules entry has no dialect", ErrInvalid)
	}
	body, err := yaml.Marshal(map[string]any{"default": map[string]any{"rules": pack.Rules}})
	if err != nil {
		return nil, fmt.Errorf("%w: text_rules %s: %w", ErrInvalid, pack.Dialect, err)
	}
	prof, err := textrule.Decode(body)
	if err != nil {
		return nil, fmt.Errorf("%w: text_rules %s: %w", ErrInvalid, pack.Dialect, err)
	}
	return prof.Default.Rules, nil
}
