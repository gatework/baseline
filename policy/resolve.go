package policy

import (
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/device"
)

var (
	varName     = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	varRef      = regexp.MustCompile(`\$\{([a-z][a-z0-9_.-]*)\}`)
	regionTerm  = regexp.MustCompile(`(^|[ ,\t])region=`)
	wholeVarRef = regexp.MustCompile(`^\$\{([a-z][a-z0-9_.-]*)\}$`)
)

// builtins are the device variables, by name.
var builtins = map[string]func(device.Device) string{
	"name": func(d device.Device) string { return d.Name }, "id": func(d device.Device) string { return d.ID },
	"site": func(d device.Device) string { return d.Site }, "role": func(d device.Device) string { return d.Role },
	"vendor": func(d device.Device) string { return d.Vendor }, "model": func(d device.Device) string { return d.Model },
	"platform": func(d device.Device) string { return d.Platform },
	"region":   func(d device.Device) string { return d.Labels["region"] },
}

// Resolved is the effective policy of one device.
type Resolved struct {
	// Policy is the assess policy with variables expanded.
	Policy assess.Policy
	// Layers are the names of the layers that applied, in order.
	Layers []string
	// Expired are the IDs of waivers that match the device but have
	// expired.
	Expired []string

	waivers []Waiver
}

// Resolve applies the layers that select d, expands variables and selects
// the waivers in force on d at now. known lists every check ID, against
// which enable and disable globs expand.
func (p *Policy) Resolve(d device.Device, now time.Time, known []assess.RuleID) (Resolved, error) {
	r := Resolved{Policy: assess.Policy{Rules: map[assess.RuleID]assess.RulePolicy{}}}
	set := func(id assess.RuleID, on bool) {
		rp := r.Policy.Rules[id]
		rp.Enabled = &on
		r.Policy.Rules[id] = rp
	}
	for _, l := range p.layers {
		if !l.applies(d) {
			continue
		}
		r.Layers = append(r.Layers, l.Name)
		for _, id := range known {
			if slices.ContainsFunc(l.Enable, func(g string) bool { return idMatch(g, id) }) {
				set(id, true)
			}
			if slices.ContainsFunc(l.Disable, func(g string) bool { return idMatch(g, id) }) {
				set(id, false)
			}
		}
		for _, id := range slices.Sorted(maps.Keys(l.Checks)) {
			r.Policy.Rules[id] = merge(r.Policy.Rules[id], l.Checks[id])
		}
	}
	for id, rp := range r.Policy.Rules {
		params, err := p.expand(d, rp.Params)
		if err != nil {
			return Resolved{}, fmt.Errorf("policy: check %s: %w", id, err)
		}
		rp.Params = params
		r.Policy.Rules[id] = rp
	}
	today := now.Format(dateLayout)
	for _, w := range p.waivers {
		if !w.scope.Match(d) {
			continue
		}
		if w.Expires < today {
			r.Expired = append(r.Expired, w.ID)
			continue
		}
		r.waivers = append(r.waivers, w)
	}
	return r, nil
}

// Waiver returns the waiver in force that accepts f.
func (r Resolved) Waiver(f assess.Finding) (Waiver, bool) {
	for _, w := range r.waivers {
		if !slices.ContainsFunc(w.Checks, func(g string) bool { return idMatch(g, f.Rule) }) {
			continue
		}
		if w.Subject != "" && !wildcard(w.Subject, f.Subject.String()) {
			continue
		}
		return w, true
	}
	return Waiver{}, false
}

func (l Layer) applies(d device.Device) bool {
	return l.scope.Match(d) && (l.except.Empty() || !l.except.Match(d))
}

// merge applies b over a: a set Enabled or Severity replaces a's, and
// parameters replace one by one.
func merge(a, b assess.RulePolicy) assess.RulePolicy {
	if b.Enabled != nil {
		a.Enabled = b.Enabled
	}
	if b.Severity != assess.SeverityUnset {
		a.Severity = b.Severity
	}
	if len(b.Params) > 0 {
		params := maps.Clone(a.Params)
		if params == nil {
			params = map[string]any{}
		}
		maps.Copy(params, b.Params)
		a.Params = params
	}
	return a
}

// expand substitutes variables in parameter values. A string that is
// exactly one reference to a list-valued lookup becomes that list, and
// inside a list it is spliced.
func (p *Policy) expand(d device.Device, params map[string]any) (map[string]any, error) {
	if params == nil {
		return params, nil
	}
	out := make(map[string]any, len(params))
	for k, v := range params {
		e, err := p.expandValue(d, v)
		if err != nil {
			return nil, fmt.Errorf("param %s: %w", k, err)
		}
		out[k] = e
	}
	return out, nil
}

func (p *Policy) expandValue(d device.Device, v any) (any, error) {
	switch t := v.(type) {
	case string:
		if m := wholeVarRef.FindStringSubmatch(t); m != nil {
			return p.value(d, m[1])
		}
		var err error
		s := varRef.ReplaceAllStringFunc(t, func(ref string) string {
			val, e := p.value(d, varRef.FindStringSubmatch(ref)[1])
			if e != nil {
				err = e
			}
			return fmt.Sprint(val)
		})
		return s, err
	case []any:
		var out []any
		for _, e := range t {
			x, err := p.expandValue(d, e)
			if err != nil {
				return nil, err
			}
			if list, ok := x.([]any); ok {
				out = append(out, list...)
			} else {
				out = append(out, x)
			}
		}
		return out, nil
	}
	return v, nil
}

// value returns a variable's value for d: a device variable, a label or a
// lookup. Missing labels and lookup misses without default are "".
func (p *Policy) value(d device.Device, name string) (any, error) {
	if f, ok := builtins[name]; ok {
		return f(d), nil
	}
	if k, ok := strings.CutPrefix(name, "label."); ok {
		return d.Labels[k], nil
	}
	l, ok := p.vars[name]
	if !ok {
		return nil, fmt.Errorf("%w: unknown variable %q", ErrInvalid, name)
	}
	key, err := p.value(d, l.By)
	if err != nil {
		return nil, err
	}
	for k, v := range l.Values {
		if strings.EqualFold(k, fmt.Sprint(key)) {
			return v, nil
		}
	}
	if l.Default == nil {
		return "", nil
	}
	return l.Default, nil
}

// selector parses device selector expressions, accepting "region=X" for
// "label:region=X".
func selector(exprs []string) (device.Selector, error) {
	out := make([]string, len(exprs))
	for i, e := range exprs {
		out[i] = regionTerm.ReplaceAllString(e, "${1}label:region=")
	}
	return device.ParseSelector(out...)
}

// idMatch matches a check ID against a glob such as "ntp.*".
func idMatch(glob string, id assess.RuleID) bool {
	ok, err := path.Match(glob, string(id))
	return err == nil && ok
}

// wildcard matches s against a pattern where "*" matches any run of
// characters, including "/".
func wildcard(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for _, part := range parts[1 : len(parts)-1] {
		i := strings.Index(s, part)
		if i < 0 {
			return false
		}
		s = s[i+len(part):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}
