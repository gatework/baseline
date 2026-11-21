package inventory

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/gatework/netops/device"
)

// DefaultPattern matches "<REGION><campus>-[<area>-]<ROLE><seq>", such as
// LAB3-10-SW01, TST2-LEF01 or LAB3-19-ENG-ASW01.
const DefaultPattern = `^(?P<region>[A-Za-z]{3})(?P<campus>\d+)?(?:-(?P<area>.+?))?-(?P<role>[A-Za-z]+?)(?P<seq>\d*)$`

// Naming classifies devices by hostname. The zero value is not usable;
// use NewNaming.
type Naming struct {
	pattern *regexp.Regexp
	roles   map[string]string
}

// NewNaming compiles a naming rule. pattern must have a "role" or
// "region" named group; "region", "campus", "area" and "role" groups are
// recognized and any other named group becomes a label. roles maps the
// lowercase role token to a role name ("sw" to "access"); tokens not
// listed are used as they are, lowercased.
func NewNaming(pattern string, roles map[string]string) (*Naming, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("inventory: naming pattern: %w", err)
	}
	if !slices.Contains(re.SubexpNames(), "role") && !slices.Contains(re.SubexpNames(), "region") {
		return nil, fmt.Errorf("inventory: naming pattern has no role or region group")
	}
	r := make(map[string]string, len(roles))
	for k, v := range roles {
		r[strings.ToLower(k)] = v
	}
	return &Naming{pattern: re, roles: r}, nil
}

// Classify fills d's Site, Role and labels from its name. A domain suffix
// is ignored. Names that do not match are returned unchanged: their
// devices still get the default layers.
func (n *Naming) Classify(d device.Device) device.Device {
	d = d.Clone()
	name, _, _ := strings.Cut(d.Name, ".")
	m := n.pattern.FindStringSubmatch(name)
	if m == nil {
		return d
	}
	if d.Labels == nil {
		d.Labels = map[string]string{}
	}
	groups := map[string]string{}
	for i, g := range n.pattern.SubexpNames() {
		if g != "" && m[i] != "" {
			groups[g] = m[i]
		}
	}
	if region := strings.ToLower(groups["region"]); region != "" {
		d.Labels["region"] = region
		if d.Site == "" {
			d.Site = strings.ToUpper(groups["region"]) + groups["campus"]
		}
	}
	if token := strings.ToLower(groups["role"]); token != "" && d.Role == "" {
		d.Role = token
		if r, ok := n.roles[token]; ok {
			d.Role = r
		}
	}
	for _, g := range slices.Sorted(maps.Keys(groups)) {
		if g == "region" || g == "role" || g == "seq" {
			continue
		}
		d.Labels[g] = strings.ToLower(groups[g])
	}
	return d
}
