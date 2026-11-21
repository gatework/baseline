package vendors

import (
	"maps"
	"slices"
	"strings"

	"github.com/gatework/netops/device"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/vendors/alteon"
	"github.com/gatework/baseline/vendors/comware"
	"github.com/gatework/baseline/vendors/hillstone"
	"github.com/gatework/baseline/vendors/ios"
	"github.com/gatework/baseline/vendors/nxos"
	"github.com/gatework/baseline/vendors/panos"
)

var (
	_ baseline.Extractor = (*comware.Extractor)(nil)
	_ baseline.Extractor = (*nxos.Extractor)(nil)
	_ baseline.Extractor = (*ios.Extractor)(nil)
	_ baseline.Extractor = (*hillstone.Extractor)(nil)
	_ baseline.Extractor = (*panos.Extractor)(nil)
	_ baseline.Extractor = (*alteon.Extractor)(nil)
)

// DefaultAliases maps inventory vendor keys (net-connector platform names)
// to extractors.
func DefaultAliases() map[string]string {
	return map[string]string{
		"h3c": comware.Name, "h3c_wireless": comware.Name, "comware": comware.Name, "hp_comware": comware.Name,
		"cisco_nxos": nxos.Name, "nxos": nxos.Name,
		"cisco_ios": ios.Name, "cisco_xe": ios.Name, "ios": ios.Name, "centec": ios.Name,
		"hillstone": hillstone.Name, "palo_alto": panos.Name, "panos": panos.Name, "radware": alteon.Name, "alteon": alteon.Name,
	}
}

// Registry selects extractors. It is immutable and safe for concurrent
// use.
type Registry struct {
	byName  map[string]baseline.Extractor
	aliases map[string]string
}

// New returns a registry of every built-in extractor. aliases add to or
// override DefaultAliases.
func New(aliases map[string]string) *Registry {
	r := &Registry{byName: map[string]baseline.Extractor{}, aliases: DefaultAliases()}
	for _, x := range []baseline.Extractor{
		comware.New(), nxos.New(), ios.New(), hillstone.New(), panos.New(), alteon.New(),
	} {
		r.byName[x.Vendor()] = x
	}
	for k, v := range aliases {
		r.aliases[strings.ToLower(k)] = v
	}
	return r
}

// Names returns the extractor names, sorted.
func (r *Registry) Names() []string { return slices.Sorted(maps.Keys(r.byName)) }

// For returns the extractor for d: by its vendor key, else by recognizing
// text.
func (r *Registry) For(d device.Device, text string) (baseline.Extractor, bool) {
	if name, ok := r.aliases[strings.ToLower(d.Vendor)]; ok {
		x, ok := r.byName[name]
		return x, ok
	}
	if x, ok := r.byName[strings.ToLower(d.Vendor)]; ok {
		return x, true
	}
	x, ok := r.byName[detect(text)]
	return x, ok
}

// detect recognizes a dialect from the first part of a configuration.
func detect(text string) string {
	head := text[:min(len(text), 64<<10)]
	switch {
	case strings.Contains(head, "\n sysname ") || strings.Contains(head, "\nsysname "):
		return comware.Name
	case strings.Contains(head, "\nfeature ") && (strings.Contains(head, "!Command: show running-config") ||
		strings.Contains(head, "\nswitchname ") || strings.Contains(head, "\nversion ")):
		return nxos.Name
	case strings.Contains(head, "\nset deviceconfig "):
		return panos.Name
	case strings.Contains(head, "\n/c/sys"):
		return alteon.Name
	case strings.Contains(head, "show configuration running") || strings.Contains(head, "\nhostname \""):
		return hillstone.Name
	case strings.Contains(head, "\nhostname ") || strings.Contains(head, "\nline vty "):
		return ios.Name
	}
	return ""
}
