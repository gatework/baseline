package survey

import (
	"cmp"
	"maps"
	"slices"
	"strings"

	"github.com/gatework/netops/device"
	"github.com/gatework/netops/drift"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/internal/tz"
)

// sep joins ordered values.
const sep = " > "

// Sample is one device's posture.
type Sample struct {
	Device  device.Device
	Vendor  string
	Posture *baseline.Posture
}

// Key is one surveyed setting and how to read it from a posture. The
// value is "" when the posture has no such setting.
type Key struct {
	Check string // the check whose parameters the setting feeds
	Param string // "servers", "offset", "domain"
	// Local settings (source interfaces) differ by site and vendor by
	// design; they are surveyed but never drafted as expectations.
	Local bool
	read  func(*baseline.Posture) string
}

// Keys returns the surveyed settings.
func Keys() []Key {
	return []Key{
		{Check: "ntp.servers", Param: "servers", read: func(p *baseline.Posture) string { return join(baseline.Hosts(p.Time.NTP)) }},
		{Check: "logging.hosts", Param: "servers", read: func(p *baseline.Posture) string { return join(baseline.Hosts(p.Logging.Hosts)) }},
		{Check: "aaa.servers", Param: "servers", read: aaaServers},
		{Check: "snmp.trap_hosts", Param: "servers", read: func(p *baseline.Posture) string { return join(baseline.Hosts(p.SNMP.TrapHosts)) }},
		{Check: "clock.timezone", Param: "offset", read: func(p *baseline.Posture) string {
			if !p.Time.Timezone.Set {
				return ""
			}
			return tz.Format(p.Time.Timezone.Offset)
		}},
		{Check: "nac.domain", Param: "domain", read: func(p *baseline.Posture) string {
			if !p.NAC.Dot1x && !p.NAC.MACAuth {
				return ""
			}
			return strings.ToLower(join(p.NAC.Domains))
		}},
		{Check: "logging.source", Param: "interface", Local: true, read: func(p *baseline.Posture) string { return p.Logging.Source }},
		{Check: "ntp.source", Param: "interface", Local: true, read: func(p *baseline.Posture) string { return p.Time.Source }},
	}
}

// Value is one distinct value and the devices holding it.
type Value struct {
	Value   string   `json:"value"`
	Count   int      `json:"count"`
	Devices []string `json:"devices"` // up to maxSample names
}

// Distribution is how one setting is configured within one scope.
type Distribution struct {
	Check string `json:"check"`
	Param string `json:"param"`
	Scope string `json:"scope"` // "global", "region=<r>" or "site=<s>"
	// Total counts devices with the setting; Absent those without it.
	Total     int     `json:"total"`
	Absent    int     `json:"absent"`
	Values    []Value `json:"values"` // most common first
	Consensus string  `json:"consensus,omitempty"`
	Share     float64 `json:"share"`
	Reached   bool    `json:"reached"`
}

// Survey is the result of surveying a fleet.
type Survey struct {
	Devices       int            `json:"devices"`
	Quorum        float64        `json:"quorum"`
	Distributions []Distribution `json:"distributions"`
}

const maxSample = 5

// Build surveys samples globally, per region and per site. quorum in
// (0, 1] is the share of devices that must agree for a value to become
// the expectation; devices without the setting count against every value.
func Build(samples []Sample, quorum float64) Survey {
	s := Survey{Devices: len(samples), Quorum: quorum}
	groups := map[string][]Sample{}
	for _, smp := range samples {
		if r := smp.Device.Labels["region"]; r != "" {
			groups["region="+r] = append(groups["region="+r], smp)
		}
		if site := smp.Device.Site; site != "" {
			groups["site="+site] = append(groups["site="+site], smp)
		}
	}
	scopes := slices.SortedFunc(maps.Keys(groups), compareScopes)
	for _, k := range Keys() {
		s.Distributions = append(s.Distributions, distribution(k, "global", samples, quorum))
		for _, scope := range scopes {
			s.Distributions = append(s.Distributions, distribution(k, scope, groups[scope], quorum))
		}
	}
	return s
}

// Lookup returns the distribution of check in scope.
func (s Survey) Lookup(check, scope string) (Distribution, bool) {
	i := slices.IndexFunc(s.Distributions, func(d Distribution) bool { return d.Check == check && d.Scope == scope })
	if i < 0 {
		return Distribution{}, false
	}
	return s.Distributions[i], true
}

func distribution(k Key, scope string, samples []Sample, quorum float64) Distribution {
	d := Distribution{Check: k.Check, Param: k.Param, Scope: scope}
	var members []drift.Member[string]
	byValue := map[string]*Value{}
	for _, smp := range samples {
		v := k.read(smp.Posture)
		members = append(members, drift.Member[string]{ID: cmp.Or(smp.Device.Name, smp.Device.ID), Value: v})
		if v == "" {
			d.Absent++
			continue
		}
		val, ok := byValue[v]
		if !ok {
			val = &Value{Value: v}
			byValue[v] = val
		}
		val.Count++
		if len(val.Devices) < maxSample {
			val.Devices = append(val.Devices, cmp.Or(smp.Device.Name, smp.Device.ID))
		}
	}
	d.Total = len(members) - d.Absent
	for _, v := range byValue {
		d.Values = append(d.Values, *v)
	}
	slices.SortFunc(d.Values, func(a, b Value) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.Value, b.Value))
	})
	if len(members) > 0 {
		a := drift.Consensus(members, func(v string) string { return v }, quorum)
		// A majority without the setting is no expectation.
		d.Consensus, d.Share, d.Reached = a.Value, a.Share, a.Reached && a.Value != ""
	}
	return d
}

func aaaServers(p *baseline.Posture) string {
	set, ok := p.AAA.Management("")
	if !ok {
		return ""
	}
	return join(baseline.Hosts(p.AAA.Servers(set.Login, "authentication")))
}

func join(v []string) string { return strings.Join(v, sep) }

// Split returns the parts of an ordered value.
func Split(v string) []string {
	if v == "" {
		return nil
	}
	return strings.Split(v, sep)
}

// compareScopes orders regions before sites, then by name.
func compareScopes(a, b string) int {
	rank := func(s string) int {
		if strings.HasPrefix(s, "region=") {
			return 0
		}
		return 1
	}
	return cmp.Or(cmp.Compare(rank(a), rank(b)), cmp.Compare(a, b))
}
