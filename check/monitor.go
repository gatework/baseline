package check

import (
	"context"
	"slices"
	"strings"

	"github.com/gatework/netops/assess"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/internal/tz"
)

func loggingRules() []Rule {
	f := facets(baseline.FacetLogging)
	return []Rule{
		assess.Check(meta("logging.enabled", titleLoggingEnabled, assess.SeverityHigh, assess.CategoryConfiguration, f),
			func(in Input) []assess.Finding {
				return enabled(in.Model, in.Model.Logging.State, "info-center", fixLogging)
			}),
		assess.NewRule(meta("logging.hosts", titleLoggingHosts, assess.SeverityMedium, assess.CategoryConfiguration, f,
			serverParams(1)...), func(_ context.Context, in Input) ([]assess.Finding, error) {
			return serverList(in, "logging", in.Model.Logging.Hosts, fixLogging)
		}),
		assess.Check(meta("logging.source", titleLoggingSource, assess.SeverityLow, assess.CategoryConfiguration, f,
			assess.Text("interface", "")), func(in Input) []assess.Finding {
			p := in.Model
			return sourceCheck(p, device(p).Child("logging", "source"), p.Logging.Source, in.Params.Text("interface"), fixLogging)
		}),
	}
}

func timeRules() []Rule {
	f := facets(baseline.FacetNTP)
	return []Rule{
		assess.Check(meta("ntp.enabled", titleNTPEnabled, assess.SeverityHigh, assess.CategoryConfiguration, f),
			func(in Input) []assess.Finding { return enabled(in.Model, in.Model.Time.NTPState, "NTP", fixNTP) }),
		assess.NewRule(meta("ntp.servers", titleNTPServers, assess.SeverityMedium, assess.CategoryConfiguration, f,
			serverParams(2)...), func(_ context.Context, in Input) ([]assess.Finding, error) {
			return serverList(in, "ntp", in.Model.Time.NTP, fixNTP)
		}),
		assess.Check(meta("ntp.source", titleNTPSource, assess.SeverityLow, assess.CategoryConfiguration, f,
			assess.Text("interface", "")), func(in Input) []assess.Finding {
			p := in.Model
			return sourceCheck(p, device(p).Child("ntp", "source"), p.Time.Source, in.Params.Text("interface"), fixNTP)
		}),
		assess.Check(meta("ntp.auth", titleNTPAuth, assess.SeverityLow, assess.CategorySecurity, f),
			func(in Input) []assess.Finding {
				if in.Model.Time.Auth {
					return nil
				}
				return []assess.Finding{found(in.Model, device(in.Model).Child("ntp", "auth"), 0, fixNTP, detailDisabled, "NTP 认证")}
			}),
		assess.NewRule(meta("clock.timezone", titleClockTimezone, assess.SeverityLow, assess.CategoryConfiguration,
			facets(baseline.FacetClock), assess.Text("offset", "+08:00")), timezone),
	}
}

func snmpRules() []Rule {
	f := facets(baseline.FacetSNMP)
	return []Rule{
		assess.Check(meta("snmp.default_community", titleSNMPDefault, assess.SeverityCritical, assess.CategorySecurity, f,
			assess.List("forbidden", "public", "private", "community", "snmp", "admin", "cisco", "h3c")), defaultCommunity),
		assess.Check(meta("snmp.write_community", titleSNMPWrite, assess.SeverityHigh, assess.CategorySecurity, f),
			writeCommunity),
		assess.Check(meta("snmp.community_acl", titleSNMPACL, assess.SeverityMedium, assess.CategorySecurity,
			facets(baseline.FacetSNMP, baseline.FacetACL)), communityACL),
		assess.Check(meta("snmp.v3_only", titleSNMPV3Only, assess.SeverityMedium, assess.CategorySecurity, f), v3Only),
		assess.Check(meta("snmp.v3_privacy", titleSNMPV3Privacy, assess.SeverityMedium, assess.CategorySecurity, f),
			v3Privacy),
		assess.NewRule(meta("snmp.trap_hosts", titleSNMPTrapHosts, assess.SeverityLow, assess.CategoryConfiguration, f,
			assess.List("servers"), assess.Text("order", string(OrderAny)), assess.Bool("exclusive", false),
			assess.Integer("min", 1)),
			func(_ context.Context, in Input) ([]assess.Finding, error) {
				if in.Model.SNMP.State != baseline.StateEnabled {
					return nil, nil
				}
				return serverList(in, "snmp-trap", in.Model.SNMP.TrapHosts, fixSNMP)
			}),
		assess.Check(meta("snmp.location", titleSNMPLocation, assess.SeverityInfo, assess.CategoryConfiguration, f),
			func(in Input) []assess.Finding {
				p := in.Model
				if p.SNMP.State != baseline.StateEnabled || p.SNMP.Location != "" {
					return nil
				}
				return []assess.Finding{found(p, device(p).Child("snmp", "location"), 0, fixSNMP, detailNoLocation)}
			}),
	}
}

// enabled reports a feature that is not enabled.
func enabled(p *baseline.Posture, s baseline.State, name, fix string) []assess.Finding {
	if s.Enabled() {
		return nil
	}
	return []assess.Finding{found(p, device(p).Child("feature", name), 0, fix, detailDisabled, name)}
}

func serverList(in Input, kind string, servers []baseline.Server, fix string) ([]assess.Finding, error) {
	spec, err := serverSpec(in)
	if err != nil {
		return nil, err
	}
	p := in.Model
	return serverFindings(p, device(p).Child(kind, "servers"), firstLine(servers), fix, spec, baseline.Hosts(servers)), nil
}

func timezone(_ context.Context, in Input) ([]assess.Finding, error) {
	p := in.Model
	want, ok := tz.ParseFormat(in.Params.Text("offset"))
	if !ok {
		return nil, errOffset(in.Params.Text("offset"))
	}
	z := p.Time.Timezone
	sub := device(p).Child("clock", "timezone")
	switch {
	case !z.Set:
		return []assess.Finding{found(p, sub, 0, fixClock, detailTimezoneUnset)}, nil
	case z.Offset != want:
		f := found(p, sub, z.Line, fixClock, detailTimezone, z.Name, tz.Format(z.Offset), tz.Format(want))
		f.Expected, f.Actual = tz.Format(want), tz.Format(z.Offset)
		return []assess.Finding{f}, nil
	}
	return nil, nil
}

func defaultCommunity(in Input) []assess.Finding {
	p := in.Model
	forbidden := in.Params.List("forbidden")
	var out []assess.Finding
	for _, c := range p.SNMP.Communities {
		name := c.Name.Reveal()
		if slices.ContainsFunc(forbidden, func(f string) bool { return strings.EqualFold(f, name) }) {
			// The name is a well-known default, so naming it leaks nothing.
			out = append(out, found(p, device(p).Child("snmp-community", strings.ToLower(name)), c.Line, fixSNMP,
				detailCommunity, strings.ToLower(name)))
		}
	}
	return out
}

func writeCommunity(in Input) []assess.Finding {
	p := in.Model
	var out []assess.Finding
	for _, c := range p.SNMP.Communities {
		if c.Write {
			out = append(out, found(p, device(p).Child("snmp-community", "write"), c.Line, fixSNMP, detailWriteCommunity))
		}
	}
	return out
}

func communityACL(in Input) []assess.Finding {
	p := in.Model
	var out []assess.Finding
	for _, c := range p.SNMP.Communities {
		sub := device(p).Child("snmp-community", "line-"+itoa(c.Line))
		switch {
		case c.ACL == "":
			out = append(out, found(p, sub, c.Line, fixSNMP, detailCommunityNoACL, c.Line))
		case !p.HasACL(c.ACL):
			out = append(out, found(p, sub, c.Line, fixSNMP, detailCommunityBadACL, c.ACL))
		}
	}
	return out
}

func v3Only(in Input) []assess.Finding {
	p := in.Model
	if p.SNMP.State != baseline.StateEnabled {
		return nil
	}
	var weak []string
	for _, v := range p.SNMP.Versions {
		if v != "v3" {
			weak = append(weak, v)
		}
	}
	if len(weak) == 0 {
		return nil
	}
	return []assess.Finding{found(p, device(p).Child("snmp", "version"), 0, fixSNMP, detailVersions, strings.Join(weak, ", "))}
}

func v3Privacy(in Input) []assess.Finding {
	p := in.Model
	var out []assess.Finding
	for _, u := range p.SNMP.Users {
		if !u.Auth || !u.Privacy {
			out = append(out, found(p, device(p).Child("snmp-user", u.Name), u.Line, fixSNMP, detailV3User, u.Name, u.Auth, u.Privacy))
		}
	}
	return out
}
