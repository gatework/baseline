package nxos

import (
	"slices"
	"strings"

	"github.com/gatework/netops/parse"
	"github.com/gatework/netops/secret"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/internal/token"
	"github.com/gatework/baseline/internal/tz"
)

var loggingIgnored = []string{
	"level", "origin-id", "event", "logfile", "timestamp", "module", "message", "console", "monitor",
	"rate-limit", "ip", "rfc-strict",
}

// logging decodes "logging server A [SEVERITY] [port N] [use-vrf V]
// [facility F]" and "logging source-interface X".
func (x *extraction) logging(n *parse.Node, w token.Words, no bool) {
	switch {
	case no:
	case w.Prefix("logging", "server"):
		s := baseline.Server{Host: w.At(2), Port: w.Int("port"), Rank: baseline.RankOrdered, Line: n.Line.Number}
		s.VRF, _ = w.After("use-vrf")
		x.p.Logging.Hosts = append(x.p.Logging.Hosts, s)
	case w.Prefix("logging", "source-interface"):
		x.p.Logging.Source = w.At(2)
	case slices.Contains(loggingIgnored, w.At(1)):
	default:
		x.unknown(n, baseline.FacetLogging)
	}
}

var ntpIgnored = []string{"allow", "logging", "master", "access-group", "passive", "trusted-key", "authentication-key"}

// ntp decodes "ntp server A [prefer] [use-vrf V] [key N]", "ntp peer" and
// "ntp source-interface X". A preferred server ranks first.
func (x *extraction) ntp(n *parse.Node, w token.Words, no bool) {
	t := &x.p.Time
	switch {
	case no:
	case w.Prefix("ntp", "server"), w.Prefix("ntp", "peer"):
		s := baseline.Server{Host: w.At(2), Rank: baseline.RankOrdered, Keyed: w.Has("key"), Line: n.Line.Number}
		s.VRF, _ = w.After("use-vrf")
		if w.Has("prefer") {
			s.Rank = baseline.RankPrimary
		}
		t.NTP = append(t.NTP, s)
	case w.Prefix("ntp", "source-interface"), w.Prefix("ntp", "source"):
		t.Source = w.At(2)
	case w.Prefix("ntp", "authenticate"):
		t.Auth = true
	case slices.Contains(ntpIgnored, w.At(1)):
	default:
		x.unknown(n, baseline.FacetNTP)
	}
}

// clock decodes "clock timezone NAME H M".
func (x *extraction) clock(n *parse.Node, w token.Words) {
	switch {
	case w.Prefix("clock", "timezone"):
		d, ok := tz.Hours(w.At(3), w.At(4))
		if !ok {
			x.unknown(n, baseline.FacetClock)
			return
		}
		x.p.Time.Timezone = baseline.Timezone{Name: w.At(2), Offset: d, Set: true, Line: n.Line.Number}
	case w.Prefix("clock", "summer-time"), w.Prefix("clock", "protocol"), w.Prefix("clock", "format"):
	default:
		x.unknown(n, baseline.FacetClock)
	}
}

var snmpIgnored = []string{"enable", "source-interface", "globalEnforcePriv", "aaa-user", "counter", "tcp-session", "packetsize", "protocol", "mib", "engineID"}

// snmp decodes snmp-server statements.
func (x *extraction) snmp(n *parse.Node, w token.Words, no bool) {
	s := &x.p.SNMP
	switch {
	case no:
	case w.Prefix("snmp-server", "community"):
		c := baseline.Community{Name: secret.New(w.At(2)), Line: n.Line.Number}
		c.Write = w.Has("rw") || w.Has("network-admin")
		if acl, ok := w.After("use-ipv4acl"); ok {
			c.ACL = acl
		} else if acl, ok := w.After("use-acl"); ok {
			c.ACL = acl
		}
		x.mergeCommunity(c)
		x.addVersion("v2c")
	case w.Prefix("snmp-server", "user"):
		u := baseline.SNMPUser{Name: w.At(2), Auth: w.Has("auth"), Privacy: w.Has("priv"), Line: n.Line.Number}
		if i := slices.IndexFunc(s.Users, func(o baseline.SNMPUser) bool { return o.Name == u.Name }); i >= 0 {
			s.Users[i].Auth = s.Users[i].Auth || u.Auth
			s.Users[i].Privacy = s.Users[i].Privacy || u.Privacy
		} else {
			s.Users = append(s.Users, u)
		}
		x.addVersion("v3")
	case w.Prefix("snmp-server", "host"):
		h := baseline.Server{Host: w.At(2), Rank: baseline.RankOrdered, Line: n.Line.Number}
		h.VRF, _ = w.After("use-vrf")
		h.Port = w.Int("udp-port")
		if !slices.ContainsFunc(s.TrapHosts, func(o baseline.Server) bool { return o.Host == h.Host }) {
			s.TrapHosts = append(s.TrapHosts, h)
		}
	case w.Prefix("snmp-server", "location"):
		s.Location = strings.Join(w.From(2), " ")
	case w.Prefix("snmp-server", "contact"):
		s.Contact = strings.Join(w.From(2), " ")
	case slices.Contains(snmpIgnored, w.At(1)):
	default:
		x.unknown(n, baseline.FacetSNMP)
	}
}

// mergeCommunity merges the several statements NX-OS writes per
// community (group, then use-ipv4acl).
func (x *extraction) mergeCommunity(c baseline.Community) {
	s := &x.p.SNMP
	s.State = baseline.StateEnabled
	i := slices.IndexFunc(s.Communities, func(o baseline.Community) bool { return o.Name.Reveal() == c.Name.Reveal() })
	if i < 0 {
		s.Communities = append(s.Communities, c)
		return
	}
	s.Communities[i].Write = s.Communities[i].Write || c.Write
	if c.ACL != "" {
		s.Communities[i].ACL = c.ACL
	}
}

func (x *extraction) addVersion(v string) {
	s := &x.p.SNMP
	s.State = baseline.StateEnabled
	if !slices.Contains(s.Versions, v) {
		s.Versions = append(s.Versions, v)
		slices.Sort(s.Versions)
	}
}
