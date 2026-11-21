package comware

import (
	"slices"
	"strings"

	"github.com/gatework/netops/parse"
	"github.com/gatework/netops/secret"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/internal/token"
	"github.com/gatework/baseline/internal/tz"
)

// loggingIgnored lists info-center options the model does not hold.
var loggingIgnored = []string{
	"timestamp", "logbuffer", "source", "logfile", "synchronous", "security-logfile", "logging", "format",
	"diagnostic-logfile", "trace-logfile", "trapbuffer", "console", "monitor", "syslog", "trap", "snmp",
	"loghost-max", "rfc5424", "terminal",
}

// logging decodes info-center statements.
func (x *extraction) logging(n *parse.Node, w token.Words, undo bool) {
	l := &x.p.Logging
	switch {
	case w.Prefix("info-center", "enable"):
		l.State = baseline.StateEnabled
		if undo {
			l.State = baseline.StateDisabled
		}
	case undo:
	case w.Prefix("info-center", "loghost", "source"):
		l.Source = w.At(3)
	case w.Prefix("info-center", "loghost"):
		rest := w.From(2)
		var s baseline.Server
		if rest.At(0) == "vpn-instance" {
			s.VRF, rest = rest.At(1), rest.From(2)
		}
		if rest.At(0) == "ipv6" {
			rest = rest.From(1)
		}
		s.Host, s.Port, s.Rank, s.Line = rest.At(0), rest.Int("port"), baseline.RankOrdered, n.Line.Number
		if s.Host == "" {
			x.unknown(n, baseline.FacetLogging)
			return
		}
		l.Hosts = append(l.Hosts, s)
	case slices.Contains(loggingIgnored, w.At(1)):
	default:
		x.unknown(n, baseline.FacetLogging)
	}
}

// ntpIgnored lists ntp-service options the model does not hold.
var ntpIgnored = []string{
	"refclock-master", "dscp", "max-dynamic-sessions", "inbound", "broadcast-client", "multicast-client",
	"access", "time-offset-thresholds", "authentication-keyid", "reliable", "ipv6",
}

// ntp decodes ntp-service statements. A "priority" server is preferred and
// ranks first; peers are listed with servers in configured order.
func (x *extraction) ntp(n *parse.Node, w token.Words, undo bool) {
	t := &x.p.Time
	switch {
	case w.Prefix("ntp-service", "enable"):
		t.NTPState = baseline.StateEnabled
		if undo {
			t.NTPState = baseline.StateDisabled
		}
	case undo:
	case w.Prefix("ntp-service", "source"):
		t.Source = w.At(2)
	case w.Prefix("ntp-service", "authentication", "enable"):
		t.Auth = true
	case w.Prefix("ntp-service", "authentication-keyid"), w.Prefix("ntp-service", "reliable"):
	case w.Prefix("ntp-service", "unicast-server"), w.Prefix("ntp-service", "unicast-peer"):
		rest := w.From(2)
		var s baseline.Server
		if rest.At(0) == "vpn-instance" {
			s.VRF, rest = rest.At(1), rest.From(2)
		}
		s.Host, s.Line, s.Rank = rest.At(0), n.Line.Number, baseline.RankOrdered
		s.Source, _ = rest.After("source")
		s.Keyed = rest.Has("authentication-keyid")
		if rest.Has("priority") {
			s.Rank = baseline.RankPrimary
		}
		if s.Host == "" {
			x.unknown(n, baseline.FacetNTP)
			return
		}
		t.NTP = append(t.NTP, s)
	case slices.Contains(ntpIgnored, w.At(1)):
	default:
		x.unknown(n, baseline.FacetNTP)
	}
}

// clock decodes "clock timezone NAME add|minus HH:MM:SS" and "clock
// protocol ntp"; the latter makes NTP the time source on Comware V7.
func (x *extraction) clock(n *parse.Node, w token.Words) {
	switch {
	case w.Prefix("clock", "timezone"):
		d, ok := tz.Signed(w.At(3), w.At(4))
		if !ok {
			x.unknown(n, baseline.FacetClock)
			return
		}
		x.p.Time.Timezone = baseline.Timezone{Name: w.At(2), Offset: d, Set: true, Line: n.Line.Number}
	case w.Prefix("clock", "protocol"):
		if w.At(2) == "ntp" {
			x.p.Time.NTPState = baseline.StateEnabled
		}
	case w.Prefix("clock", "summer-time"), w.Prefix("clock", "datetime"):
	default:
		x.unknown(n, baseline.FacetClock)
	}
}

// snmpIgnored lists snmp-agent options the model does not hold.
var snmpIgnored = []string{
	"local-engineid", "packet", "trap", "inform", "mib-view", "group", "log", "remote", "source",
	"notification-log", "context", "calculate-password", "port", "community-map",
}

// snmp decodes snmp-agent statements.
func (x *extraction) snmp(n *parse.Node, w token.Words, undo bool) {
	s := &x.p.SNMP
	switch {
	case len(w) == 1:
		s.State = baseline.StateEnabled
		if undo {
			s.State = baseline.StateDisabled
		}
	case undo:
	case w.Prefix("snmp-agent", "sys-info", "version"):
		s.Versions = nil
		for _, v := range w.From(3) {
			if v == "all" {
				s.Versions = []string{"v1", "v2c", "v3"}
				break
			}
			s.Versions = append(s.Versions, v)
		}
	case w.Prefix("snmp-agent", "sys-info", "location"):
		s.Location = strings.Join(w.From(3), " ")
	case w.Prefix("snmp-agent", "sys-info", "contact"):
		s.Contact = strings.Join(w.From(3), " ")
	case w.Prefix("snmp-agent", "community"):
		rest := w.From(3)
		c := baseline.Community{Write: w.At(2) == "write", Line: n.Line.Number}
		if rest.At(0) == "simple" || rest.At(0) == "cipher" {
			rest = rest.From(1)
		}
		c.Name = secret.New(rest.At(0))
		c.ACL = aclAfter(rest)
		s.Communities = append(s.Communities, c)
		s.State = baseline.StateEnabled
	case w.Prefix("snmp-agent", "usm-user"):
		u := baseline.SNMPUser{Name: w.At(3), Line: n.Line.Number}
		u.Auth = w.Has("authentication-mode")
		u.Privacy = w.Has("privacy-mode")
		if w.At(2) == "v3" {
			s.Users = append(s.Users, u)
		}
		s.State = baseline.StateEnabled
	case w.Prefix("snmp-agent", "target-host"):
		rest := w.From(2)
		h := baseline.Server{Rank: baseline.RankOrdered, Line: n.Line.Number}
		h.Host, _ = rest.After("udp-domain")
		h.Port = rest.Int("udp-port")
		h.VRF, _ = rest.After("vpn-instance")
		if h.Host == "" {
			x.unknown(n, baseline.FacetSNMP)
			return
		}
		s.TrapHosts = append(s.TrapHosts, h)
	case slices.Contains(snmpIgnored, w.At(1)), w.Prefix("snmp-agent", "sys-info"):
	default:
		x.unknown(n, baseline.FacetSNMP)
	}
}

// aclAfter returns the ACL a statement references with "acl N" or "acl
// name X", ignoring "acl ipv6".
func aclAfter(w token.Words) string {
	i := slices.Index(w, "acl")
	if i < 0 {
		return ""
	}
	return aclRef(w.From(i + 1))
}
