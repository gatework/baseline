package baseline

import (
	"fmt"
	"slices"
)

// Rank is the role of a server within an ordered set. Vendors that name
// roles explicitly (H3C hwtacacs primary/secondary, PAN-OS
// primary-ntp-server) yield RankPrimary and RankSecondary; vendors that
// rely on configuration order yield RankOrdered and the position in the
// slice is the order.
type Rank int

// Ranks.
const (
	RankUnset Rank = iota
	RankPrimary
	RankSecondary
	RankOrdered
)

var rankNames = [...]string{"", "primary", "secondary", "ordered"}

// String returns the lowercase name.
func (r Rank) String() string {
	if r < 0 || int(r) >= len(rankNames) {
		return fmt.Sprintf("Rank(%d)", int(r))
	}
	return rankNames[r]
}

// Valid reports whether r is a set rank.
func (r Rank) Valid() bool { return r >= RankPrimary && r <= RankOrdered }

// MarshalText encodes the rank by name.
func (r Rank) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

// Server is one remote server the device uses: AAA, syslog, NTP or SNMP
// trap receiver. Shared keys are never recorded, only whether one is set.
type Server struct {
	Host   string `json:"host"`             // address or name as configured
	Port   int    `json:"port,omitempty"`   // 0 is the protocol default
	VRF    string `json:"vrf,omitempty"`    // VPN instance or VRF
	Source string `json:"source,omitempty"` // source interface or address
	Rank   Rank   `json:"rank"`
	// Function limits an AAA server to "authentication", "authorization"
	// or "accounting"; empty means every function.
	Function string `json:"function,omitempty"`
	Keyed    bool   `json:"keyed,omitempty"`
	Line     int    `json:"line,omitempty"` // configuration line, for evidence
}

// Ordered returns the servers in effective order: explicit primaries
// first, then secondaries, then the rest in configured order. The sort is
// stable, so servers of one rank keep their configured order.
func Ordered(servers []Server) []Server {
	out := slices.Clone(servers)
	weight := func(r Rank) int {
		switch r {
		case RankPrimary:
			return 0
		case RankSecondary:
			return 1
		case RankOrdered, RankUnset:
			return 2
		}
		return 3
	}
	slices.SortStableFunc(out, func(a, b Server) int { return weight(a.Rank) - weight(b.Rank) })
	return out
}

// Hosts returns the hosts of servers in effective order, without
// duplicates.
func Hosts(servers []Server) []string {
	out := make([]string, 0, len(servers))
	for _, s := range Ordered(servers) {
		if !slices.Contains(out, s.Host) {
			out = append(out, s.Host)
		}
	}
	return out
}

// ServerGroup is a named set of AAA servers of one protocol: an H3C
// hwtacacs or radius scheme, a Cisco aaa group server.
type ServerGroup struct {
	Name     string   `json:"name"`
	Protocol string   `json:"protocol"` // "tacacs" or "radius"
	Servers  []Server `json:"servers"`
	Line     int      `json:"line,omitempty"`
}

// For returns the servers that serve function, in effective order.
func (g ServerGroup) For(function string) []Server {
	var out []Server
	for _, s := range g.Servers {
		if s.Function == "" || s.Function == function {
			out = append(out, s)
		}
	}
	return Ordered(out)
}
