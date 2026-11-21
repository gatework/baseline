package baseline

import (
	"time"

	"github.com/gatework/netops/config"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/secret"
)

// Posture is the management-plane model of one device's configuration.
// An extractor builds it once and checks only read it; it is not safe to
// mutate concurrently with checks.
type Posture struct {
	Device   device.Device `json:"device"`
	Hostname string        `json:"hostname,omitempty"`
	Version  string        `json:"version,omitempty"`

	AAA        AAA            `json:"aaa"`
	Logging    Logging        `json:"logging"`
	Time       Time           `json:"time"`
	SNMP       SNMP           `json:"snmp"`
	Lines      []Line         `json:"lines,omitempty"`
	Services   Services       `json:"services"`
	Accounts   []Account      `json:"accounts,omitempty"`
	NAC        NAC            `json:"nac"`
	Interfaces []Interface    `json:"interfaces,omitempty"`
	ACLs       map[string]ACL `json:"acls,omitempty"`

	// Config is the parsed configuration the posture was extracted from,
	// for vendor text rules and evidence. It is shared read-only.
	Config *config.Document `json:"-"`
}

// LinesOf returns the lines of kind k in configured order.
func (p *Posture) LinesOf(k LineKind) []Line {
	var out []Line
	for _, l := range p.Lines {
		if l.Kind == k {
			out = append(out, l)
		}
	}
	return out
}

// HasACL reports whether name is a defined access list.
func (p *Posture) HasACL(name string) bool {
	_, ok := p.ACLs[name]
	return ok
}

// Logging is the remote syslog configuration.
type Logging struct {
	State  State    `json:"state"`
	Hosts  []Server `json:"hosts,omitempty"`
	Source string   `json:"source,omitempty"`
}

// Time is the clock configuration.
type Time struct {
	NTPState State    `json:"ntp_state"`
	NTP      []Server `json:"ntp,omitempty"`
	Source   string   `json:"source,omitempty"`
	Auth     bool     `json:"auth,omitempty"`
	Timezone Timezone `json:"timezone"`
}

// Timezone is the configured time zone. Vendors spell zone names freely
// ("BeiJing", "BJ+8"), so checks compare Offset.
type Timezone struct {
	Name   string        `json:"name,omitempty"`
	Offset time.Duration `json:"offset"`
	Set    bool          `json:"set"`
	Line   int           `json:"line,omitempty"`
}

// SNMP is the agent configuration.
type SNMP struct {
	State       State       `json:"state"`
	Versions    []string    `json:"versions,omitempty"` // "v1", "v2c", "v3"
	Communities []Community `json:"communities,omitempty"`
	Users       []SNMPUser  `json:"users,omitempty"`
	TrapHosts   []Server    `json:"trap_hosts,omitempty"`
	Location    string      `json:"location,omitempty"`
	Contact     string      `json:"contact,omitempty"`
}

// Community is an SNMPv1/v2c community. Its name is a credential.
type Community struct {
	Name  secret.Secret `json:"name"`
	Write bool          `json:"write,omitempty"`
	ACL   string        `json:"acl,omitempty"`
	Line  int           `json:"line,omitempty"`
}

// SNMPUser is an SNMPv3 user.
type SNMPUser struct {
	Name    string `json:"name"`
	Auth    bool   `json:"auth"`
	Privacy bool   `json:"privacy"`
	Line    int    `json:"line,omitempty"`
}
