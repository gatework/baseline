package baseline

import "slices"

// PortMode is the layer-2 role of an interface.
type PortMode string

// Port modes.
const (
	PortUnknown PortMode = ""
	PortAccess  PortMode = "access"
	PortTrunk   PortMode = "trunk"
	PortHybrid  PortMode = "hybrid"
	PortRouted  PortMode = "routed"
)

// InterfaceKind classifies interfaces for checks that apply to some kinds
// only.
type InterfaceKind string

// Interface kinds.
const (
	InterfacePhysical  InterfaceKind = "physical"
	InterfaceAggregate InterfaceKind = "aggregate"
	InterfaceVLAN      InterfaceKind = "vlan"
	InterfaceLoopback  InterfaceKind = "loopback"
	InterfaceMgmt      InterfaceKind = "mgmt"
	InterfaceOther     InterfaceKind = "other"
)

// Interface is the configuration of one interface.
type Interface struct {
	Name        string        `json:"name"`
	Kind        InterfaceKind `json:"kind"`
	Mode        PortMode      `json:"mode,omitempty"`
	Shutdown    bool          `json:"shutdown,omitempty"`
	Description string        `json:"description,omitempty"`
	// AccessVLAN is the access VLAN of an access port, 0 when unset.
	AccessVLAN int  `json:"access_vlan,omitempty"`
	Edge       bool `json:"edge,omitempty"` // STP edge / portfast
	Dot1x      bool `json:"dot1x,omitempty"`
	MACAuth    bool `json:"mac_auth,omitempty"`
	// Domain is the authentication domain forced on the port, if any.
	Domain     string `json:"domain,omitempty"`
	LoopDetect bool   `json:"loop_detect,omitempty"`
	// Member reports membership of an aggregate.
	Member bool `json:"member,omitempty"`
	Line   int  `json:"line,omitempty"`
}

// EndHost reports a port that faces end hosts: a physical access
// or hybrid port that is up and not part of an aggregate.
func (i Interface) EndHost() bool {
	return i.Kind == InterfacePhysical && (i.Mode == PortAccess || i.Mode == PortHybrid) && !i.Shutdown && !i.Member
}

// NAC is the network access control (802.1X and MAC authentication)
// configuration.
type NAC struct {
	Dot1x   bool `json:"dot1x"`    // enabled globally
	MACAuth bool `json:"mac_auth"` // enabled globally
	// Domains are the authentication domains used by 802.1X/MAC
	// authentication, globally or on ports, deduplicated in order.
	Domains []string `json:"domains,omitempty"`
	// Method is the 802.1X authentication method (eap, chap, pap).
	Method string `json:"method,omitempty"`
	Line   int    `json:"line,omitempty"`
}

// AddDomain records domain once.
func (n *NAC) AddDomain(domain string) {
	if domain != "" && !slices.Contains(n.Domains, domain) {
		n.Domains = append(n.Domains, domain)
	}
}
