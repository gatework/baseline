// Package hillstone extracts the management-plane posture of Hillstone
// StoneOS firewall configurations.
//
// StoneOS has no login lines or 802.1X in the model's sense: admin access
// is "admin host" (who may reach each protocol) plus "manage" per
// interface (where it listens). A protocol is enabled when an interface
// manages it; it is ACL-restricted when "admin host" does not allow it from
// any address.
package hillstone
