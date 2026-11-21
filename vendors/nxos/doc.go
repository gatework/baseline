// Package nxos extracts the management-plane posture of Cisco NX-OS
// configurations and carries the NX-OS best-practice text rules.
//
// Absent statements take NX-OS defaults: SSH is enabled and telnet
// disabled unless the features say otherwise; NX-API (HTTPS) follows
// "feature nxapi"; Ethernet ports are routed and shut down unless
// configured; VTY and console lines always authenticate through AAA; a
// login method list that does not end in "none" falls back to the local
// database.
package nxos
