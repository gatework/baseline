// Package comware extracts the management-plane posture of H3C Comware V5
// and V7 configurations (switches, routers and wireless controllers) and
// carries the Comware best-practice text rules.
//
// Absent statements take Comware V7 defaults: telnet, SSH, HTTP, HTTPS and
// NTP are disabled; info-center is enabled; VTY lines authenticate by
// password and AUX/console lines not at all; VTY lines accept SSH and
// telnet; the idle timeout is ten minutes; the default ISP domain is
// "system" with local authentication; the default SNMP version is v3.
package comware
