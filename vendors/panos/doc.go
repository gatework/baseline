// Package panos extracts the management-plane posture of Palo Alto
// PAN-OS configurations in "set" format.
//
// Management access is restricted by "permitted-ip", which acts as the
// ACL of SSH, HTTPS and SNMP. Absent statements take PAN-OS defaults:
// telnet and HTTP disabled, SSH and HTTPS enabled. Administrators that
// authenticate through an authentication profile have no local login.
package panos
