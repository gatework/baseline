// Package ios extracts the management-plane posture of Cisco IOS and
// IOS-XE configurations, and of Centec CNOS, whose CLI follows IOS.
//
// Absent statements take IOS defaults: VTY lines accept SSH and telnet,
// the idle timeout is ten minutes, SSH runs version 1.99 (v1 compatible)
// unless "ip ssh version 2", HTTP and HTTPS follow "ip http server" and
// "ip http secure-server", telnet is enabled exactly when a usable VTY
// accepts it. Physical interfaces are access ports when the device is a
// switch (some interface uses switchport) and routed otherwise.
package ios
