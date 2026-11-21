// Package baseline is the vendor-neutral model of a network device's
// management plane, the subject of configuration baseline checks.
//
// A vendor extractor turns one configuration into a Posture: AAA servers
// and method lists, syslog and NTP servers in their configured order,
// SNMP, console and VTY lines, management services, local accounts,
// 802.1X/MAC authentication and interfaces. Checks read only the Posture,
// never vendor syntax, so one check covers every vendor whose extractor
// fills the facets it requires.
//
// A Facet names one part of the model. An extractor declares, per facet,
// whether it decodes it completely or does not support it at all; the
// assess engine then skips checks whose facets are missing instead of
// reporting false violations.
//
// Secrets never enter the model: shared keys and passwords are recorded
// only as "set", SNMP community names are kept as secret.Secret.
package baseline
