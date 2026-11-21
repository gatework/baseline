// Package survey bootstraps a baseline from the fleet as it is: it
// measures, per setting, how devices are configured globally and per
// region, finds the values most devices agree on, and drafts a policy
// whose expectations are those agreements. Devices that disagree are the
// outliers: candidates for remediation or for a waiver.
//
// Values are compared in effective order, so a fleet whose NTP servers
// agree as a set but not in order does not reach consensus on order.
// Secrets (SNMP communities, keys) are never surveyed.
package survey
