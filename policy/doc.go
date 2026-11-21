// Package policy is the configurable baseline: which checks run on which
// devices, with which expected values, and which violations are accepted.
//
// A Policy is a list of layers applied in order, general to specific. A
// layer applies to the devices its scope selects (netops device selector
// syntax, plus "region=" for the region label) minus those its except
// selects. A layer enables, disables (by ID glob) and tunes checks; a later
// layer replaces the severity and the individual parameters an earlier one
// set. Parameter strings may reference device variables ("${region}",
// "${site}", "${role}", "${vendor}", "${name}", "${label.K}") and policy
// lookups ("${ntp_servers}" selected by another variable).
//
// A Waiver accepts the violations of matching checks on matching devices
// until it expires: findings stay in the report, marked waived. An
// expired waiver no longer applies and is reported.
package policy
