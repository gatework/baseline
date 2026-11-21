// Package report is the result of a baseline run: per device, the
// findings (open or waived), the outcome of every check and the facet
// coverage; across devices, the compliance matrix and summaries by check,
// severity and vendor.
//
// A check's status on a device is one of: pass, fail (an open finding),
// waived (every finding waived), unsupported (the vendor lacks a required
// facet), disabled (the policy turned it off) or error.
package report
