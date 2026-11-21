// Package alteon extracts the management-plane posture of Radware Alteon
// configurations ("/cfg/dump" path format).
//
// Statements are menu paths ("/c/sys/ntp") followed by tab-indented
// settings. "/c/sys/access/mgmt/add" networks act as the ACL of the
// management protocols they list.
package alteon
