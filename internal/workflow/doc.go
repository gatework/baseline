// Package workflow runs the baseline use cases over injected ports: it
// reads each device's configuration from a Source, picks its extractor,
// extracts the posture, resolves the device's policy and runs the check
// engine, then marks waived findings.
package workflow
