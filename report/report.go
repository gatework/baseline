package report

import (
	"cmp"
	"slices"
	"strings"
	"time"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"
)

// SchemaVersion is the version of the Report JSON document.
const SchemaVersion = 1

// Status is the outcome of one check on one device.
type Status string

// Statuses.
const (
	StatusPass        Status = "pass"
	StatusFail        Status = "fail"
	StatusWaived      Status = "waived"
	StatusUnsupported Status = "unsupported"
	StatusDisabled    Status = "disabled"
	StatusError       Status = "error"
)

// Statuses returns every status in matrix legend order.
func Statuses() []Status {
	return []Status{StatusFail, StatusWaived, StatusPass, StatusUnsupported, StatusDisabled, StatusError}
}

// Waiver is the waiver that accepted a finding.
type Waiver struct {
	ID      string `json:"id"`
	Reason  string `json:"reason"`
	Owner   string `json:"owner"`
	Expires string `json:"expires"`
}

// Result is one finding, open or waived.
type Result struct {
	Finding assess.Finding `json:"finding"`
	Waiver  *Waiver        `json:"waiver,omitempty"`
}

// Open reports whether the finding is not waived.
func (r Result) Open() bool { return r.Waiver == nil }

// Device is the result of one device.
type Device struct {
	Device   device.Device        `json:"device"`
	Vendor   string               `json:"vendor,omitempty"` // extractor name
	Layers   []string             `json:"layers,omitempty"`
	Coverage evidence.Coverage    `json:"coverage"`
	Issues   []evidence.Issue     `json:"issues,omitempty"`
	Results  []Result             `json:"results"`
	Rules    []assess.RuleOutcome `json:"rules"`
	// ExpiredWaivers are waivers that match the device but have expired.
	ExpiredWaivers []string `json:"expired_waivers,omitempty"`
	// Error is the failure code when the device could not be checked.
	Error string `json:"error,omitempty"`
}

// Status returns the status of rule on the device.
func (d Device) Status(rule assess.RuleID) Status {
	if d.Error != "" {
		return StatusError
	}
	i := slices.IndexFunc(d.Rules, func(o assess.RuleOutcome) bool { return o.Rule == rule })
	if i < 0 {
		return StatusUnsupported
	}
	switch d.Rules[i].State {
	case assess.RuleDisabled:
		return StatusDisabled
	case assess.RuleSkipped:
		return StatusUnsupported
	case assess.RuleFailed:
		return StatusError
	case assess.RuleRan:
	}
	status := StatusPass
	for _, r := range d.Results {
		if r.Finding.Rule != rule {
			continue
		}
		if r.Open() {
			return StatusFail
		}
		status = StatusWaived
	}
	return status
}

// Open returns the open findings.
func (d Device) Open() []Result {
	var out []Result
	for _, r := range d.Results {
		if r.Open() {
			out = append(out, r)
		}
	}
	return out
}

// Report is the result of one baseline run.
type Report struct {
	SchemaVersion int       `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	// Checks are the declarations of every check in catalog order.
	Checks  []Check  `json:"checks"`
	Devices []Device `json:"devices"`
}

// Check is the declaration of one check, for report legends.
type Check struct {
	ID       assess.RuleID   `json:"id"`
	Title    string          `json:"title"`
	Severity assess.Severity `json:"severity"`
	Category assess.Category `json:"category"`
}

// New returns a report of devices, ordered by device.
func New(at time.Time, metas []assess.Meta, devices []Device) Report {
	r := Report{SchemaVersion: SchemaVersion, GeneratedAt: at, Devices: slices.Clone(devices)}
	for _, m := range metas {
		r.Checks = append(r.Checks, Check{ID: m.ID, Title: m.Title, Severity: m.Severity, Category: m.Category})
	}
	slices.SortStableFunc(r.Devices, func(a, b Device) int { return device.Compare(a.Device, b.Device) })
	return r
}

// Highest returns the most severe open finding, or SeverityUnset.
func (r Report) Highest() assess.Severity {
	h := assess.SeverityUnset
	for _, d := range r.Devices {
		for _, res := range d.Open() {
			h = max(h, res.Finding.Severity)
		}
	}
	return h
}

// Failed returns the devices that could not be checked.
func (r Report) Failed() []Device {
	var out []Device
	for _, d := range r.Devices {
		if d.Error != "" {
			out = append(out, d)
		}
	}
	return out
}

// CheckSummary counts the statuses of one check across devices.
type CheckSummary struct {
	Check  Check          `json:"check"`
	Counts map[Status]int `json:"counts"`
}

// ByCheck summarizes every check, most failing first, then catalog
// order.
func (r Report) ByCheck() []CheckSummary {
	out := make([]CheckSummary, len(r.Checks))
	for i, c := range r.Checks {
		out[i] = CheckSummary{Check: c, Counts: map[Status]int{}}
		for _, d := range r.Devices {
			out[i].Counts[d.Status(c.ID)]++
		}
	}
	slices.SortStableFunc(out, func(a, b CheckSummary) int {
		return cmp.Compare(b.Counts[StatusFail], a.Counts[StatusFail])
	})
	return out
}

// Compliant counts the devices without open findings or errors.
func (r Report) Compliant() int {
	n := 0
	for _, d := range r.Devices {
		if d.Error == "" && len(d.Open()) == 0 {
			n++
		}
	}
	return n
}

// CoverageRow is the facet coverage of one vendor.
type CoverageRow struct {
	Vendor  string                                         `json:"vendor"`
	Devices int                                            `json:"devices"`
	Facets  map[evidence.Dimension]map[evidence.Status]int `json:"facets"`
	Issues  map[string]int                                 `json:"issues,omitempty"` // by "facet keyword"
}

// Coverage returns the facet coverage by vendor, sorted by vendor.
func (r Report) Coverage(facets []evidence.Dimension) []CoverageRow {
	rows := map[string]*CoverageRow{}
	for _, d := range r.Devices {
		v := cmp.Or(d.Vendor, "unknown")
		row, ok := rows[v]
		if !ok {
			row = &CoverageRow{Vendor: v, Facets: map[evidence.Dimension]map[evidence.Status]int{}, Issues: map[string]int{}}
			rows[v] = row
		}
		row.Devices++
		for _, f := range facets {
			if row.Facets[f] == nil {
				row.Facets[f] = map[evidence.Status]int{}
			}
			row.Facets[f][d.Coverage.Status(f)]++
		}
		for _, is := range d.Issues {
			values := make([]string, len(is.Fields))
			for i, fl := range is.Fields {
				values[i] = fl.Value
			}
			row.Issues[strings.Join(values, " ")]++
		}
	}
	out := make([]CoverageRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, *row)
	}
	slices.SortFunc(out, func(a, b CoverageRow) int { return cmp.Compare(a.Vendor, b.Vendor) })
	return out
}
