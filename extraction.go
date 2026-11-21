package baseline

import (
	"cmp"
	"context"
	"maps"
	"slices"

	"github.com/gatework/netops/config"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"
)

// Extraction is the result of extracting one configuration.
type Extraction struct {
	Posture  *Posture
	Coverage evidence.Coverage
	// Issues are management lines the extractor recognized as belonging to
	// a facet but could not decode; each degrades its facet to partial.
	Issues []evidence.Issue
}

// Tally accumulates an extractor's coverage: the facets it supports, the
// dialect, and the lines it could not decode. The zero value is not
// usable; use NewTally.
type Tally struct {
	device    string
	supported map[evidence.Dimension]bool
	issues    map[evidence.Dimension][]evidence.Issue
	dialect   evidence.Dimension
}

// NewTally starts a tally for device, whose configuration is in dialect,
// supporting facets.
func NewTally(deviceID, dialect string, facets ...evidence.Dimension) *Tally {
	t := &Tally{
		device: deviceID, supported: map[evidence.Dimension]bool{},
		issues: map[evidence.Dimension][]evidence.Issue{}, dialect: DialectFacet(dialect),
	}
	for _, f := range facets {
		t.supported[f] = true
	}
	return t
}

// Unrecognized records that line of facet could not be decoded. The line
// text is not recorded, so no configuration content leaks into issues.
func (t *Tally) Unrecognized(facet evidence.Dimension, line int, keyword string) {
	ref := evidence.SourceRef{Device: t.device, Command: "configuration", Line: line}
	t.issues[facet] = append(t.issues[facet], evidence.Issue{
		Code: "unrecognized", Source: &ref,
		Fields: []evidence.Field{{Key: "facet", Value: string(facet)}, {Key: "keyword", Value: keyword}},
	})
}

// Result returns the extraction for posture: every facet of Facets is
// complete, partial (supported with issues) or unsupported, and the
// dialect facet is complete.
func (t *Tally) Result(p *Posture) Extraction {
	entries := map[evidence.Dimension]evidence.Status{t.dialect: evidence.StatusComplete}
	var issues []evidence.Issue
	for _, f := range Facets() {
		switch {
		case !t.supported[f]:
			entries[f] = evidence.StatusUnsupported
		case len(t.issues[f]) > 0:
			entries[f] = evidence.StatusPartial
		default:
			entries[f] = evidence.StatusComplete
		}
	}
	for _, f := range slices.Sorted(maps.Keys(t.issues)) {
		issues = append(issues, t.issues[f]...)
	}
	slices.SortStableFunc(issues, func(a, b evidence.Issue) int { return cmp.Compare(a.Source.Line, b.Source.Line) })
	cov, err := evidence.NewCoverage(entries)
	if err != nil {
		// Facet names and statuses are constants of this package.
		panic(err)
	}
	return Extraction{Posture: p, Coverage: cov, Issues: issues}
}

// Extractor is a vendor's decoder of configurations into postures: the
// port through which vendor syntax enters the model. Implementations are
// stateless and safe for concurrent use.
//
//nolint:iface // the port vendors implement and the workflow consumes; the model package owns it
type Extractor interface {
	// Vendor returns the extractor name, also its dialect facet name.
	Vendor() string
	// Dialect returns the configuration dialect to parse with.
	Dialect() config.Dialect
	// Extract builds the posture of d from doc.
	Extract(ctx context.Context, d device.Device, doc *config.Document) (Extraction, error)
}
