package mgmt

import (
	"regexp"

	"github.com/gatework/netops/evidence"

	"github.com/gatework/baseline"
)

// Facets are the facets an appliance extractor supports: the management
// plane without login lines, 802.1X and switch interfaces.
func Facets() []evidence.Dimension {
	return []evidence.Dimension{
		baseline.FacetAAA, baseline.FacetLogging, baseline.FacetNTP, baseline.FacetClock, baseline.FacetSNMP,
		baseline.FacetService, baseline.FacetAccount, baseline.FacetACL,
	}
}

// Sensitive returns patterns whose first group is a secret, for the given
// keywords followed by a value ("secret X", "rcomm X").
func Sensitive(keywords ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(keywords))
	for _, k := range keywords {
		out = append(out, regexp.MustCompile(`(?i)\b`+regexp.QuoteMeta(k)+`\s+(?:\d\s+)?("[^"]*"|\S+)`))
	}
	return out
}
