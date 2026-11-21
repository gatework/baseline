package baseline

import "github.com/gatework/netops/evidence"

// Facets of the management-plane model. Each is an evidence.Dimension, so
// checks declare them in assess.Meta.Requires and extractors report them
// in an evidence.Coverage.
const (
	FacetAAA       evidence.Dimension = "aaa"
	FacetLogging   evidence.Dimension = "logging"
	FacetNTP       evidence.Dimension = "ntp"
	FacetClock     evidence.Dimension = "clock"
	FacetSNMP      evidence.Dimension = "snmp"
	FacetLine      evidence.Dimension = "line"
	FacetService   evidence.Dimension = "service"
	FacetAccount   evidence.Dimension = "account"
	FacetNAC       evidence.Dimension = "nac"
	FacetInterface evidence.Dimension = "interface"
	FacetACL       evidence.Dimension = "acl"
)

// Facets returns every facet in report order.
func Facets() []evidence.Dimension {
	return []evidence.Dimension{
		FacetAAA, FacetLogging, FacetNTP, FacetClock, FacetSNMP, FacetLine,
		FacetService, FacetAccount, FacetNAC, FacetInterface, FacetACL,
	}
}

// DialectFacet is the facet that is complete only for configurations of
// one dialect, such as "dialect.comware". Vendor text rules require it, so
// they run on that vendor's devices and are reported unsupported elsewhere.
func DialectFacet(dialect string) evidence.Dimension {
	return evidence.Dimension("dialect." + dialect)
}
