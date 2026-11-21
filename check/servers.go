package check

import (
	"fmt"
	"slices"
	"strings"
)

// Order is how a server list's order is compared.
type Order string

// Orders.
const (
	OrderStrict  Order = "strict"
	OrderPrimary Order = "primary"
	OrderAny     Order = "any"
)

// Valid reports whether o is a known order.
func (o Order) Valid() bool { return o == OrderStrict || o == OrderPrimary || o == OrderAny }

// ServerSpec is the expectation on an ordered server list.
type ServerSpec struct {
	Expected  []string // hosts in expected order; empty checks only Min
	Order     Order
	Exclusive bool // hosts outside Expected are violations
	Min       int  // minimum number of servers
}

// Problem is one way a server list deviates from its spec.
type Problem struct {
	Kind   ProblemKind
	Hosts  []string // the hosts concerned
	Detail string
}

// ProblemKind classifies a Problem.
type ProblemKind string

// Problem kinds.
const (
	ProblemMissing    ProblemKind = "missing"
	ProblemUnexpected ProblemKind = "unexpected"
	ProblemOrder      ProblemKind = "order"
	ProblemTooFew     ProblemKind = "too_few"
)

// Compare checks actual, in effective order, against the spec. Hosts
// compare case-insensitively.
func (s ServerSpec) Compare(actual []string) []Problem {
	var out []Problem
	norm := func(h string) string { return strings.ToLower(strings.TrimSpace(h)) }
	have := make([]string, len(actual))
	for i, h := range actual {
		have[i] = norm(h)
	}
	want := make([]string, len(s.Expected))
	for i, h := range s.Expected {
		want[i] = norm(h)
	}
	if len(have) < s.Min {
		out = append(out, Problem{Kind: ProblemTooFew, Detail: fmt.Sprintf("%d < %d", len(have), s.Min)})
	}
	var missing, unexpected []string
	for _, h := range want {
		if !slices.Contains(have, h) {
			missing = append(missing, h)
		}
	}
	if s.Exclusive && len(want) > 0 {
		for _, h := range have {
			if !slices.Contains(want, h) {
				unexpected = append(unexpected, h)
			}
		}
	}
	if len(missing) > 0 {
		out = append(out, Problem{Kind: ProblemMissing, Hosts: missing})
	}
	if len(unexpected) > 0 {
		out = append(out, Problem{Kind: ProblemUnexpected, Hosts: unexpected})
	}
	if len(want) == 0 || len(missing) > 0 {
		return out
	}
	// Every expected host is present: compare the order of the expected
	// hosts as they appear in actual.
	var seen []string
	for _, h := range have {
		if slices.Contains(want, h) && !slices.Contains(seen, h) {
			seen = append(seen, h)
		}
	}
	switch s.Order {
	case OrderStrict:
		if !slices.Equal(seen, want) {
			out = append(out, Problem{Kind: ProblemOrder, Hosts: seen})
		}
	case OrderPrimary:
		if have[0] != want[0] {
			out = append(out, Problem{Kind: ProblemOrder, Hosts: have[:1]})
		}
	case OrderAny:
	}
	return out
}
