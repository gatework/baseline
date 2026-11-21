// Package check is the catalog of vendor-neutral baseline checks over a
// baseline.Posture, plus adapters that turn vendor text rules into checks.
//
// Every check is an assess.Rule: it declares the facets it requires, so
// the engine skips it on vendors that do not support them, and its
// expected values are typed parameters that a policy sets per region,
// site, role or vendor. Checks never read vendor syntax.
//
// Server lists are compared with an Order mode: "strict" requires the
// expected servers in the expected order (primary, then secondary...),
// "primary" requires only the first one to match, "any" ignores order.
package check
