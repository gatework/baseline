package cli

import (
	"context"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/device"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/internal/bootstrap"
)

// loadCatalog builds the catalog without a source, for listing checks.
func loadCatalog(ctx context.Context, a *app) (*assess.Catalog[*baseline.Posture], error) {
	c, err := a.load(ctx)
	if err != nil {
		return nil, err
	}
	pol, err := bootstrap.LoadPolicy(c.Policy)
	if err != nil {
		return nil, err
	}
	return bootstrap.Catalog(pol)
}

func noSelector() device.Selector { return device.Selector{} }
