package cli

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/evidence"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/report"
)

func (a *app) coverageCmd() *cobra.Command {
	return &cobra.Command{
		Use: "coverage", Short: shortCoverage, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			app, err := a.build(cmd.Context())
			if err != nil {
				return err
			}
			sel, err := a.selector()
			if err != nil {
				return err
			}
			xs, err := app.Runner.Extract(cmd.Context(), sel)
			if err != nil {
				return err
			}
			devices := make([]report.Device, 0, len(xs))
			for _, x := range xs {
				devices = append(devices, report.Device{Device: x.Device, Vendor: cmp.Or(x.Vendor, x.Error),
					Coverage: x.Extraction.Coverage, Issues: x.Extraction.Issues})
			}
			rep := report.New(a.env.Now(), nil, devices)
			out := cmd.OutOrStdout()
			facets := baseline.Facets()
			names := make([]string, len(facets))
			for i, f := range facets {
				names[i] = string(f)
			}
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintf(tw, textCoverage, strings.Join(names, "\t"))
			rows := rep.Coverage(facets)
			for _, row := range rows {
				cells := make([]string, len(facets))
				for i, f := range facets {
					cells[i] = coverageCell(row.Facets[f], row.Devices)
				}
				fmt.Fprintf(tw, "%s\t%d\t%s\n", row.Vendor, row.Devices, strings.Join(cells, "\t"))
			}
			tw.Flush()
			for _, row := range rows {
				if len(row.Issues) == 0 {
					continue
				}
				fmt.Fprintf(out, textIssues, row.Vendor)
				keys := slices.SortedFunc(maps.Keys(row.Issues), func(x, y string) int {
					return cmp.Or(cmp.Compare(row.Issues[y], row.Issues[x]), cmp.Compare(x, y))
				})
				for _, k := range keys[:min(len(keys), 20)] {
					fmt.Fprintf(out, textIssueRow, row.Issues[k], sanitize(k))
				}
			}
			return nil
		},
	}
}

// coverageCell renders one facet's coverage: "✓" when complete everywhere,
// "-" when unsupported, otherwise the counts.
func coverageCell(counts map[evidence.Status]int, total int) string {
	switch {
	case counts[evidence.StatusComplete] == total:
		return "✓"
	case counts[evidence.StatusUnsupported] == total:
		return "-"
	}
	return fmt.Sprintf("%d✓/%d~/%d-", counts[evidence.StatusComplete], counts[evidence.StatusPartial],
		counts[evidence.StatusUnsupported])
}
