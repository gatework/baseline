package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/assess"
)

func (a *app) checksCmd() *cobra.Command {
	return &cobra.Command{
		Use: "checks", Short: shortChecks, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pol, err := loadCatalog(cmd.Context(), a)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			for _, m := range pol.Metas() {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", m.ID, m.Severity, dims(m), m.Title)
			}
			return tw.Flush()
		},
	}
}

func (a *app) explainCmd() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use: "explain CHECK", Short: shortExplain, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			catalog, err := loadCatalog(cmd.Context(), a)
			if err != nil {
				return err
			}
			id := assess.RuleID(args[0])
			r, ok := catalog.Lookup(id)
			if !ok {
				return fmt.Errorf(errUnknownCheck, id)
			}
			m := r.Meta()
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, textCheckMeta, m.ID, m.Title, m.Severity, m.Category, dims(m))
			for _, p := range m.Params {
				fmt.Fprintf(out, textParam, p.Name(), p.Kind())
			}
			if name == "" {
				return nil
			}
			app, err := a.build(cmd.Context())
			if err != nil {
				return err
			}
			devices, err := app.Runner.Devices(cmd.Context(), noSelector())
			if err != nil {
				return err
			}
			for _, d := range devices {
				if !strings.EqualFold(d.Name, name) && d.ID != name {
					continue
				}
				res, err := app.Policy.Resolve(d, a.env.Now(), app.Catalog.IDs())
				if err != nil {
					return err
				}
				rp := res.Policy.Rules[id]
				enabled := rp.Enabled == nil || *rp.Enabled
				params, _ := json.Marshal(rp.Params)
				sev := m.Severity
				if rp.Severity.Valid() {
					sev = rp.Severity
				}
				fmt.Fprintf(out, textResolved, d.Label(), enabled, sev, strings.Join(res.Layers, " > "), params)
				return nil
			}
			return fmt.Errorf(errUnknownDevice, name)
		},
	}
	cmd.Flags().StringVar(&name, "device", "", flagDevice)
	return cmd
}

func dims(m assess.Meta) string {
	parts := make([]string, len(m.Requires))
	for i, d := range m.Requires {
		parts[i] = string(d)
	}
	return strings.Join(parts, ",")
}
