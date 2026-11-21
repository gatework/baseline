package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/baseline/survey"
)

func (a *app) surveyCmd() *cobra.Command {
	var quorum float64
	var draft string
	cmd := &cobra.Command{
		Use: "survey", Short: shortSurvey, Args: cobra.NoArgs,
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
			var samples []survey.Sample
			for _, x := range xs {
				if x.Error == "" {
					samples = append(samples, survey.Sample{Device: x.Device, Vendor: x.Vendor, Posture: x.Extraction.Posture})
				}
			}
			s := survey.Build(samples, quorum)
			out := cmd.OutOrStdout()
			for _, d := range s.Distributions {
				consensus := textNoConsensus
				if d.Reached {
					consensus = d.Consensus
				}
				fmt.Fprintf(out, textDistTitle, d.Check, d.Scope, d.Total, d.Absent, sanitize(consensus), d.Share*100)
				for _, v := range d.Values[:min(len(d.Values), 5)] {
					fmt.Fprintf(out, textDistRow, v.Count, sanitize(v.Value), strings.Join(v.Devices, ", "))
				}
			}
			body, err := s.Draft()
			if err != nil {
				return err
			}
			if draft == "-" {
				fmt.Fprintf(out, "\n%s", body)
				return nil
			}
			if err := a.env.WriteFile(draft, body); err != nil {
				return err
			}
			fmt.Fprintf(out, textDraftSaved, draft)
			return nil
		},
	}
	cmd.Flags().Float64Var(&quorum, "quorum", 0.6, flagQuorum)
	cmd.Flags().StringVar(&draft, "draft", "policy.draft.yml", flagDraft)
	return cmd
}
