package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/assess"

	"github.com/gatework/baseline/report"
)

func (a *app) checkCmd() *cobra.Command {
	var format, failOn string
	var limit int
	cmd := &cobra.Command{
		Use: "check", Short: shortCheck, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			threshold := assess.SeverityUnset
			if failOn != "" {
				s, err := assess.ParseSeverity(failOn)
				if err != nil {
					return fmt.Errorf(errSeverity, failOn)
				}
				threshold = s
			}
			app, err := a.build(cmd.Context())
			if err != nil {
				return err
			}
			sel, err := a.selector()
			if err != nil {
				return err
			}
			rep, err := app.Runner.Check(cmd.Context(), sel)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			switch format {
			case "table":
				renderSummary(out, rep, limit)
			case "json":
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(rep); err != nil {
					return err
				}
			case "matrix":
				renderMatrix(out, rep)
			default:
				return fmt.Errorf(errFormat, format)
			}
			switch {
			case len(rep.Failed()) > 0:
				return errIncomplete
			case threshold != assess.SeverityUnset && rep.Highest() >= threshold:
				return errFindings
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "table", flagFormat+"：table|json|matrix")
	cmd.Flags().StringVar(&failOn, "fail-on", "", flagFailOn+"（info|low|medium|high|critical）")
	cmd.Flags().IntVar(&limit, "limit", 50, flagLimit)
	return cmd
}

func renderSummary(out io.Writer, rep report.Report, limit int) {
	failed := len(rep.Failed())
	compliant := rep.Compliant()
	fmt.Fprintf(out, textSummary, len(rep.Devices), compliant, len(rep.Devices)-compliant-failed, failed,
		severityName(rep.Highest()))
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprint(tw, textByCheck)
	for _, s := range rep.ByCheck() {
		c := s.Counts
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n", s.Check.ID, s.Check.Severity, c[report.StatusFail],
			c[report.StatusWaived], c[report.StatusPass], c[report.StatusUnsupported], c[report.StatusDisabled],
			c[report.StatusError], s.Check.Title)
	}
	tw.Flush()

	var open []openFinding
	waived := 0
	var expired []string
	for _, d := range rep.Devices {
		for _, r := range d.Results {
			if !r.Open() {
				waived++
				continue
			}
			open = append(open, openFinding{device: d.Device.Label(), f: r.Finding})
		}
		for _, w := range d.ExpiredWaivers {
			if !slices.Contains(expired, w) {
				expired = append(expired, w)
			}
		}
	}
	slices.SortStableFunc(open, func(x, y openFinding) int { return int(y.f.Severity) - int(x.f.Severity) })
	if len(open) > 0 {
		fmt.Fprint(out, textFindings)
		tw = tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		for i, o := range open {
			if limit > 0 && i == limit {
				tw.Flush()
				fmt.Fprintf(out, textMore, len(open)-limit)
				break
			}
			fmt.Fprintf(tw, textFindingRow, o.f.Severity, o.f.Rule, o.device, sanitize(subjectTail(o.f.Subject)), sanitize(o.f.Detail))
		}
		tw.Flush()
	}
	if waived > 0 || len(expired) > 0 {
		fmt.Fprintf(out, textWaivedCount, waived, joinOr(expired, textNone))
	}
	if failed > 0 {
		fmt.Fprint(out, textFailed)
		for _, d := range rep.Failed() {
			fmt.Fprintf(out, textFailedRow, d.Device.Label(), d.Error)
		}
	}
}

type openFinding struct {
	device string
	f      assess.Finding
}

// renderMatrix writes the device × check status matrix as CSV.
func renderMatrix(out io.Writer, rep report.Report) {
	head := []string{"device", "site", "role", "vendor"}
	for _, c := range rep.Checks {
		head = append(head, string(c.ID))
	}
	fmt.Fprintln(out, strings.Join(head, ","))
	for _, d := range rep.Devices {
		row := []string{csv(d.Device.Label()), csv(d.Device.Site), csv(d.Device.Role), csv(d.Vendor)}
		for _, c := range rep.Checks {
			row = append(row, string(d.Status(c.ID)))
		}
		fmt.Fprintln(out, strings.Join(row, ","))
	}
}

func subjectTail(s assess.Subject) string {
	parts := s.Parts()
	if len(parts) <= 1 {
		return "-"
	}
	tail := make([]string, 0, len(parts)-1)
	for _, p := range parts[1:] {
		tail = append(tail, p.Kind+":"+p.Key)
	}
	return strings.Join(tail, "/")
}

func severityName(s assess.Severity) string {
	if !s.Valid() {
		return textNone
	}
	return s.String()
}

func joinOr(v []string, empty string) string {
	if len(v) == 0 {
		return empty
	}
	return strings.Join(v, ", ")
}

func csv(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// sanitize escapes control characters so that device-derived text cannot
// drive the terminal.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}
