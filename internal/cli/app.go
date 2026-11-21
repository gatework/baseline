package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/netops/device"

	"github.com/gatework/baseline/internal/bootstrap"
)

// Exit codes.
const (
	ExitOK         = 0
	ExitFindings   = 1 // open findings at or above --fail-on
	ExitError      = 2
	ExitIncomplete = 3 // some devices could not be checked
)

// Version is the release of the command.
const Version = "0.1.0"

var (
	errFindings   = errors.New("cli: findings at or above the threshold")
	errIncomplete = errors.New("cli: some devices could not be checked")
)

// Env is the process environment of a run.
type Env struct {
	Stdout, Stderr io.Writer
	// Environ and Home locate ~/.gatework/baseline.yml; both may be empty.
	Environ map[string]string
	Home    string
	Now     func() time.Time
	// WriteFile writes a file the user asked for (draft policy).
	WriteFile func(path string, data []byte) error
}

type app struct {
	env     Env
	config  string
	source  string
	policy  string
	selects []string
	workers int
}

// Run executes the command line args and returns the exit code.
func Run(ctx context.Context, args []string, env Env) int {
	if env.Now == nil {
		env.Now = time.Now
	}
	a := &app{env: env}
	root := a.root() //nolint:contextcheck // cobra hands ctx to every command through cmd.Context()
	root.SetArgs(args)
	root.SetOut(env.Stdout)
	root.SetErr(env.Stderr)
	err := root.ExecuteContext(ctx)
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, errFindings):
		return ExitFindings
	case errors.Is(err, errIncomplete):
		return ExitIncomplete
	default:
		fmt.Fprintln(env.Stderr, errText(err))
		return ExitError
	}
}

func (a *app) root() *cobra.Command {
	root := &cobra.Command{
		Use: "baseline", Short: shortRoot, Long: longRoot, Version: Version,
		SilenceUsage: true, SilenceErrors: true,
	}
	f := root.PersistentFlags()
	f.StringVarP(&a.config, "config", "c", "", flagConfig)
	f.StringVarP(&a.source, "source", "s", "", flagSource)
	f.StringVarP(&a.policy, "policy", "p", "", flagPolicy)
	f.StringArrayVar(&a.selects, "select", nil, flagSelect)
	f.IntVar(&a.workers, "workers", 0, flagWorkers)
	root.AddCommand(a.checkCmd(), a.coverageCmd(), a.surveyCmd(), a.explainCmd(), a.checksCmd())
	localize(root)
	return root
}

// load reads the discovered or named baseline.yml and applies the flag
// overrides.
func (a *app) load(ctx context.Context) (bootstrap.Config, error) {
	c, err := bootstrap.Load(ctx, bootstrap.Discover(a.config, a.env.Environ, a.env.Home), a.env.Home)
	if err != nil {
		return c, err
	}
	if a.source != "" {
		c.Source = a.source
	}
	if a.policy != "" {
		c.Policy = bootstrap.Policy{Path: a.policy}
	}
	return c, nil
}

// build loads the configuration and wires the application.
func (a *app) build(ctx context.Context) (*bootstrap.App, error) {
	c, err := a.load(ctx)
	if err != nil {
		return nil, err
	}
	if a.workers > 0 {
		c.Workers = a.workers
	}
	return bootstrap.Build(c, slog.New(slog.DiscardHandler))
}

func (a *app) selector() (device.Selector, error) { return device.ParseSelector(a.selects...) }
