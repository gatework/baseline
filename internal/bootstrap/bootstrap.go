package bootstrap

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"go.yaml.in/yaml/v3"

	"github.com/gatework/netops/assess"
	textrule "github.com/gatework/netops/baseline"
	nbootstrap "github.com/gatework/netops/bootstrap"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/check"
	"github.com/gatework/baseline/internal/inventory"
	"github.com/gatework/baseline/internal/source"
	"github.com/gatework/baseline/internal/workflow"
	"github.com/gatework/baseline/policy"
	"github.com/gatework/baseline/vendors"
	"github.com/gatework/baseline/vendors/comware"
	"github.com/gatework/baseline/vendors/nxos"
)

// Name is the tool name in the shared gatework layout.
const Name = "baseline"

// Config is the tool configuration file baseline.yml, found as
// $BASELINE_CONFIG, ./baseline.yml, then ~/.gatework/baseline.yml. Relative
// paths resolve against the file's directory, "~" against the home
// directory.
type Config struct {
	Source string `yaml:"source,omitempty"`
	// Policy is the baseline policy: a file path, or the policy document
	// itself written inline under the key.
	Policy Policy `yaml:"policy,omitempty"`
	Naming struct {
		Pattern string            `yaml:"pattern,omitempty"`
		Roles   map[string]string `yaml:"roles,omitempty"`
	} `yaml:"naming,omitempty"`
	// Vendors maps inventory vendor keys to extractor names.
	Vendors map[string]string `yaml:"vendors,omitempty"`
	Workers int               `yaml:"workers,omitempty"`
}

// Policy is the policy entry of baseline.yml: a path or an inline
// document. The zero value is the empty policy.
type Policy struct {
	Path   string
	Inline []byte
}

// UnmarshalYAML accepts a scalar path or an inline mapping.
func (p *Policy) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		p.Path = n.Value
		return nil
	case yaml.MappingNode:
		body, err := yaml.Marshal(n)
		if err != nil {
			return fmt.Errorf("bootstrap: policy: %w", err)
		}
		p.Inline = body
		return nil
	case yaml.DocumentNode, yaml.SequenceNode, yaml.AliasNode:
	}
	return fmt.Errorf("%w: policy must be a path or a mapping", ErrConfig)
}

// ErrConfig reports an invalid baseline.yml.
var ErrConfig = errors.New("bootstrap: invalid configuration")

// Discover returns the configuration path to read: explicit when given,
// otherwise the netops discovery of baseline.yml ("" when none exists).
func Discover(explicit string, environ map[string]string, home string) string {
	if explicit != "" {
		return nbootstrap.ResolvePath(explicit, ".", home)
	}
	return nbootstrap.Env{App: Name, Environ: environ, Home: home}.Discover()
}

// Load reads the configuration at path; "" yields the defaults. A
// discovered file must exist; an explicit one is reported when missing.
func Load(ctx context.Context, path, home string) (Config, error) {
	var c Config
	if path == "" {
		return c, nil
	}
	if _, err := nbootstrap.ReadYAML(ctx, path, false, &c); err != nil {
		return c, err
	}
	dir := filepath.Dir(path)
	c.Source = nbootstrap.ResolvePath(c.Source, dir, home)
	c.Policy.Path = nbootstrap.ResolvePath(c.Policy.Path, dir, home)
	return c, nil
}

// App is the wired application.
type App struct {
	Runner  *workflow.Runner
	Catalog *assess.Catalog[*baseline.Posture]
	Policy  *policy.Policy
	Naming  *inventory.Naming
}

// Build wires the application for c. An empty policy path uses the empty
// policy: every check with its default parameters.
func Build(c Config, logger *slog.Logger) (*App, error) {
	if c.Source == "" {
		return nil, errors.New("bootstrap: no source directory")
	}
	pol, err := LoadPolicy(c.Policy)
	if err != nil {
		return nil, err
	}
	catalog, err := Catalog(pol)
	if err != nil {
		return nil, err
	}
	naming, err := inventory.NewNaming(cmp.Or(c.Naming.Pattern, inventory.DefaultPattern), c.Naming.Roles)
	if err != nil {
		return nil, err
	}
	runner, err := workflow.New(source.NewDir(c.Source), vendors.New(c.Vendors), pol, catalog, workflow.Options{
		Workers: c.Workers, Classify: naming.Classify, Logger: logger,
	})
	if err != nil {
		return nil, err
	}
	return &App{Runner: runner, Catalog: catalog, Policy: pol, Naming: naming}, nil
}

// LoadPolicy reads the policy: inline, from its path, or the empty policy.
func LoadPolicy(p Policy) (*policy.Policy, error) {
	body := []byte("layers: []\n")
	switch {
	case p.Inline != nil:
		body = p.Inline
	case p.Path != "":
		var err error
		if body, err = os.ReadFile(p.Path); err != nil {
			return nil, fmt.Errorf("bootstrap: %w", err)
		}
	}
	return policy.Decode(body)
}

// Catalog builds the check catalog: the vendor-neutral checks, the
// built-in vendor text rules and the policy's custom text rules.
func Catalog(pol *policy.Policy) (*assess.Catalog[*baseline.Posture], error) {
	packs := map[string][]textrule.Rule{}
	for name, load := range map[string]func() ([]textrule.Rule, error){comware.Name: comware.Rules, nxos.Name: nxos.Rules} {
		rules, err := load()
		if err != nil {
			return nil, fmt.Errorf("bootstrap: %s rules: %w", name, err)
		}
		packs[name] = rules
	}
	for dialect, rules := range pol.TextRules() {
		packs[dialect] = append(packs[dialect], rules...)
	}
	var extra []check.Rule
	for _, d := range slices.Sorted(maps.Keys(packs)) {
		rules, err := check.Text(d, packs[d])
		if err != nil {
			return nil, err
		}
		extra = append(extra, rules...)
	}
	return check.New(extra...)
}
