package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/batch"
	"github.com/gatework/netops/config"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/parse"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/policy"
	"github.com/gatework/baseline/report"
)

// Device failure codes. They name the stage that failed and never carry
// configuration content.
const (
	CodeRead        = "read_failed"
	CodeUnsupported = "unsupported_vendor"
	CodeParse       = "parse_failed"
	CodeExtract     = "extract_failed"
	CodePolicy      = "policy_failed"
	CodeCheck       = "check_failed"
)

// Source lists devices and returns their configurations.
type Source interface {
	Devices(ctx context.Context) ([]device.Device, error)
	Config(ctx context.Context, d device.Device) (string, error)
}

// Vendors picks the extractor of a device.
type Vendors interface {
	For(d device.Device, text string) (baseline.Extractor, bool)
}

// Options configure a Runner.
type Options struct {
	Workers int // devices in parallel; 0 means 8
	// Classify enriches each device (site, role, region) before policy
	// resolution; nil keeps devices as the source gives them.
	Classify func(device.Device) device.Device
	Now      func() time.Time
	Logger   *slog.Logger
}

// Runner runs checks and extractions. It is safe for concurrent use.
type Runner struct {
	src     Source
	vendors Vendors
	policy  *policy.Policy
	catalog *assess.Catalog[*baseline.Posture]
	o       Options

	mu      sync.Mutex // guards engines
	engines map[string]*assess.Engine[*baseline.Posture]
}

// New returns a runner. The policy must name only checks of the catalog.
func New(src Source, vendors Vendors, pol *policy.Policy, catalog *assess.Catalog[*baseline.Posture], o Options) (*Runner, error) {
	if err := pol.Validate(catalog.IDs()); err != nil {
		return nil, err
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Classify == nil {
		o.Classify = func(d device.Device) device.Device { return d }
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return &Runner{src: src, vendors: vendors, policy: pol, catalog: catalog, o: o,
		engines: map[string]*assess.Engine[*baseline.Posture]{}}, nil
}

// Extracted is the extraction of one device.
type Extracted struct {
	Device     device.Device
	Vendor     string
	Extraction baseline.Extraction
	Error      string
}

// Devices lists the source devices that sel selects, classified.
func (r *Runner) Devices(ctx context.Context, sel device.Selector) ([]device.Device, error) {
	all, err := r.src.Devices(ctx)
	if err != nil {
		return nil, err
	}
	var out []device.Device
	for _, d := range all {
		d = r.o.Classify(d)
		if sel.Match(d) {
			out = append(out, d)
		}
	}
	return out, nil
}

// Extract extracts every selected device.
func (r *Runner) Extract(ctx context.Context, sel device.Selector) ([]Extracted, error) {
	devices, err := r.Devices(ctx, sel)
	if err != nil {
		return nil, err
	}
	rep, err := batch.Run(ctx, devices, batch.Options[Extracted]{
		Workers: r.o.Workers, Now: r.o.Now,
		Task: func(ctx context.Context, d device.Device) (Extracted, error) { return r.extract(ctx, d), nil },
	})
	out := make([]Extracted, 0, len(rep.Results))
	for _, res := range rep.Results {
		if res.State == batch.StateSucceeded {
			out = append(out, res.Value)
		}
	}
	return out, err
}

// Check checks every selected device.
func (r *Runner) Check(ctx context.Context, sel device.Selector) (report.Report, error) {
	devices, err := r.Devices(ctx, sel)
	if err != nil {
		return report.Report{}, err
	}
	now := r.o.Now()
	rep, err := batch.Run(ctx, devices, batch.Options[report.Device]{
		Workers: r.o.Workers, Now: r.o.Now,
		Task: func(ctx context.Context, d device.Device) (report.Device, error) {
			return r.check(ctx, d, now), nil
		},
	})
	results := make([]report.Device, 0, len(rep.Results))
	for _, res := range rep.Results {
		if res.State == batch.StateSucceeded {
			results = append(results, res.Value)
		}
	}
	return report.New(now, r.catalog.Metas(), results), err
}

func (r *Runner) extract(ctx context.Context, d device.Device) Extracted {
	out := Extracted{Device: d}
	text, err := r.src.Config(ctx, d)
	if err != nil {
		r.o.Logger.WarnContext(ctx, "read configuration", slog.String("device", d.ID), slog.Any("error", err))
		out.Error = CodeRead
		return out
	}
	x, ok := r.vendors.For(d, text)
	if !ok {
		out.Error = CodeUnsupported
		return out
	}
	out.Vendor = x.Vendor()
	doc, err := config.Parse(ctx, text, x.Dialect(), parse.Limits{})
	if err != nil {
		out.Error = CodeParse
		return out
	}
	ex, err := x.Extract(ctx, d, doc)
	if err != nil {
		out.Error = CodeExtract
		return out
	}
	out.Extraction = ex
	return out
}

func (r *Runner) check(ctx context.Context, d device.Device, now time.Time) report.Device {
	ex := r.extract(ctx, d)
	out := report.Device{Device: d, Vendor: ex.Vendor, Error: ex.Error, Results: []report.Result{}}
	if ex.Error != "" {
		return out
	}
	out.Coverage, out.Issues = ex.Extraction.Coverage, ex.Extraction.Issues
	resolved, err := r.policy.Resolve(d, now, r.catalog.IDs())
	if err != nil {
		r.o.Logger.WarnContext(ctx, "resolve policy", slog.String("device", d.ID), slog.Any("error", err))
		out.Error = CodePolicy
		return out
	}
	out.Layers, out.ExpiredWaivers = resolved.Layers, resolved.Expired
	engine, err := r.engine(resolved.Policy)
	if err != nil {
		r.o.Logger.WarnContext(ctx, "build engine", slog.String("device", d.ID), slog.Any("error", err))
		out.Error = CodePolicy
		return out
	}
	a, err := engine.Run(ctx, ex.Extraction.Posture, ex.Extraction.Coverage)
	if err != nil && !errors.Is(err, context.Canceled) {
		out.Error = CodeCheck
		return out
	}
	out.Rules = a.Rules
	for _, f := range a.Findings {
		res := report.Result{Finding: f}
		if w, ok := resolved.Waiver(f); ok {
			res.Waiver = &report.Waiver{ID: w.ID, Reason: w.Reason, Owner: w.Owner, Expires: w.Expires}
		}
		out.Results = append(out.Results, res)
	}
	return out
}

// engine returns the engine for an effective policy, built once per
// distinct policy: devices of one layer combination share it.
func (r *Runner) engine(p assess.Policy) (*assess.Engine[*baseline.Posture], error) {
	key, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("workflow: policy key: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.engines[string(key)]; ok {
		return e, nil
	}
	e, err := assess.NewEngine(r.catalog, p, assess.Options{Logger: r.o.Logger})
	if err != nil {
		return nil, err
	}
	r.engines[string(key)] = e
	return e, nil
}
