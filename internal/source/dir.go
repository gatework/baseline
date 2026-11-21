package source

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/gatework/netops/device"
)

// maxConfig bounds one configuration file.
const maxConfig = 64 << 20

// fileName matches "<name>-<IPv4>.txt", the backup file convention.
var fileName = regexp.MustCompile(`^(.+)-(\d+\.\d+\.\d+\.\d+)\.txt$`)

// ErrNoConfigs reports a directory without configurations.
var ErrNoConfigs = errors.New("source: no configurations found")

// item is one configuration file.
type item struct {
	Device device.Device
	File   string // path relative to the directory
}

// Dir is a backup directory. Devices must be called before Config; each
// call rescans the directory. It is safe for concurrent use.
type Dir struct {
	root string

	mu    sync.Mutex        // guards files
	files map[string]string // device ID to file, from the last Devices call
}

// NewDir returns the backup directory at root.
func NewDir(root string) *Dir { return &Dir{root: root, files: map[string]string{}} }

// Devices lists the devices that have a configuration.
func (d *Dir) Devices(ctx context.Context) ([]device.Device, error) {
	items, err := d.items(ctx)
	if err != nil {
		return nil, err
	}
	files := make(map[string]string, len(items))
	out := make([]device.Device, 0, len(items))
	for _, it := range items {
		if _, dup := files[it.Device.ID]; dup {
			continue
		}
		files[it.Device.ID] = it.File
		out = append(out, it.Device)
	}
	d.mu.Lock()
	d.files = files
	d.mu.Unlock()
	return out, nil
}

// Config returns the configuration text of dev.
func (d *Dir) Config(ctx context.Context, dev device.Device) (string, error) {
	d.mu.Lock()
	file, ok := d.files[dev.ID]
	d.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("source: no configuration for %s", dev.ID)
	}
	return d.read(ctx, item{Device: dev, File: file})
}

// manifest is the subset of plan.json this package reads.
type manifest struct {
	Selected []struct {
		Host   string `json:"host"`
		Name   string `json:"name"`
		Vendor string `json:"vendor"`
		File   string `json:"backup_filename"`
	} `json:"selected"`
}

// items lists the configurations: from plan.json when present, otherwise
// every "<name>-<ip>.txt" file with an empty vendor, to be detected from
// the content. Entries whose file is missing are skipped.
func (d *Dir) items(ctx context.Context) ([]item, error) {
	body, err := os.ReadFile(filepath.Join(d.root, "plan.json"))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return d.scan(ctx)
	case err != nil:
		return nil, fmt.Errorf("source: %w", err)
	}
	var m manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("source: plan.json: %w", err)
	}
	var out []item
	for _, s := range m.Selected {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		addr, err := netip.ParseAddr(s.Host)
		if err != nil || s.File == "" || strings.ContainsAny(s.File, `/\`) {
			continue
		}
		if _, err := os.Stat(filepath.Join(d.root, s.File)); err != nil {
			continue
		}
		dev := device.Device{ID: addr.String(), Name: s.Name, Mgmt: addr, Vendor: s.Vendor}
		out = append(out, item{Device: dev.Normalize(), File: s.File})
	}
	if len(out) == 0 {
		return nil, ErrNoConfigs
	}
	return out, nil
}

func (d *Dir) scan(ctx context.Context) ([]item, error) {
	entries, err := os.ReadDir(d.root)
	if err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}
	var out []item
	for _, e := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		m := fileName.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		addr, err := netip.ParseAddr(m[2])
		if err != nil {
			continue
		}
		dev := device.Device{ID: addr.String(), Name: m[1], Mgmt: addr}
		out = append(out, item{Device: dev.Normalize(), File: e.Name()})
	}
	if len(out) == 0 {
		return nil, ErrNoConfigs
	}
	slices.SortFunc(out, func(a, b item) int { return device.Compare(a.Device, b.Device) })
	return out, nil
}

// read returns the configuration text of it.
func (d *Dir) read(_ context.Context, it item) (string, error) {
	f, err := os.Open(filepath.Join(d.root, it.File))
	if err != nil {
		return "", fmt.Errorf("source: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxConfig+1))
	if err != nil {
		return "", fmt.Errorf("source: %w", err)
	}
	if len(b) > maxConfig {
		return "", fmt.Errorf("source: %s exceeds %d bytes", it.File, maxConfig)
	}
	return string(b), nil
}
