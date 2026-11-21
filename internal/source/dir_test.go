package source_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gatework/baseline/internal/source"
)

func TestDir(t *testing.T) {
	t.Parallel()
	d := source.NewDir("../../testdata/backup")
	devices, err := d.Devices(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 3 {
		t.Fatalf("devices %d: entries with missing files are skipped", len(devices))
	}
	again, err := d.Devices(t.Context())
	if err != nil || len(again) != 3 {
		t.Fatalf("second scan: %d %v", len(again), err)
	}
	text, err := d.Config(t.Context(), devices[0])
	if err != nil || !strings.Contains(text, "sysname LAB1-10-SW01") {
		t.Fatalf("config: %v", err)
	}
}

func TestDir_scanWithoutManifest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "A-B-SW01-192.0.2.7.txt"), []byte("#\n sysname A\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	devices, err := source.NewDir(dir).Devices(t.Context())
	if err != nil || len(devices) != 1 || devices[0].Name != "A-B-SW01" || devices[0].Vendor != "" {
		t.Fatalf("devices %+v %v", devices, err)
	}
	if _, err := source.NewDir(t.TempDir()).Devices(t.Context()); !errors.Is(err, source.ErrNoConfigs) {
		t.Errorf("empty dir: %v", err)
	}
}
