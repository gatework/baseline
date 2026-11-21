package bootstrap_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gatework/baseline/internal/bootstrap"
)

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, body string
		// want returns the expected source and policy path for a home.
		want     func(home string) (source, policy string)
		inline   bool
		policyOK bool
	}{
		{"policy path relative to the file", "source: ~/backups\npolicy: policy.yml\n",
			func(h string) (string, string) {
				return filepath.Join(h, "backups"), filepath.Join(h, ".gatework", "policy.yml")
			}, false, false},
		{"inline policy", "source: /data/b\npolicy:\n  layers:\n    - name: default\n      disable: [ntp.auth]\n",
			func(string) (string, string) { return "/data/b", "" }, true, true},
		{"no policy", "source: b\n",
			func(h string) (string, string) { return filepath.Join(h, ".gatework", "b"), "" }, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			write(t, filepath.Join(home, ".gatework", "baseline.yml"), tt.body)
			path := bootstrap.Discover("", map[string]string{}, home)
			if path != filepath.Join(home, ".gatework", "baseline.yml") {
				t.Fatalf("discovered %q", path)
			}
			c, err := bootstrap.Load(t.Context(), path, home)
			if err != nil {
				t.Fatal(err)
			}
			source, policy := tt.want(home)
			if c.Source != source || c.Policy.Path != policy || (c.Policy.Inline != nil) != tt.inline {
				t.Errorf("config %+v", c)
			}
			if tt.policyOK {
				if _, err := bootstrap.LoadPolicy(c.Policy); err != nil {
					t.Errorf("policy: %v", err)
				}
			}
		})
	}
}

func TestLoad_rejectsUnknownKeys(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "baseline.yml")
	write(t, path, "sorce: x\n")
	if _, err := bootstrap.Load(t.Context(), path, ""); err == nil {
		t.Fatal("typo accepted")
	}
}

func TestLoad_example(t *testing.T) {
	t.Parallel()
	c, err := bootstrap.Load(t.Context(), filepath.Join("..", "..", "examples", "baseline.yml"), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pol, err := bootstrap.LoadPolicy(c.Policy)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := bootstrap.Catalog(pol)
	if err != nil {
		t.Fatal(err)
	}
	if err := pol.Validate(cat.IDs()); err != nil {
		t.Fatal(err)
	}
}
