// Command baseline checks network device configurations against a
// configurable, multi-vendor baseline.
package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/gatework/baseline/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	home, _ := os.UserHomeDir()
	code := cli.Run(ctx, os.Args[1:], cli.Env{
		Stdout: os.Stdout, Stderr: os.Stderr, Environ: environ(), Home: home,
		WriteFile: func(path string, data []byte) error { return os.WriteFile(path, data, 0o600) },
	})
	stop()
	os.Exit(code)
}

func environ() map[string]string {
	out := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			out[k] = v
		}
	}
	return out
}
