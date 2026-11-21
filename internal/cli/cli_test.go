package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gatework/baseline/internal/cli"
)

const fixtures = "../../testdata/backup"

func run(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := cli.Run(t.Context(), args, cli.Env{
		Stdout: &out, Stderr: &errOut, Now: func() time.Time { return time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC) },
		WriteFile: func(path string, data []byte) error { return os.WriteFile(path, data, 0o600) },
	})
	return code, out.String() + errOut.String()
}

func TestRun_check(t *testing.T) {
	t.Parallel()
	code, out := run(t, "check", "-c", "", "-s", fixtures, "--fail-on", "high")
	if code != cli.ExitFindings {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, want := range []string{"service.telnet", "snmp.default_community", "LAB1-10-SW01"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
}

func TestRun_checkJSON(t *testing.T) {
	t.Parallel()
	code, out := run(t, "check", "-c", "", "-s", fixtures, "-f", "json", "--select", "vendor=cisco_nxos")
	if code != cli.ExitOK {
		t.Fatalf("exit %d\n%s", code, out)
	}
	var rep struct {
		Devices []struct {
			Device struct{ Name string } `json:"device"`
		} `json:"devices"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil || len(rep.Devices) != 1 || rep.Devices[0].Device.Name != "LAB2-LEF01" {
		t.Fatalf("report %+v %v", rep, err)
	}
	if strings.Contains(out, "EXAMPLEONLY") {
		t.Error("report leaks a secret")
	}
}

func TestRun_waiverAndPolicy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yml")
	body := `layers:
  - name: default
    disable: ["text.*", "snmp.*", "nac.*", "iface.*", "ntp.*", "line.*", "aaa.*", "account.*", "logging.*", "clock.*", "service.ssh_acl", "service.http"]
waivers:
  - {id: W-1, scope: ["LAB1-*"], checks: ["service.telnet"], reason: lab, owner: ops, expires: 2027-01-01}
`
	if err := os.WriteFile(pol, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := run(t, "check", "-c", "", "-s", fixtures, "-p", pol, "--fail-on", "low")
	if code != cli.ExitOK || !strings.Contains(out, "已豁免 1 项") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestRun_surveyAndCoverage(t *testing.T) {
	t.Parallel()
	draft := filepath.Join(t.TempDir(), "draft.yml")
	if code, out := run(t, "survey", "-c", "", "-s", fixtures, "--draft", draft); code != cli.ExitOK {
		t.Fatalf("survey exit %d\n%s", code, out)
	}
	if code, out := run(t, "check", "-c", "", "-s", fixtures, "-p", draft); code != cli.ExitOK {
		t.Fatalf("draft policy rejected: %d\n%s", code, out)
	}
	code, out := run(t, "coverage", "-c", "", "-s", fixtures)
	if code != cli.ExitOK || !strings.Contains(out, "panos") {
		t.Fatalf("coverage exit %d\n%s", code, out)
	}
}

func TestRun_explain(t *testing.T) {
	t.Parallel()
	code, out := run(t, "explain", "ntp.servers", "-c", "", "-s", fixtures, "--device", "LAB1-10-SW01")
	if code != cli.ExitOK || !strings.Contains(out, "order") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if code, _ := run(t, "explain", "no.such", "-c", ""); code != cli.ExitError {
		t.Errorf("unknown check exit %d", code)
	}
}

func TestRun_helpIsChinese(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"--help"}, {"check", "--help"}, {"survey", "-h"}, {"help", "explain"}} {
		code, out := run(t, args...)
		if code != cli.ExitOK {
			t.Fatalf("%v: exit %d", args, code)
		}
		for _, english := range []string{"Usage:", "Flags:", "Available Commands", "(default", " string ", " int ", "help for", "completion"} {
			if strings.Contains(out, english) {
				t.Errorf("%v: help contains %q:\n%s", args, english, out)
			}
		}
	}
	if code, out := run(t, "check", "--bogus"); code != cli.ExitError || !strings.Contains(out, "未知参数 --bogus") {
		t.Errorf("usage error: %d %s", code, out)
	}
}
