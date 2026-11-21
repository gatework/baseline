package survey_test

import (
	"strings"
	"testing"

	"github.com/gatework/netops/assess"
	"github.com/gatework/netops/device"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/policy"
	"github.com/gatework/baseline/survey"
)

func sample(name, region, site string, ntp []string, domain string) survey.Sample {
	p := &baseline.Posture{}
	for _, h := range ntp {
		p.Time.NTP = append(p.Time.NTP, baseline.Server{Host: h, Rank: baseline.RankOrdered})
	}
	if domain != "" {
		p.NAC = baseline.NAC{Dot1x: true, Domains: []string{domain}}
	}
	return survey.Sample{Device: device.Device{Name: name, Site: site, Labels: map[string]string{"region": region}}, Posture: p}
}

func fleet() []survey.Sample {
	std := []string{"10.0.0.18", "10.0.0.19"}
	return []survey.Sample{
		sample("TST2-SW01", "tst", "TST2", std, "tst"),
		sample("TST2-SW02", "tst", "TST2", std, "tst"),
		sample("TST2-SW03", "tst", "TST2", []string{"10.0.0.19", "10.0.0.18"}, "tst"),
		sample("LAB3-SW01", "lab", "LAB3", std, "lab"),
		sample("LAB3-SW02", "lab", "LAB3", std, "lab"),
		sample("DEV9-SW01", "dev", "DEV9", []string{"10.5.0.1"}, ""),
		sample("DEV9-SW02", "dev", "DEV9", []string{"10.5.0.1"}, ""),
	}
}

func TestBuild(t *testing.T) {
	t.Parallel()
	s := survey.Build(fleet(), 0.5)
	g, ok := s.Lookup("ntp.servers", "global")
	if !ok || !g.Reached || g.Consensus != "10.0.0.18 > 10.0.0.19" || g.Values[0].Count != 4 {
		t.Fatalf("global ntp %+v", g)
	}
	tst, _ := s.Lookup("ntp.servers", "region=tst")
	if !tst.Reached || len(tst.Values) != 2 {
		t.Errorf("order is part of the value: %+v", tst)
	}
	d, _ := s.Lookup("nac.domain", "region=dev")
	if d.Reached || d.Absent != 2 {
		t.Errorf("a majority without the setting is no expectation: %+v", d)
	}
}

func TestSurvey_Draft(t *testing.T) {
	t.Parallel()
	body, err := survey.Build(fleet(), 0.5).Draft()
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{"domain: ${region}", "name: region-dev", "- 10.5.0.1"} {
		if !strings.Contains(text, want) {
			t.Errorf("draft lacks %q:\n%s", want, text)
		}
	}
	p, err := policy.Decode(body)
	if err != nil {
		t.Fatalf("draft is not a valid policy: %v\n%s", err, text)
	}
	if err := p.Validate([]assess.RuleID{"ntp.servers", "nac.domain", "aaa.servers", "logging.hosts",
		"snmp.trap_hosts", "clock.timezone"}); err != nil {
		t.Fatal(err)
	}
}
