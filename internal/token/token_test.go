package token_test

import (
	"slices"
	"testing"

	"github.com/gatework/netops/config"
	"github.com/gatework/netops/parse"

	"github.com/gatework/baseline/internal/token"
)

func TestSplit(t *testing.T) {
	t.Parallel()
	got := token.Split(`logging syslog "10.0.0.1" vrouter "mgt vr" udp 514`)
	want := token.Words{"logging", "syslog", "10.0.0.1", "vrouter", "mgt vr", "udp", "514"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
	if got.Int("udp") != 514 || got.At(99) != "" {
		t.Error("accessors")
	}
}

func TestKeyword(t *testing.T) {
	t.Parallel()
	d := config.Comware()
	tests := []struct {
		node *parse.Node
		want string
	}{
		{&parse.Node{Text: "ntp-service frobnicate fast", Depth: 0}, "ntp-service frobnicate"},
		{&parse.Node{Text: "bogus-option secret", Depth: 1}, "bogus-option"},
		{&parse.Node{Text: "snmp-agent community read public", Depth: 0}, "snmp-agent"},
		{&parse.Node{Text: "info-center 10.0.0.1", Depth: 0}, "info-center"},
	}
	for _, tt := range tests {
		if got := token.Keyword(tt.node, d); got != tt.want {
			t.Errorf("%q: got %q, want %q", tt.node.Text, got, tt.want)
		}
	}
}
