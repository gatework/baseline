package baseline_test

import (
	"slices"
	"testing"

	"github.com/gatework/netops/evidence"

	"github.com/gatework/baseline"
)

func TestHosts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		servers []baseline.Server
		want    []string
	}{
		{"configured order", []baseline.Server{{Host: "b", Rank: baseline.RankOrdered}, {Host: "a", Rank: baseline.RankOrdered}}, []string{"b", "a"}},
		{"primary first", []baseline.Server{{Host: "s", Rank: baseline.RankSecondary}, {Host: "p", Rank: baseline.RankPrimary}}, []string{"p", "s"}},
		{"preferred before ordered", []baseline.Server{{Host: "o", Rank: baseline.RankOrdered}, {Host: "p", Rank: baseline.RankPrimary}}, []string{"p", "o"}},
		{"deduplicated", []baseline.Server{{Host: "a", Function: "authentication"}, {Host: "a", Function: "accounting"}}, []string{"a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := baseline.Hosts(tt.servers); !slices.Equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLine_Usable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		line baseline.Line
		want bool
	}{
		{"password without password", baseline.Line{Kind: baseline.LineVTY, Auth: baseline.LineAuthPassword, Protocols: []string{"ssh"}}, false},
		{"vty without protocol", baseline.Line{Kind: baseline.LineVTY, Auth: baseline.LineAuthAAA, Protocols: []string{}}, false},
		{"aaa vty", baseline.Line{Kind: baseline.LineVTY, Auth: baseline.LineAuthAAA, Protocols: []string{"ssh"}}, true},
		{"console", baseline.Line{Kind: baseline.LineConsole, Auth: baseline.LineAuthNone}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.line.Usable(); got != tt.want {
				t.Errorf("got %v", got)
			}
		})
	}
}

func TestAccount_CanLogin(t *testing.T) {
	t.Parallel()
	if !(baseline.Account{}).CanLogin() || (baseline.Account{Services: []string{}}).CanLogin() {
		t.Fatal("nil means any, empty means none")
	}
}

func TestTally_Result(t *testing.T) {
	t.Parallel()
	tl := baseline.NewTally("d1", "comware", baseline.FacetNTP, baseline.FacetLine)
	tl.Unrecognized(baseline.FacetLine, 7, "line")
	ex := tl.Result(&baseline.Posture{})
	want := map[evidence.Dimension]evidence.Status{
		baseline.FacetNTP: evidence.StatusComplete, baseline.FacetLine: evidence.StatusPartial,
		baseline.FacetNAC: evidence.StatusUnsupported, baseline.DialectFacet("comware"): evidence.StatusComplete,
	}
	for d, s := range want {
		if got := ex.Coverage.Status(d); got != s {
			t.Errorf("%s: got %s, want %s", d, got, s)
		}
	}
	if len(ex.Issues) != 1 || ex.Issues[0].Source.Line != 7 {
		t.Errorf("issues %+v", ex.Issues)
	}
}
