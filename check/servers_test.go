package check_test

import (
	"fmt"
	"testing"

	"github.com/gatework/baseline/check"
)

func TestServerSpec_Compare(t *testing.T) {
	t.Parallel()
	want := []string{"10.0.0.1", "10.0.0.2"}
	tests := []struct {
		name   string
		spec   check.ServerSpec
		actual []string
		kinds  []check.ProblemKind
	}{
		{"strict match", check.ServerSpec{Expected: want, Order: check.OrderStrict}, want, nil},
		{"strict reversed", check.ServerSpec{Expected: want, Order: check.OrderStrict}, []string{"10.0.0.2", "10.0.0.1"}, []check.ProblemKind{check.ProblemOrder}},
		{"primary reversed", check.ServerSpec{Expected: want, Order: check.OrderPrimary}, []string{"10.0.0.2", "10.0.0.1"}, []check.ProblemKind{check.ProblemOrder}},
		{"primary extra secondary", check.ServerSpec{Expected: want, Order: check.OrderPrimary}, []string{"10.0.0.1", "10.9.9.9", "10.0.0.2"}, nil},
		{"any reversed", check.ServerSpec{Expected: want, Order: check.OrderAny}, []string{"10.0.0.2", "10.0.0.1"}, nil},
		{"strict ignores extras between", check.ServerSpec{Expected: want, Order: check.OrderStrict}, []string{"10.0.0.1", "x", "10.0.0.2"}, nil},
		{"exclusive extra", check.ServerSpec{Expected: want, Order: check.OrderAny, Exclusive: true}, []string{"10.0.0.1", "10.0.0.2", "x"}, []check.ProblemKind{check.ProblemUnexpected}},
		{"missing skips order", check.ServerSpec{Expected: want, Order: check.OrderStrict}, []string{"10.0.0.2"}, []check.ProblemKind{check.ProblemMissing}},
		{"too few", check.ServerSpec{Order: check.OrderAny, Min: 2}, []string{"x"}, []check.ProblemKind{check.ProblemTooFew}},
		{"case insensitive", check.ServerSpec{Expected: []string{"NTP.Example"}, Order: check.OrderStrict}, []string{"ntp.example"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.spec.Compare(tt.actual)
			if len(got) != len(tt.kinds) {
				t.Fatalf("got %+v, want kinds %v", got, tt.kinds)
			}
			for i, p := range got {
				if p.Kind != tt.kinds[i] {
					t.Errorf("problem %d: got %s, want %s", i, p.Kind, tt.kinds[i])
				}
			}
		})
	}
}

func ExampleServerSpec_Compare() {
	spec := check.ServerSpec{Expected: []string{"10.0.0.18", "10.0.0.19"}, Order: check.OrderStrict, Min: 2}
	for _, p := range spec.Compare([]string{"10.0.0.19", "10.0.0.18"}) {
		fmt.Println(p.Kind, p.Hosts)
	}
	// Output: order [10.0.0.19 10.0.0.18]
}
