package inventory_test

import (
	"testing"

	"github.com/gatework/netops/device"

	"github.com/gatework/baseline/internal/inventory"
)

func TestNaming_Classify(t *testing.T) {
	t.Parallel()
	n, err := inventory.NewNaming(inventory.DefaultPattern, map[string]string{"sw": "access", "lef": "leaf"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, site, role, region, area string
	}{
		{"LAB3-10-SW01", "LAB3", "access", "lab", "10"},
		{"TST2-LEF01", "TST2", "leaf", "tst", ""},
		{"LAB3-19-ENG-ASW01", "LAB3", "asw", "lab", "19-eng"},
		{"DEV8-CSW01.example.com", "DEV8", "csw", "dev", ""},
		{"HUZ4-AC", "HUZ4", "ac", "huz", ""},
		{"Switch", "", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := n.Classify(device.Device{Name: tt.name})
			if d.Site != tt.site || d.Role != tt.role || d.Labels["region"] != tt.region || d.Labels["area"] != tt.area {
				t.Errorf("got site=%q role=%q labels=%v", d.Site, d.Role, d.Labels)
			}
		})
	}
}
