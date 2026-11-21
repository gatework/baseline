package tz_test

import (
	"testing"
	"time"

	"github.com/gatework/baseline/internal/tz"
)

func TestOffsets(t *testing.T) {
	t.Parallel()
	eight := 8 * time.Hour
	tests := []struct {
		name string
		got  func() (time.Duration, bool)
		want time.Duration
		ok   bool
	}{
		{"comware add", func() (time.Duration, bool) { return tz.Signed("add", "08:00:00") }, eight, true},
		{"comware minus", func() (time.Duration, bool) { return tz.Signed("minus", "05:30") }, -(5*time.Hour + 30*time.Minute), true},
		{"comware bad", func() (time.Duration, bool) { return tz.Signed("add", "25:00") }, 0, false},
		{"cisco hours", func() (time.Duration, bool) { return tz.Hours("8", "0") }, eight, true},
		{"cisco negative", func() (time.Duration, bool) { return tz.Hours("-3", "30") }, -(3*time.Hour + 30*time.Minute), true},
		{"named", func() (time.Duration, bool) { return tz.Named("Asia/Chongqing") }, eight, true},
		{"format round trip", func() (time.Duration, bool) { return tz.ParseFormat(tz.Format(-eight)) }, -eight, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := tt.got()
			if got != tt.want || ok != tt.ok {
				t.Errorf("got %v %v", got, ok)
			}
		})
	}
}
