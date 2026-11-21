package tz

import (
	"strconv"
	"strings"
	"time"
)

// named maps IANA zone names seen on devices to their standard offsets.
// Only zones without daylight saving are listed: a fixed offset is what a
// baseline can compare.
var named = map[string]time.Duration{
	"utc": 0, "gmt": 0, "etc/utc": 0, "prc": 8 * time.Hour,
	"asia/shanghai": 8 * time.Hour, "asia/chongqing": 8 * time.Hour, "asia/chungking": 8 * time.Hour,
	"asia/hong_kong": 8 * time.Hour, "asia/taipei": 8 * time.Hour, "asia/singapore": 8 * time.Hour,
	"asia/kolkata": 5*time.Hour + 30*time.Minute, "asia/calcutta": 5*time.Hour + 30*time.Minute,
	"asia/dubai": 4 * time.Hour, "asia/tokyo": 9 * time.Hour, "asia/seoul": 9 * time.Hour,
	"asia/karachi": 5 * time.Hour, "asia/dhaka": 6 * time.Hour, "asia/bangkok": 7 * time.Hour,
	"asia/jakarta": 7 * time.Hour, "africa/lagos": time.Hour, "africa/nairobi": 3 * time.Hour,
}

// Signed decodes Comware "add|minus HH[:MM[:SS]]".
func Signed(direction, hms string) (time.Duration, bool) {
	d, ok := clock(hms)
	switch {
	case !ok:
		return 0, false
	case direction == "add":
		return d, true
	case direction == "minus":
		return -d, true
	}
	return 0, false
}

// Hours decodes Cisco "H [M]" where H may be negative.
func Hours(hours, minutes string) (time.Duration, bool) {
	h, err := strconv.Atoi(hours)
	if err != nil || h < -14 || h > 14 {
		return 0, false
	}
	m := 0
	if minutes != "" {
		if m, err = strconv.Atoi(minutes); err != nil || m < 0 || m >= 60 {
			return 0, false
		}
	}
	d := time.Duration(h)*time.Hour + time.Duration(m)*time.Minute
	if strings.HasPrefix(hours, "-") {
		d = time.Duration(h)*time.Hour - time.Duration(m)*time.Minute
	}
	return d, true
}

// Named returns the offset of a fixed-offset IANA zone.
func Named(name string) (time.Duration, bool) {
	d, ok := named[strings.ToLower(name)]
	return d, ok
}

// Format renders an offset as "+08:00".
func Format(d time.Duration) string {
	sign := "+"
	if d < 0 {
		sign, d = "-", -d
	}
	return sign + pad(int(d/time.Hour)) + ":" + pad(int(d%time.Hour/time.Minute))
}

// ParseFormat parses the Format form.
func ParseFormat(s string) (time.Duration, bool) {
	if len(s) < 2 || (s[0] != '+' && s[0] != '-') {
		return 0, false
	}
	d, ok := clock(s[1:])
	if !ok {
		return 0, false
	}
	if s[0] == '-' {
		d = -d
	}
	return d, true
}

func clock(hms string) (time.Duration, bool) {
	parts := strings.Split(hms, ":")
	if len(parts) == 0 || len(parts) > 3 {
		return 0, false
	}
	units := []time.Duration{time.Hour, time.Minute, time.Second}
	var d time.Duration
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || (i == 0 && n > 14) || (i > 0 && n >= 60) {
			return 0, false
		}
		d += time.Duration(n) * units[i]
	}
	return d, true
}

func pad(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}
