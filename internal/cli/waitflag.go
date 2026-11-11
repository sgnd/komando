package cli

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// waitFlag is a --wait that takes a duration (10s, 5m, 1d) or a bare
// number of seconds, which `svc --wait` took before it took durations.
type waitFlag struct{ d *time.Duration }

func (w waitFlag) String() string {
	if w.d == nil || *w.d == 0 {
		return "0"
	}
	s := w.d.String() // 1h0m0s reads as 1h
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if strings.HasSuffix(s, "h0m") {
		s = s[:len(s)-2]
	}
	return s
}

func (w waitFlag) Set(s string) error {
	d, err := parseWait(s)
	if err != nil {
		return err
	}
	*w.d = d
	return nil
}

func (waitFlag) Type() string { return "duration" }

func parseWait(s string) (time.Duration, error) {
	if n, err := strconv.Atoi(s); err == nil && n >= 0 {
		return time.Duration(n) * time.Second, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		if n, err := strconv.Atoi(days); err == nil && n >= 0 {
			return time.Duration(n) * 24 * time.Hour, nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d >= 0 {
		return d, nil
	}
	return 0, errors.New("give a time like 30s, 10m or 1h (a bare number is seconds)")
}
