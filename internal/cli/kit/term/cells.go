package term

import "time"

// The cells every table shares (S-9.6), so a person reads one form:

// YesCell is a boolean: "yes", or "-" so the few that say yes stand out.
func YesCell(b bool) string {
	if b {
		return "yes"
	}
	return "-"
}

// TimeCell is a moment: this computer's time with its zone
// (2026-11-07 14:30 WIB), "-" for none.
func TimeCell(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04 MST")
}
