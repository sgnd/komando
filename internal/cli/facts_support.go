package cli

import (
	"strings"
	"time"
)

// OS support dates for `komando facts`.
//
// These dates come from the vendors' own release pages, checked on
// osTableChecked:
//
//   - Ubuntu: https://ubuntu.com/about/release-cycle (standard support, then
//     ESM with Ubuntu Pro; Canonical gives months, the table uses the last
//     day of that month)
//   - Debian: https://wiki.debian.org/DebianReleases and
//     https://wiki.debian.org/LTS (security team, then Debian LTS, which
//     every server gets without a subscription)
//   - RHEL, Rocky, AlmaLinux, Oracle Linux, CentOS:
//     https://access.redhat.com/support/policy/updates/errata and each
//     project's release page (end of maintenance support)
//   - Alpine: https://alpinelinux.org/releases/
//   - Amazon Linux: https://aws.amazon.com/amazon-linux-2/faqs/ and
//     https://docs.aws.amazon.com/linux/al2023/ug/release-cadence.html
//   - Windows Server: https://learn.microsoft.com/lifecycle/products/
//     (end of extended support, which still brings security updates; for
//     2012 and 2012 R2 the paid Extended Security Updates). Keyed by build.
//
// They need updating: add each new release, and check the table when a
// vendor moves a date (https://endoflife.date collects them all). A
// release that is not here is reported as "unknown", never as supported.
const osTableChecked = "2026-11-05"

// osLife is one release's support window, as YYYY-MM-DD dates.
type osLife struct {
	standard string // last day of standard security support
	extended string // last day of extended support ("" = none)
	by       string // who gives the extended support
	auto     bool   // extended support needs no subscription (Debian LTS)
}

var osTable = map[string]map[string]osLife{
	"ubuntu": {
		"14.04": {"2019-04-30", "2024-04-30", "ubuntu-pro-esm", false},
		"16.04": {"2021-04-30", "2026-04-30", "ubuntu-pro-esm", false},
		"18.04": {"2023-05-31", "2028-04-30", "ubuntu-pro-esm", false},
		"20.04": {"2025-05-31", "2030-04-30", "ubuntu-pro-esm", false},
		"22.04": {"2027-06-30", "2032-04-30", "ubuntu-pro-esm", false},
		"24.04": {"2029-05-31", "2034-04-30", "ubuntu-pro-esm", false},
		"26.04": {"2031-05-31", "2036-04-30", "ubuntu-pro-esm", false},
	},
	"debian": {
		"9":  {"2020-07-06", "2022-06-30", "debian-lts", true},
		"10": {"2022-09-10", "2024-06-30", "debian-lts", true},
		"11": {"2024-08-14", "2026-08-31", "debian-lts", true},
		"12": {"2026-06-10", "2028-06-30", "debian-lts", true},
		"13": {"2028-08-09", "2030-06-30", "debian-lts", true},
	},
	"rhel":      rhelFamily(nil),
	"rocky":     rhelFamily(nil),
	"almalinux": rhelFamily(map[string]osLife{"8": {standard: "2029-03-01"}}),
	"ol":        rhelFamily(nil),
	"centos": { // CentOS Linux; CentOS Stream is centosStream
		"7": {standard: "2024-06-30"},
		"8": {standard: "2021-12-31"},
	},
	"alpine": {
		"3.16": {standard: "2024-05-23"},
		"3.17": {standard: "2024-11-22"},
		"3.18": {standard: "2025-05-09"},
		"3.19": {standard: "2025-11-01"},
		"3.20": {standard: "2026-04-01"},
		"3.21": {standard: "2026-11-01"},
		"3.22": {standard: "2027-05-01"},
		"3.23": {standard: "2027-11-01"},
	},
	"amzn": {
		"2":    {standard: "2026-06-30"},
		"2023": {standard: "2029-06-30"},
	},
	"windows-server": {
		"9200":  {"2023-10-10", "2026-10-13", "microsoft-esu", false}, // 2012
		"9600":  {"2023-10-10", "2026-10-13", "microsoft-esu", false}, // 2012 R2
		"14393": {standard: "2027-01-12"},                             // 2016
		"17763": {standard: "2029-01-09"},                             // 2019
		"20348": {standard: "2031-10-14"},                             // 2022
		"26100": {standard: "2034-11-14"},                             // 2025
	},
}

var centosStream = map[string]osLife{
	"8":  {standard: "2024-05-31"},
	"9":  {standard: "2027-05-31"},
	"10": {standard: "2030-01-01"},
}

func rhelFamily(over map[string]osLife) map[string]osLife {
	m := map[string]osLife{
		"7":  {standard: "2024-06-30"},
		"8":  {standard: "2029-05-31"},
		"9":  {standard: "2032-05-31"},
		"10": {standard: "2035-05-31"},
	}
	for k, v := range over {
		m[k] = v
	}
	return m
}

// osSupport says whether a server's OS still gets security updates.
//
// status is one of:
//   - supported: in standard security support
//   - extended: past standard support, still patched (Ubuntu Pro ESM is
//     enabled, or Debian LTS)
//   - unsupported: no security updates any more
//   - unknown: komando cannot tell (a release not in its table, or an
//     Ubuntu server past standard support whose ESM state is unreadable)
type osSupport struct {
	Status        string  `json:"status"`
	StandardUntil *string `json:"standard_support_until"`
	ExtendedUntil *string `json:"extended_support_until"`
	ExtendedBy    string  `json:"extended_by,omitempty"` // ubuntu-pro-esm, debian-lts
	PastStandard  *bool   `json:"past_standard_support"`
	ESMEnabled    *bool   `json:"esm_enabled"` // Ubuntu only; null elsewhere or when unreadable
	TableChecked  string  `json:"dates_checked"`
}

// releaseKey is the part of VERSION_ID the table uses: "3.20" of Alpine
// "3.20.3", "8" of Rocky "8.10".
func releaseKey(id, version string) string {
	switch id {
	case "ubuntu", "amzn":
		return version
	case "alpine":
		p := strings.Split(version, ".")
		if len(p) >= 2 {
			return p[0] + "." + p[1]
		}
		return version
	}
	v, _, _ := strings.Cut(version, ".")
	return v
}

// lookupOS finds a release's support window.
func lookupOS(id, version, pretty string) (osLife, bool) {
	key := releaseKey(id, version)
	if id == "centos" && strings.Contains(strings.ToLower(pretty), "stream") {
		l, ok := centosStream[key]
		return l, ok
	}
	l, ok := osTable[id][key]
	return l, ok
}

// supportOf works out the support status on day now. esm is whether
// Ubuntu Pro ESM (esm-infra) is enabled, nil when unknown.
func supportOf(id, version, pretty string, esm *bool, now time.Time) osSupport {
	s := osSupport{Status: "unknown", TableChecked: osTableChecked}
	if id == "ubuntu" {
		s.ESMEnabled = esm
	}
	l, ok := lookupOS(id, version, pretty)
	if !ok {
		return s
	}
	today := now.UTC().Format("2006-01-02")
	std := l.standard
	s.StandardUntil = &std
	if l.extended != "" {
		ext := l.extended
		s.ExtendedUntil, s.ExtendedBy = &ext, l.by
	}
	past := today > l.standard
	s.PastStandard = &past
	switch {
	case !past:
		s.Status = "supported"
	case l.extended == "" || today > l.extended:
		s.Status = "unsupported"
	case l.auto:
		s.Status = "extended"
	case esm == nil:
		s.Status = "unknown"
	case *esm:
		s.Status = "extended"
	default:
		s.Status = "unsupported"
	}
	return s
}
