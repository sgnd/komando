package cli

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// What `komando facts` and `komando pkg security` both read on a server:
// the OS and its support dates, failed units, whether a reboot is needed
// and which services run old code. One shell fragment and one parser, so
// the two commands give the same answer on the same server.

// osShell prints os=, os_version=, os_pretty= and, on Ubuntu, pro_json=
// (`pro status`, for ESM). It needs $T20 (a timeout prefix, may be empty).
const osShell = `if [ -r /etc/os-release ]; then . /etc/os-release; echo "os=$ID"; echo "os_version=$VERSION_ID"; echo "os_pretty=$PRETTY_NAME"; else echo "os=$(uname -s | tr A-Z a-z)"; fi
if command -v pro >/dev/null 2>&1; then echo "pro_json=$($T20 pro status --format json 2>/dev/null | tr -d '\n')"
elif command -v ua >/dev/null 2>&1; then echo "pro_json=$($T20 ua status --format json 2>/dev/null | tr -d '\n')"
fi
`

// hostStateShell defines hoststate, which prints:
//
//	failed_checked=yes, failed=UNIT   (systemd servers)
//	reboot=yes|no, reboot_pkg=NAME    (no reboot= line: komando cannot tell)
//	restart_checked=yes, svc=UNIT     (services running old code)
//	ksta=N                            (needrestart's kernel state)
//
// It needs $T (a timeout prefix, may be empty), $S (sudo -n or empty) and
// $HS_ROOT (non-empty when commands may run as root). needrestart and
// needs-restarting -s see only part of the processes without root, so they
// run only with it; -r l keeps needrestart from restarting anything.
const hostStateShell = `hoststate() {
  if [ -d /run/systemd/system ]; then echo failed_checked=yes; systemctl list-units --state=failed --no-legend --plain 2>/dev/null | awk '$1 != "" {print "failed="$1}'; fi
  if [ -f /var/run/reboot-required ]; then echo reboot=yes; sed 's/^/reboot_pkg=/' /var/run/reboot-required.pkgs 2>/dev/null | sort -u
  elif command -v dpkg >/dev/null 2>&1; then echo reboot=no
  elif command -v needs-restarting >/dev/null 2>&1; then $T needs-restarting -r >/dev/null 2>&1; case $? in 0) echo reboot=no;; 1) echo reboot=yes;; esac
  fi
  [ -n "$HS_ROOT" ] || return 0
  if command -v needrestart >/dev/null 2>&1; then
    o=$($T $S needrestart -b -r l 2>/dev/null) && { echo restart_checked=yes; printf '%s\n' "$o" | sed -n 's/^NEEDRESTART-SVC: */svc=/p; s/^NEEDRESTART-KSTA: */ksta=/p'; }
  elif command -v needs-restarting >/dev/null 2>&1; then
    o=$($T $S needs-restarting -s 2>/dev/null) && { echo restart_checked=yes; printf '%s\n' "$o" | awk '$1 != "" {print "svc="$1}'; }
  fi
  return 0
}
`

// hostState is what hoststate printed.
type hostState struct {
	FailedChecked  bool
	Failed         []string
	Reboot         *bool // nil: komando cannot tell
	RebootPackages []string
	RestartChecked bool
	NeedRestart    []string
}

// line reads one key=value line of hoststate; false when the key is not
// one of its keys.
func (h *hostState) line(k, v string) bool {
	add := func(s *[]string) {
		if v != "" && !slices.Contains(*s, v) {
			*s = append(*s, v)
		}
	}
	yes, no := true, false
	switch k {
	case "failed_checked":
		h.FailedChecked = true
	case "failed":
		add(&h.Failed)
	case "reboot":
		switch {
		case v == "yes":
			h.Reboot = &yes
		case v == "no" && h.Reboot == nil:
			h.Reboot = &no
		}
	case "reboot_pkg":
		add(&h.RebootPackages)
	case "restart_checked":
		h.RestartChecked = true
	case "svc":
		add(&h.NeedRestart)
	case "ksta":
		if v == "2" || v == "3" { // a newer kernel is installed than the one running
			h.Reboot = &yes
			v = "kernel"
			add(&h.RebootPackages)
		}
	default:
		return false
	}
	return true
}

// supportWarning is the warning for a server whose OS gets no (or maybe
// no) security updates, and whether a count of security updates must be
// shown as unknown: 0 would look safe. name is the OS's name.
func supportWarning(name string, sup osSupport, now time.Time) (warning string, unknownCount bool) {
	switch {
	case sup.Status == "unsupported":
		msg := name + " gets no security updates any more"
		switch {
		case sup.ExtendedUntil != nil && now.UTC().Format("2006-01-02") <= *sup.ExtendedUntil:
			msg = fmt.Sprintf("%s: standard support ended %s and Ubuntu Pro (ESM) is not enabled, so it gets no security updates", name, *sup.StandardUntil)
		case sup.StandardUntil != nil:
			last := *sup.StandardUntil
			if sup.ExtendedUntil != nil {
				last = *sup.ExtendedUntil
			}
			msg = fmt.Sprintf("%s reached end of life on %s and gets no security updates", name, last)
		}
		return msg, true
	case sup.Status == "unknown" && sup.PastStandard != nil && *sup.PastStandard:
		return fmt.Sprintf("%s: standard support ended %s and komando cannot tell whether Ubuntu Pro (ESM) is enabled (`pro status` was not readable), so it may get no security updates", name, *sup.StandardUntil), true
	case sup.Status == "unknown":
		return fmt.Sprintf("komando does not know the support dates of %s; check that it still gets security updates", name), false
	}
	return "", false
}

// osName is how a warning names the OS: its pretty name, else ID and
// version.
func osName(id, version, pretty string) string {
	if n := strings.TrimSpace(pretty); n != "" {
		return n
	}
	return strings.TrimSpace(id + " " + version)
}

// osSupportFrom judges OS support from osShell's values.
func osSupportFrom(id, version, pretty string, proJSON *string, now time.Time) osSupport {
	var esm *bool
	if id == "ubuntu" && proJSON != nil {
		esm = parseProESM(*proJSON)
	}
	return supportOf(id, version, pretty, esm, now)
}
