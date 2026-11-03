package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// ------------------------------------------------------------------ svc ---

// svcResult reads `systemctl show` output into units and fails the host
// when systemd is not running or a unit does not exist.
func svcResult(rr *sshx.RunResult) ([]map[string]any, *out.Error) {
	if marker(rr.Stdout) == "no-systemd" {
		return nil, errNoSystemd()
	}
	v, _ := parseSvcShow(nil, rr.Stdout)
	units, _ := v.([]map[string]any)
	var missing []string
	for _, u := range units {
		if u["load_state"] == "not-found" {
			missing = append(missing, fmt.Sprint(u["id"]))
		}
	}
	if len(missing) > 0 {
		return units, out.Errf(out.ExitNotFound, "UNIT_NOT_FOUND", "check the name with `komando svc list TARGET`",
			"unit not found: %s", strings.Join(missing, ", "))
	}
	return units, nil
}

func svcTable(data any) string {
	units, _ := data.([]map[string]any)
	rows := [][]string{}
	for _, u := range units {
		mem := ""
		if n, ok := u["memory_current"].(int64); ok && n >= 0 {
			mem = humanBytes(n)
		}
		since := ""
		if t, ok := u["active_enter_timestamp"].(string); ok && u["active_state"] == "active" {
			since = t
		}
		rows = append(rows, []string{cell(u["id"]), cell(u["active_state"]), cell(u["sub_state"]), cell(u["unit_file_state"]),
			cell(u["main_pid"]), cell(u["n_restarts"]), mem, since})
	}
	return textTable([]string{"unit", "active", "sub", "enabled", "pid", "restarts", "memory", "since"}, rows)
}

func cell(v any) string {
	if v == nil {
		return ""
	}
	if n, ok := v.(int64); ok && n == 0 {
		return "0"
	}
	return fmt.Sprint(v)
}

func svcStatus(ctx context.Context, target string, units []string) error {
	command := noSystemd + "systemctl show --no-pager -p " + strings.Join(svcProps, ",") + " -- " + quoteAll(units)
	return runOps(ctx, opsSpec{name: "svc.status", target: target, command: command, display: "svc status " + strings.Join(units, " "),
		parse: func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) {
			u, err := svcResult(rr)
			return u, err
		}, text: svcTable})
}

// svcScript builds the action script: run systemctl, optionally wait for
// the units to become active, then show their state like `svc status`.
func svcScript(action string, units []string, now bool, wait int) string {
	q := quoteAll(units)
	var sb strings.Builder
	sb.WriteString(noSystemd)
	flag := ""
	if now && (action == "enable" || action == "disable") {
		flag = " --now"
	}
	sb.WriteString("systemctl " + action + flag + " -- " + q + " >&2; rc=$?\n")
	starts := action == "start" || action == "restart" || action == "reload"
	switch {
	case starts && wait > 0:
		fmt.Fprintf(&sb, "i=0; while [ $rc -eq 0 ] && [ $i -lt %d ]; do ok=1; for u in %s; do systemctl is-active --quiet -- \"$u\" || ok=0; done; [ $ok = 1 ] && break; sleep 1; i=$((i+1)); done\n", wait, q)
	case starts:
		sb.WriteString("sleep 1\n") // a unit that dies right away shows as failed
	}
	sb.WriteString("systemctl show --no-pager -p " + strings.Join(svcProps, ",") + " -- " + q + "\n")
	if starts {
		unitFlags := make([]string, 0, len(units))
		for _, u := range units {
			unitFlags = append(unitFlags, "-u "+sshx.Q(u))
		}
		// the reason a start failed, on stderr
		sb.WriteString("if [ $rc -ne 0 ]; then journalctl -n 20 --no-pager -o cat " + strings.Join(unitFlags, " ") + " >&2 2>/dev/null; fi\n")
	}
	sb.WriteString("echo \"#komando:rc=$rc\"; exit 0")
	return sb.String()
}

// svcActionResult reads the action script's output.
func svcActionResult(action string, wait int, rr *sshx.RunResult) (any, *out.Error) {
	units, err := svcResult(rr)
	if err != nil {
		return units, err
	}
	rc, _ := strconv.Atoi(strings.TrimPrefix(marker(rr.Stdout), "rc="))
	if rc != 0 {
		return units, out.Errf(out.ExitRemote, "SVC_FAILED", "the unit's last journal lines are in stderr; more with `komando logs TARGET --unit UNIT`",
			"systemctl %s failed (exit %d)", action, rc)
	}
	if wait > 0 {
		var down []string
		for _, u := range units {
			if u["active_state"] != "active" {
				down = append(down, fmt.Sprintf("%v is %v", u["id"], u["active_state"]))
			}
		}
		if len(down) > 0 {
			return units, out.Errf(out.ExitRemote, "UNIT_NOT_ACTIVE", "read why with `komando logs TARGET --unit UNIT -n 50`",
				"not active after %ds: %s", wait, strings.Join(down, ", "))
		}
	}
	return units, nil
}

func svcAction(ctx context.Context, action, target string, units []string, sudo, now bool, wait int) error {
	display := "svc " + action + " " + strings.Join(units, " ")
	if now && (action == "enable" || action == "disable") {
		display = "svc " + action + " --now " + strings.Join(units, " ")
	}
	return runOps(ctx, opsSpec{name: "svc." + action, target: target, command: svcScript(action, units, now, wait), display: display,
		sudo: sudo, mutating: true, timeoutAtLeast: time.Duration(wait+30) * time.Second,
		parse: func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) { return svcActionResult(action, wait, rr) },
		text:  svcTable})
}

func svcListResult(rr *sshx.RunResult) (any, *out.Error) {
	if marker(rr.Stdout) == "no-systemd" {
		return nil, errNoSystemd()
	}
	rows := []map[string]string{}
	for _, line := range strings.Split(rr.Stdout, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		rows = append(rows, map[string]string{"unit": f[0], "load": f[1], "active": f[2], "sub": f[3], "description": strings.Join(f[4:], " ")})
	}
	return rows, nil
}

func svcListTable(data any) string {
	units, _ := data.([]map[string]string)
	rows := [][]string{}
	for _, u := range units {
		rows = append(rows, []string{u["unit"], u["load"], u["active"], u["sub"], u["description"]})
	}
	return textTable([]string{"unit", "load", "active", "sub", "description"}, rows)
}

// ----------------------------------------------------------------- logs ---

// journalPriorities are the names journalctl -p takes (also 0-7 and FROM..TO).
var journalPriorities = map[string]bool{"emerg": true, "alert": true, "crit": true, "err": true, "warning": true, "notice": true, "info": true, "debug": true,
	"0": true, "1": true, "2": true, "3": true, "4": true, "5": true, "6": true, "7": true}

// check validates the options here, so a mistake is a usage error (exit 2)
// before anything runs on a server.
func (o *logOpts) check() error {
	n := 0
	for _, s := range []string{o.unit, o.file, o.container} {
		if s != "" {
			n++
		}
	}
	if n > 1 {
		return out.Usage("give one source: --unit, --file or --container")
	}
	if o.lines < 0 {
		return out.Usage("-n must be 0 or more")
	}
	if o.file != "" && (o.since != "" || o.until != "") {
		return out.Usage("--since and --until work with the journal (--unit) and --container; a plain file has no time index, filter it with --grep")
	}
	if o.priority != "" {
		if o.file != "" || o.container != "" {
			return out.Usage("-p works with the journal only (no --file or --container)")
		}
		lo, hi, isRange := strings.Cut(o.priority, "..")
		if !journalPriorities[lo] || (isRange && !journalPriorities[hi]) {
			return out.Usage("invalid priority %q: use emerg, alert, crit, err, warning, notice, info, debug or 0-7 (or a range like err..warning)", o.priority)
		}
	}
	if o.follow && o.until != "" {
		return out.Usage("--until cannot be used with --follow")
	}
	return nil
}

// preflight checks the source on the server first and stops with a
// marker that result turns into an error code.
func (o *logOpts) preflight() string {
	fail := func(m string) string { return "{ echo '#komando:" + m + "'; exit 0; }" }
	switch {
	case o.container != "":
		return ""
	case o.file != "":
		f := sshx.Q(o.file)
		return "[ -e " + f + " ] || " + fail("no-file") + "\n[ -r " + f + " ] || " + fail("no-read") + "\n"
	}
	// journald runs with systemd; without it, only journal files kept on
	// disk can be read
	return "command -v journalctl >/dev/null 2>&1 && { [ -d /run/systemd/system ] || [ -n \"$(find /var/log/journal /run/log/journal -name '*.journal' 2>/dev/null | head -n 1)\" ]; } || " +
		fail("no-systemd") + "\n"
}

// followCheck runs the source check before --follow starts streaming, so a
// missing file or journal stops with its own code (exit 3) instead of a
// stream that never shows anything.
func (o *logOpts) followCheck(ctx context.Context, target string, sudo bool) error {
	pre := o.preflight()
	if pre == "" {
		return nil
	}
	st, err := loadState()
	if err != nil {
		return err
	}
	hosts, err := resolveTargets(st, target)
	if err != nil {
		return err
	}
	res := fanout(ctx, st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) {
		return sshx.Run(ctx, c, sshx.RunRequest{Command: pre + "true", Sudo: sudo, Timeout: 30 * time.Second, MaxOutput: 4096})
	})
	for _, r := range res {
		if r.Err != nil {
			continue // the stream reports connection problems itself
		}
		if _, e := o.result(r.Value.(*sshx.RunResult)); e != nil {
			e.Message = withHost(r.Host.Name, e.Message)
			return e
		}
	}
	return nil
}

// logsResult turns the preflight markers and journalctl's own messages
// into clear errors.
func (o *logOpts) result(rr *sshx.RunResult) (any, *out.Error) {
	switch marker(rr.Stdout) {
	case "no-systemd":
		return "", errNoSystemd()
	case "no-file":
		return "", out.Errf(out.ExitNotFound, "FILE_NOT_FOUND", "check the path, e.g. `komando fs ls TARGET /var/log`", "%s does not exist", o.file)
	case "no-read":
		return "", out.Errf(out.ExitRemote, "PERMISSION_DENIED", "add --sudo", "cannot read %s", o.file)
	}
	if strings.Contains(rr.Stderr, "insufficient permissions") {
		// journalctl as a plain user, as it says itself: only root and the
		// adm / systemd-journal groups read the system journal
		return "", out.Errf(out.ExitRemote, "JOURNAL_PERMISSION", "add --sudo, or add the login user to the systemd-journal group",
			"this user may not read the system journal")
	}
	if strings.Contains(rr.Stderr, "No journal files were found") {
		return "", out.Errf(out.ExitNotFound, "NO_JOURNAL", "the service may log to a file: `komando logs TARGET --file /var/log/...`",
			"journald has no log files on this server")
	}
	if o.unit == "" && o.file == "" && o.container == "" || o.unit != "" {
		if strings.Contains(rr.Stderr, "not seeing messages from other users") {
			return opsWarnings{data: rr.Stdout, warnings: []string{"you see only your own journal entries; add --sudo to read the whole journal"}}, nil
		}
	}
	return rr.Stdout, nil
}
