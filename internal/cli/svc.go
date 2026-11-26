package cli

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/snippet"
	"github.com/sgnd/komando/internal/sshx"
)

// svc status and actions.

// svcResult reads `systemctl show` output into units and fails the host
// when systemd is not running or a unit does not exist.
func svcResult(rr *sshx.RunResult) ([]map[string]any, *out.Error) {
	if e := systemdMissing(rr.Stdout); e != nil {
		return nil, e
	}
	v := parseSvcShow(nil, rr.Stdout)
	units, _ := v.([]map[string]any)
	var missing []string
	for _, u := range units {
		if u["load_state"] == "not-found" {
			missing = append(missing, fmt.Sprintf("%q", fmt.Sprint(u["id"])))
		}
	}
	if len(missing) > 0 {
		return units, out.Errf(out.ExitNotFound, "UNIT_NOT_FOUND", "check the name with `komando svc list TARGET`",
			"no unit named %s", strings.Join(missing, " or "))
	}
	return units, nil
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

func svcListResult(rr *sshx.RunResult) (any, *out.Error) {
	if e := systemdMissing(rr.Stdout); e != nil {
		return nil, e
	}
	rows := []map[string]string{}
	for _, line := range strings.Split(rr.Stdout, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		rows = append(rows, map[string]string{"unit": f[0], "load": f[1], "active": f[2], "sub": f[3], "description": strings.Join(f[4:], " ")})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i]["unit"] < rows[j]["unit"] })
	return rows, nil
}

// logs.

// logsAlias is `svc logs TARGET UNIT` and `docker logs TARGET CONTAINER`:
// it only turns the second word into --unit or --container and runs
// `logs`, so it takes exactly the flags of `logs` (ux.md section 11: one
// implementation).
func logsAlias(use, name, source string) *cobra.Command {
	// the logs flag that does nothing for this source is not there: a
	// journal unit has no --timestamps choice, a container log no priority
	idle := map[string]string{"unit": "timestamps", "container": "priority"}
	var lo logOpts
	c := &cobra.Command{
		Use:   use,
		Short: map[string]string{"unit": "Read a service unit's logs", "container": "Read a container's logs"}[source],
		Long:  "Same as `komando logs TARGET --" + source + " " + strings.ToUpper(source) + "`.",
		Args:  cobra.ExactArgs(2),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			if cmd.Flags().Changed(source) {
				return out.Usage("give the %s once: as the second word or with --%s, not both", source, source)
			}
			_ = cmd.Flags().Set(source, args[1])
			return runLogs(cl, cmd.Context(), name, args[0], &lo, lo.sudo)
		}),
	}
	lo.bind(c, idle[source])
	for _, f := range []string{"unit", "file", "container"} {
		_ = c.Flags().MarkHidden(f)
	}
	return c
}

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
		return out.Usage("-n takes 0 or more")
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
			return out.Usage("%q is not a log priority: use emerg, alert, crit, err, warning, notice, info, debug or 0-7 (or a range like err..warning)", o.priority)
		}
	}
	if o.timestamps && o.container == "" {
		return out.Usage("--timestamps works with --container only; journal lines already start with their time")
	}
	if o.follow && o.until != "" {
		return out.Usage("--until cannot be used with --follow")
	}
	if o.container != "" {
		if err := checkContainerName(o.container); err != nil {
			return err
		}
	}
	if o.file != "" && !strings.HasPrefix(o.file, "/") {
		return out.Usage("--file takes the full path of the log on the server, starting with / (got %q)", o.file)
	}
	_, _, err := o.times()
	return err
}

// times is --since and --until in the form the source takes: journalctl
// reads -2h as "2 hours ago" (2h alone is not a time to it), docker logs
// reads 2h and has no days.
func (o *logOpts) times() (since, until string, err error) {
	docker := o.container != ""
	if since, err = logTime("--since", o.since, docker); err != nil {
		return "", "", err
	}
	until, err = logTime("--until", o.until, docker)
	return since, until, err
}

const logTimeUnits = `(us|ms|s|sec|secs|seconds?|m|min|mins|minutes?|h|hr|hrs|hours?|d|days?|w|weeks?)`

var (
	relTimeRe = regexp.MustCompile(`^-?(\d+` + logTimeUnits + `)+$`)
	agoTimeRe = regexp.MustCompile(`^\d+ ?` + logTimeUnits + ` ago$`)
)

var relPartRe = regexp.MustCompile(`(\d+)` + logTimeUnits)

// relDuration adds up a journal-style time back from now ("1d2h", "90min",
// "1w"), which relTimeRe has already checked.
func relDuration(rel string) time.Duration {
	var d time.Duration
	for _, m := range relPartRe.FindAllStringSubmatch(rel, -1) {
		n, _ := strconv.ParseInt(m[1], 10, 64)
		var unit time.Duration
		switch u := m[2]; {
		case u == "us":
			unit = time.Microsecond
		case u == "ms":
			unit = time.Millisecond
		case strings.HasPrefix(u, "s"):
			unit = time.Second
		case u == "m" || strings.HasPrefix(u, "min"):
			unit = time.Minute
		case strings.HasPrefix(u, "h"):
			unit = time.Hour
		case strings.HasPrefix(u, "d"):
			unit = 24 * time.Hour
		case strings.HasPrefix(u, "w"):
			unit = 7 * 24 * time.Hour
		}
		d += time.Duration(n) * unit
	}
	return d
}

var logTimeLayouts = []string{"2006-01-02", "2006-01-02 15:04", "2006-01-02 15:04:05", "2006-01-02T15:04", "2006-01-02T15:04:05"}

// dockerTimeArg is --since or --until for docker logs: today, yesterday
// and now become the server's own midnight or time when the command runs
// there (docker reads a time without a zone as the server's local time,
// as journalctl does); any other time is passed as it is.
func dockerTimeArg(v string) string {
	switch v {
	case "now":
		return `"$(date +%Y-%m-%dT%H:%M:%S)"`
	case "today":
		return `"$(date +%Y-%m-%dT00:00:00)"`
	case "yesterday":
		// GNU and busybox date take -d @SECONDS, BSD date -r SECONDS
		return `"$(y=$(( $(date +%s) - 86400 )); date -d "@$y" +%Y-%m-%dT00:00:00 2>/dev/null || date -r "$y" +%Y-%m-%dT00:00:00)"`
	}
	return sshx.Q(v)
}

func logTime(flag, v string, docker bool) (string, error) {
	journalOnly := out.Usage("%s %s works with the journal; for a container give a time back from now (30m, 2h, 7d) or a date (2026-01-02T10:00:00)", flag, v)
	switch {
	case v == "":
		return "", nil
	case v == "today" || v == "yesterday" || v == "now":
		return v, nil // a container's are worked out on the server (dockerTimeArg)
	case relTimeRe.MatchString(v):
		rel := strings.TrimPrefix(v, "-")
		if !docker {
			return "-" + rel, nil
		}
		// docker takes Go durations only: 1w, 90min or 1d2h become hours,
		// minutes or seconds
		d := relDuration(rel)
		switch {
		case d%time.Hour == 0:
			return strconv.FormatInt(int64(d/time.Hour), 10) + "h", nil
		case d%time.Minute == 0:
			return strconv.FormatInt(int64(d/time.Minute), 10) + "m", nil
		}
		return strconv.FormatInt(int64(d/time.Second), 10) + "s", nil
	case agoTimeRe.MatchString(v):
		if docker {
			return "", journalOnly
		}
		return v, nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		if docker {
			return v, nil
		}
		return t.UTC().Format("2006-01-02 15:04:05") + " UTC", nil
	}
	for _, l := range logTimeLayouts {
		if _, err := time.Parse(l, v); err == nil {
			if docker {
				return strings.Replace(v, " ", "T", 1), nil
			}
			return strings.Replace(v, "T", " ", 1), nil
		}
	}
	return "", out.Usage("%s %q is not a time: give a time back from now (30m, 2h, 7d), today, yesterday, or a date (2026-01-02 10:00)", flag, v)
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
func (o *logOpts) followCheck(cl *call, ctx context.Context, target string, sudo bool) error {
	pre := o.preflight()
	if pre == "" {
		return nil
	}
	st, err := loadState()
	if err != nil {
		return err
	}
	hosts, err := resolveTargets(cl, st, target)
	if err != nil {
		return err
	}
	res := fanout(cl, ctx, st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) {
		check := "true"
		if o.sudo && o.file != "" {
			check = sudoReadScript(o.file, "true") // a link root does not follow stops here
		}
		return sshx.Run(ctx, c, sshx.RunRequest{Command: pre + check, Sudo: sudo, Timeout: 30 * time.Second, MaxOutput: 4096})
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
		return "", out.Errf(out.ExitNotFound, "FILE_NOT_FOUND", "check the path, for example `komando fs list TARGET /var/log`", "%s does not exist", o.file)
	case "no-read":
		return "", out.Errf(out.ExitRemote, "PERMISSION_DENIED", "add --sudo", "cannot read %s", o.file)
	}
	if o.sudo && o.file != "" && o.container == "" && rr.ExitCode == sudoExitLink {
		return "", toErr(readLinkStop(o.file))
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

// followLogs streams a log command until Ctrl-C (or --timeout, if given).
func followLogs(cl *call, ctx context.Context, target, command string, sudo bool) error {
	if cl.flags.timeout == 0 {
		cl.flags.timeout = 24 * time.Hour // the person stops it with Ctrl-C
	}
	return runFleet(cl, ctx, "logs", target, command, nil, execOpts{sudo: sudo, stream: true, follow: true}, false)
}

// svcUnitVar is the units svc-status takes. A systemd unit name and a
// Windows service name allow different characters: each text keeps the
// pattern today's command checks (winServiceName on Windows).
var svcUnitVar = snippet.Var{Name: "unit", Channel: snippet.Text,
	Pattern: regexp.MustCompile(`^(?:` + svcUnitUnix + `|` + strings.Trim(winServiceName.String(), "^$") + `)$`),
	Families: map[snippet.Family]*regexp.Regexp{
		snippet.Unix:    regexp.MustCompile(`^` + svcUnitUnix + `$`),
		snippet.Windows: winServiceName,
	},
	MaxLen: 256, Longest: strings.Repeat("a", 256), Required: true, List: true, MaxItems: 32}

// svcUnitUnix is a systemd unit name, with the \x escapes systemd writes.
const svcUnitUnix = `[A-Za-z0-9@._:\\-]+`

// svcSnippets are the ready-made snippets of svc list and svc status
// (design 2.1). They move with the host commands' package (M11).
func svcSnippets() []snippet.Builtin {
	return []snippet.Builtin{{
		Name: "svc-list", Type: "host", Replaces: "svc list", Reader: "KomandoCall+Services.swift:36-43; KomandoCall.swift:67",
		Tier: capability.Read, Shape: "svc-list/1",
		Checks: []string{"TestSvcStatusFindsMissingUnitsAndNoSystemd", "TestSnippetSamplesMatchGoldens/svc-list", "TestWindowsSvcAndFacts"},
		Text: map[snippet.Family]string{
			snippet.Unix:    noSystemd + "systemctl list-units --type=service --all --no-legend --plain --no-pager",
			snippet.Windows: winSvcListScript,
		},
		Parse: func(o snippet.Output, f snippet.Family) (any, error) {
			if f == snippet.Windows {
				return winSvcList("")(nil, snippetRun(o))
			}
			return svcListResult(snippetRun(o))
		},
	}, {
		Name: "svc-status", Type: "host", Replaces: "svc status", Reader: "KomandoCall+Services.swift:36-43",
		Tier: capability.Read, Shape: "svc-status/1", Vars: []snippet.Var{svcUnitVar},
		Checks: []string{"TestSvcStatusFindsMissingUnitsAndNoSystemd", "TestParseSvcShow", "TestWindowsSvcAndFacts",
			"TestSnippetSvcUnitNames", "TestSnippetSamplesMatchGoldens/svc-status"},
		Text: map[snippet.Family]string{
			snippet.Unix:    noSystemd + "systemctl show --no-pager -p " + strings.Join(svcProps, ",") + " -- {{var:unit}}",
			snippet.Windows: winSvcStatusText("@({{var:unit}})"),
		},
		Parse: func(o snippet.Output, f snippet.Family) (any, error) {
			if f == snippet.Windows {
				return winServices(snippetRun(o))
			}
			return svcResult(snippetRun(o))
		},
	}}
}
