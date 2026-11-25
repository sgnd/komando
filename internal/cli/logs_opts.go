package cli

import (
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/snippet"
	"github.com/sgnd/komando/internal/sshx"
)

// logOpts are the flags of `komando logs` and its aliases (svc logs,
// docker logs).
type logOpts struct {
	unit, file, container, since, until, grep, priority string
	lines                                               int
	sudo, follow, timestamps                            bool
}

// dockerLogs is `docker logs` with the time of each line only when asked
// (--timestamps), as docker and kubectl do.
func (o *logOpts) dockerLogs() string {
	if o.timestamps {
		return "docker logs --timestamps"
	}
	return "docker logs"
}

// bind adds the logs flags to c, except those named in skip.
func (o *logOpts) bind(c *cobra.Command, skip ...string) {
	f := c.Flags()
	f.StringVarP(&o.unit, "unit", "u", "", "systemd unit (journalctl)")
	f.StringVar(&o.file, "file", "", "read this log file on the server (full path)")
	f.StringVarP(&o.container, "container", "c", "", "read this Docker container's log (its name or ID)")
	f.StringVar(&o.since, "since", "", "start time: back from now (30m, 2h, 7d), today, yesterday or '2026-01-02 10:00'")
	f.StringVar(&o.until, "until", "", "end time, in the same forms as --since")
	f.StringVar(&o.grep, "grep", "", "only lines matching this extended regex (case-insensitive)")
	if !slices.Contains(skip, "priority") {
		f.StringVarP(&o.priority, "priority", "p", "", "journal priority and worse: emerg, alert, crit, err, warning, notice, info, debug (or 0-7)")
	}
	f.IntVarP(&o.lines, "limit", "n", 200, "the most lines to show (the last ones)")
	f.BoolVarP(&o.sudo, "sudo", "s", false, "read via sudo (the whole journal, protected files)")
	f.BoolVarP(&o.follow, "follow", "f", false, "keep printing new lines until Ctrl-C")
	if !slices.Contains(skip, "timestamps") {
		f.BoolVar(&o.timestamps, "timestamps", false, "show when each container log line was written (containers)")
	}
	flagAlias(c, "tail", "limit") // the word docker and kubectl use: a permanent synonym
}

func (o *logOpts) build() (string, error) {
	if err := o.check(); err != nil {
		return "", err
	}
	c := o.runSource()
	if o.follow {
		return c, nil // followCheck checks the source before streaming
	}
	return o.preflight() + c, nil
}

// runSource is source as it runs: a log file read with --sudo is opened
// through sudoReadScript, so root does not follow a link another server
// user made (app.log -> /etc/shadow). With --follow it keeps reading the
// file it opened (tail -f), as following by name would open the name
// again as root without that check. source stays the plain command shown
// in the output and the audit log.
func (o *logOpts) runSource() string {
	if !o.sudo || o.container != "" || o.file == "" {
		return o.source()
	}
	n := strconv.Itoa(o.lines)
	if o.follow {
		c := sudoReadScript(o.file, "tail -n "+n+" -f")
		if o.grep != "" {
			c += " | grep --line-buffered -iE -- " + sshx.Q(o.grep)
		}
		return c
	}
	if o.grep != "" {
		return sudoReadScript(o.file, "grep -iE -- "+sshx.Q(o.grep)) + " | tail -n " + n
	}
	return sudoReadScript(o.file, "tail -n "+n)
}

// logResult is the shape of the log snippets (design 2.1): the lines as
// they came, and whether the output cap cut them.
type logResult struct {
	Lines     []snippetLogLine `json:"lines"`
	Truncated bool             `json:"truncated"`
}

type snippetLogLine struct {
	Text string `json:"text"`
}

// logLines splits a log's output into its lines.
func logLines(o snippet.Output, stdout string) logResult {
	r := logResult{Lines: []snippetLogLine{}, Truncated: o.Truncated}
	if stdout = strings.TrimSuffix(stdout, "\n"); stdout == "" {
		return r
	}
	for _, l := range strings.Split(stdout, "\n") {
		r.Lines = append(r.Lines, snippetLogLine{Text: l})
	}
	return r
}

// logLimitVar is the count of lines, as -n takes it.
var logLimitVar = snippet.Var{Name: "limit", Channel: snippet.Number, Pattern: regexp.MustCompile(`^[0-9]+$`), MaxLen: 5, Longest: "99999", Default: "200"}

// logsSnippets are the ready-made snippets of logs --unit and docker logs
// (design 2.1). They move with the host commands' package (M11). Written
// losses: --since, --until, --grep, --priority, --file, --sudo, --follow
// and --timestamps, and logs without a unit (the whole journal).
func logsSnippets() []snippet.Builtin {
	journal := &logOpts{unit: "unit"} // result reads only that a unit is given
	return []snippet.Builtin{{
		Name: "logs", Type: "host", Replaces: "logs --unit", Reader: "KomandoCall+Logs.swift:78",
		Tier: capability.Read, Shape: "logs/1",
		Vars: []snippet.Var{{Name: "unit", Channel: snippet.Text, Pattern: regexp.MustCompile(`^` + svcUnitUnix + `$`), MaxLen: 256,
			Longest: strings.Repeat("a", 256), Required: true}, logLimitVar},
		Checks: []string{"TestLogsFlagsChecked", "TestSnippetLogsGoldens", "TestSnippetLogsLikeTheCommand", "TestSnippetLogsValues", "TestSnippetLogsTruncated"},
		Text:   map[snippet.Family]string{snippet.Unix: journal.preflight() + "journalctl --no-pager -o short-iso -u {{var:unit}} -n {{var:limit}}"},
		Parse: func(o snippet.Output, _ snippet.Family) (any, error) {
			d, e := journal.result(snippetRun(o))
			if e != nil {
				if e.Code == "JOURNAL_PERMISSION" {
					// the command asks as today; never a group that reads every log
					e.Hint = "the login user cannot read the system journal; run `komando logs TARGET --unit UNIT --sudo` (the command, which asks as it does today), or ask the person whether this user should read the whole journal"
				}
				return nil, e
			}
			if w, ok := d.(opsWarnings); ok {
				s, _ := w.data.(string)
				return opsWarnings{data: logLines(o, s), warnings: w.warnings}, nil
			}
			s, _ := d.(string)
			return logLines(o, s), nil
		},
	}, {
		Name: "docker-logs", Type: "host", Replaces: "docker logs", Reader: "KomandoCall+Docker.swift:10-54",
		Tier: capability.Read, Shape: "docker-logs/1",
		Vars: []snippet.Var{{Name: "container", Channel: snippet.Text, Pattern: containerNameRe, MaxLen: 255,
			Longest: strings.Repeat("a", 255), Required: true}, logLimitVar},
		Checks: []string{"TestLogsFlagsChecked", "TestSnippetLogsGoldens", "TestSnippetLogsLikeTheCommand", "TestSnippetLogsValues"},
		Text:   map[snippet.Family]string{snippet.Unix: "docker logs --tail {{var:limit}} {{var:container}} 2>&1"},
		Parse:  func(o snippet.Output, _ snippet.Family) (any, error) { return logLines(o, o.Stdout), nil },
	}}
}
