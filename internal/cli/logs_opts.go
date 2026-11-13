package cli

import (
	"slices"
	"strconv"

	"github.com/spf13/cobra"

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
