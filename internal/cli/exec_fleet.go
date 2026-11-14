package cli

import (
	"fmt"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// The closing lines of a command that ran on servers. A person reads the
// per-host blocks above them, so the closing line names who failed and how;
// an AI agent reads data.results.

// runSummary is fleetSummary plus the hosts --fail-fast never started.
type runSummary struct {
	fleetSummary
	Skipped      int      `json:"skipped,omitempty"`
	SkippedHosts []string `json:"skipped_hosts,omitempty"`
}

// hostFail is one failed host for the closing line.
type hostFail struct {
	host   string
	reason string     // "exit 3", "timed out", "connection refused"
	err    *out.Error // the host's own error, when it has one
}

// failReason is the short reason shown after a host's name.
func failReason(code int, e *out.Error) string {
	if e != nil {
		switch e.Code {
		case "TIMEOUT":
			return "timed out"
		case "CONNECTION_REFUSED":
			return "connection refused"
		case "CONNECT_TIMEOUT":
			return "connect timed out"
		case "AUTH_FAILED":
			return "login failed"
		case "HOSTKEY_MISMATCH":
			return "host key mismatch"
		}
		if code == 0 || code == -1 {
			return strings.ToLower(strings.ReplaceAll(e.Code, "_", " "))
		}
	}
	return fmt.Sprintf("exit %d", code)
}

// finishFleet prints a multi-host result and turns failures into the exit
// code: worst is the worst exit of the failed hosts.
func finishFleet(cl *call, command string, data any, sum runSummary, worst int, fails []hostFail) error {
	if len(fails) == 0 {
		cl.out.Print(command, data, nil)
		return nil
	}
	soft := &out.Error{Exit: worst}
	defer func() {
		// data that is not per-host results (jobs) says itself where to look
		// and what to run next, for a person and an agent alike
		if h, ok := data.(fleetHinter); ok && sum.Total > 1 {
			if hint := h.fleetHint(cl); hint != "" {
				soft.Hint = hint
			}
		}
		cl.out.Print(command, data, soft)
	}()
	if sum.Total == 1 {
		f := fails[0]
		soft.Code, soft.Message = "FAILED", "server "+f.host+" failed ("+f.reason+")"
		if f.err != nil && f.err.Code != "REMOTE_EXIT" {
			// a connection, timeout or policy problem: its own code and hint
			soft.Code = f.err.Code
			soft.Message = withHost(f.host, f.err.Message)
			soft.Hint = f.err.Hint
		}
		if soft.Hint == "" && cl.out.Format != "text" {
			soft.Hint = "each server's result has its exit code and error output (data.results in -o json)"
		}
	} else {
		parts := make([]string, len(fails))
		for i, f := range fails {
			parts[i] = f.host + " (" + f.reason + ")"
		}
		soft.Code = "PARTIAL_FAILURE"
		soft.Message = failedOf(len(fails), sum.Total) + ": " + strings.Join(parts, ", ")
		if sum.Skipped > 0 {
			soft.Message += fmt.Sprintf("; %d skipped by --fail-fast: %s", sum.Skipped, strings.Join(sum.SkippedHosts, ", "))
		}
		if cl.out.Format != "text" {
			soft.Hint = "each server's result has its exit code and error output (data.results in -o json)"
		}
	}
	return exitCode(worst)
}

// fleetHinter is data whose closing hint is its own: job start and job
// wait return jobs, not data.results.
type fleetHinter interface{ fleetHint(cl *call) string }

// truncationNotes tells a person, on stderr, that output was cut. JSON
// readers have stdout_truncated / stderr_truncated.
func truncationNotes(cl *call, rs []execHostResult, limit int, many bool) {
	if cl.out.Format != "text" {
		return
	}
	for _, r := range rs {
		if r.RunResult == nil || !(r.StdoutTruncated || r.StderrTruncated) {
			continue
		}
		who := ""
		if many {
			who = " from " + r.Host
		}
		sayLine(cl, "Note: showing the first "+humanBytes(int64(limit))+" of the output"+who+"; raise --max-output, or run it with `komando job start` or `komando download` for big output")
	}
}

// withHost puts the server's name in front of msg, unless msg already names
// it ("no authentication method available for web1" stays as it is).
func withHost(host, msg string) string {
	for _, w := range strings.FieldsFunc(msg, func(r rune) bool { return r == ' ' || r == ':' || r == ',' || r == '(' || r == ')' || r == '"' }) {
		if w == host {
			return msg
		}
	}
	return host + ": " + msg
}
