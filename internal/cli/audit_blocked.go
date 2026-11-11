package cli

import (
	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
)

// blockAudited: this command recorded its safety stop already, with what
// it ran on; auditBlocked does not record it twice.
var blockAudited bool

// auditBlocked records a safety stop (exit 6) that the command itself did
// not record, so `audit --failed` shows every blocked attempt: a protected
// host rm, a deny rule removal, a secret sent somewhere.
func auditBlocked(cmd *cobra.Command, e *out.Error) {
	if e.Exit != out.ExitPolicy || blockAudited || g.dryRun || cmd == nil || leavesHomeNow(cmd) {
		return
	}
	st, err := loadState()
	if err != nil {
		st = nil // recorded anyway: a broken state file is no reason to lose it
	}
	var hosts, conns []string
	if st != nil { // what it was stopped on, for `audit --target`
		for _, a := range cmd.Flags().Args() {
			if kind, name, ok := st.FindName(a); ok && kind == "host" {
				hosts = append(hosts, name)
			} else if ok && kind == "conn" {
				conns = append(conns, name)
			}
		}
	}
	extra := map[string]any{"blocked": e.Code, "message": e.Message}
	if conns != nil {
		extra["conns"] = conns
	}
	audit(st, commandName(cmd), hosts, "", false, extra)
}
