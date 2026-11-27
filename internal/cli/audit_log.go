package cli

import (
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/auditlog"
	"github.com/sgnd/komando/internal/out"
)

// The audit log is a hash chain: every record carries "prev", the SHA-256 of
// the line before it, so a record edited or removed in the middle shows up
// in `komando audit check` (ISO 27001 A.8.15, NIST SP 800-53 AU-9). Someone
// who can write the file can still rebuild the whole chain or cut its end;
// send the log elsewhere when that matters.

// appendAudit adds one record, under a lock so parallel komando processes
// keep the chain in order (internal/auditlog), and sends it to syslog
// too when the audit_syslog setting names a target.
func appendAudit(cl *call, syslog string, rec map[string]any) error {
	line, err := writeAudit(rec)
	if err == nil && syslog != "" {
		sendSyslog(cl, syslog, line, time.Now())
	}
	return err
}

func writeAudit(rec map[string]any) ([]byte, error) { return auditlog.Append(rec) }

// verifyAudit checks the store's audit records (internal/auditlog).
func verifyAudit() (auditlog.Check, error) { return auditlog.Verify() }

func auditVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Check that no audit record was changed, added or removed outside komando",
		Args:  cobra.NoArgs,
		RunE: inCall(func(cl *call, cmd *cobra.Command, _ []string) error {
			r, err := verifyAudit()
			if err != nil {
				return err
			}
			if !r.OK {
				cl.out.Print("audit.check", r, &out.Error{Code: "AUDIT_TAMPERED", Exit: out.ExitError,
					Message: "the audit log chain is broken at line " + strconv.Itoa(r.FirstBroken),
					Hint:    "keep a copy of the file and find out who changed it; komando keeps adding records after it"})
				return exitCode(out.ExitError)
			}
			cl.out.Print("audit.check", r, nil)
			return nil
		}),
	}
}
