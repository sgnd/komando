package cli

import (
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
)

// The audit log is a hash chain: every record carries "prev", the SHA-256 of
// the line before it, so a record edited or removed in the middle shows up
// in `komando audit verify` (ISO 27001 A.8.15, NIST SP 800-53 AU-9). Someone
// who can write the file can still rebuild the whole chain or cut its end;
// send the log elsewhere when that matters.

// appendAudit adds one record, under a lock so parallel komando processes
// keep the chain in order (audit_log_sealed.go).
func appendAudit(rec map[string]any) error {
	line, err := writeAudit(rec)
	if err == nil && auditSyslog != "" {
		sendSyslog(auditSyslog, line, time.Now())
	}
	return err
}

// auditSyslog is the audit_syslog setting of this command's state.
var auditSyslog string

func writeAudit(rec map[string]any) ([]byte, error) { return writeSealedAudit(rec) }

type auditCheck struct {
	OK          bool   `json:"ok"`
	Entries     int    `json:"entries"`
	Chained     int    `json:"chained"`                // records with a prev hash
	FirstBroken int    `json:"first_broken,omitempty"` // line number
	Note        string `json:"note"`
}

func (a auditCheck) Text() string {
	if a.OK {
		return "audit log intact: " + strconv.Itoa(a.Entries) + " entries\n" + a.Note
	}
	return "audit log broken at line " + strconv.Itoa(a.FirstBroken) + "\n" + a.Note
}

// verifyAudit checks the store's audit records (audit_log_sealed.go).
func verifyAudit() (auditCheck, error) { return verifySealedAudit() }

func auditVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Check that no audit record was changed, added or removed outside komando",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := verifyAudit()
			if err != nil {
				return err
			}
			if !r.OK {
				out.P.Print("audit.verify", r, &out.Error{Code: "AUDIT_TAMPERED", Exit: out.ExitError,
					Message: "the audit log chain is broken at line " + strconv.Itoa(r.FirstBroken),
					Hint:    "keep a copy of the file and find out who changed it; komando keeps adding records after it"})
				return exitCode(out.ExitError)
			}
			out.P.Print("audit.verify", r, nil)
			return nil
		},
	}
}
