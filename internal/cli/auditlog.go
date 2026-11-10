package cli

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/flock"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// The audit log is a hash chain: every record carries "prev", the SHA-256 of
// the line before it, so a record edited or removed in the middle shows up
// in `komando audit verify` (ISO 27001 A.8.15, NIST SP 800-53 AU-9). Someone
// who can write the file can still rebuild the whole chain or cut its end;
// send the log elsewhere when that matters.

// appendAudit adds one record, under a lock so parallel komando processes
// keep the chain in order.
func appendAudit(rec map[string]any) error {
	line, err := writeAudit(rec)
	if err == nil && auditSyslog != "" {
		sendSyslog(auditSyslog, line, time.Now())
	}
	return err
}

// auditSyslog is the audit_syslog setting of this command's state.
var auditSyslog string

func writeAudit(rec map[string]any) ([]byte, error) {
	if store.Sealed() {
		return writeSealedAudit(rec)
	}
	f, err := os.OpenFile(store.Path("audit.jsonl"), os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := flock.Lock(f); err != nil {
		return nil, err
	}
	defer flock.Unlock(f)
	last, err := lastLine(f)
	if err != nil {
		return nil, err
	}
	if last != nil {
		rec["prev"] = lineHash(last)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	_, err = f.Write(append(b, '\n'))
	return b, err
}

func lineHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// lastLine returns the file's last line without its newline, or nil.
func lastLine(f *os.File) ([]byte, error) {
	end, err := f.Seek(0, io.SeekEnd)
	if err != nil || end == 0 {
		return nil, err
	}
	const chunk = 64 << 10
	var buf []byte
	for pos := end; pos > 0; {
		n := int64(chunk)
		if pos < n {
			n = pos
		}
		pos -= n
		part := make([]byte, n)
		if _, err := f.ReadAt(part, pos); err != nil {
			return nil, err
		}
		buf = append(part, buf...)
		trimmed := bytes.TrimRight(buf, "\n")
		if i := bytes.LastIndexByte(trimmed, '\n'); i >= 0 {
			return trimmed[i+1:], nil
		}
		if pos == 0 {
			return trimmed, nil
		}
	}
	return nil, nil
}

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
	return "audit log BROKEN at line " + strconv.Itoa(a.FirstBroken) + "\n" + a.Note
}

// verifyAudit walks the chain. Records from before the chain existed (no
// prev) are fine at the start of the file, never after a chained one.
func verifyAudit() (auditCheck, error) {
	if store.Sealed() {
		return verifySealedAudit()
	}
	r := auditCheck{OK: true, Note: "every record follows the one before it; an edited, inserted or removed record would break the chain (a cut-off end would not)"}
	f, err := os.Open(store.Path("audit.jsonl"))
	if os.IsNotExist(err) {
		r.Note = "no audit log yet"
		return r, nil
	}
	if err != nil {
		return r, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	var prev []byte
	chained := false
	for line := 1; sc.Scan(); line++ {
		b := sc.Bytes()
		r.Entries++
		var rec struct {
			Prev *string `json:"prev"`
		}
		bad := json.Unmarshal(b, &rec) != nil
		switch {
		case bad:
		case rec.Prev == nil:
			bad = chained
		default:
			chained = true
			r.Chained++
			bad = prev == nil || *rec.Prev != lineHash(prev)
		}
		if bad && r.OK {
			r.OK, r.FirstBroken = false, line
			r.Note = "a record at or just before this line was changed, added or removed outside komando"
		}
		prev = append(prev[:0], b...)
	}
	return r, sc.Err()
}

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
