package store

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"time"
)

// text is the report the person reads after the migration: names and
// counts only, never a value (design note section 5, step 14).
func (r migration3Report) text() string {
	var b strings.Builder
	b.WriteString("komando moved its store to format 3.\n")
	for _, typ := range slices.Sorted(maps.Keys(r.Counts)) {
		if c := r.Counts[typ]; c[0] != 0 || c[1] != 0 {
			fmt.Fprintf(&b, "  %s: %d before, %d after\n", typ, c[0], c[1])
		}
	}
	for _, n := range r.Names {
		fmt.Fprintf(&b, "  %s %s is now %s\n", n.Kind, n.Old, strings.Join(n.New, ", "))
	}
	for _, h := range r.KeyAndPassword {
		fmt.Fprintf(&b, "  %s logs in with its key; its saved password is kept unused: run `komando host ssh test %s`\n", h, h)
	}
	for _, s := range r.SnippetsWithOldRef {
		fmt.Fprintf(&b, "  snippet %s holds the text secret: (sent to the server as it is)\n", s)
	}
	fmt.Fprintf(&b, "Backup: %s\n", r.Backup)
	if r.BackupNote != "" {
		b.WriteString("  " + r.BackupNote + "\n")
	}
	b.WriteString("It opens only with komando v0.17.0 and holds every secret as it was: remove it once this komando works for you.")
	return b.String()
}

// BackupFile is a backup the store migration left in the komando home.
type BackupFile struct {
	Name     string
	Modified time.Time
}

// Backups lists the migration's backups under their final names. Each is
// whole: it was checked under its .partial name before it got this one.
func Backups() ([]BackupFile, error) {
	es, err := os.ReadDir(Home())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var bs []BackupFile
	for _, e := range es {
		n := e.Name()
		if !e.Type().IsRegular() || !strings.HasPrefix(n, backupPrefix) || !strings.HasSuffix(n, ".db") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			return nil, err
		}
		bs = append(bs, BackupFile{Name: n, Modified: fi.ModTime()})
	}
	return bs, nil
}
