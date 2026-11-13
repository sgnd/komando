package cli

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// logKeep is how long the log of a tunnel, server login or VPN that ended
// stays in komando's folder: long enough to read why it stopped, short
// enough that old output (addresses, errors) does not pile up.
const logKeep = 7 * 24 * time.Hour

// sweepLogs removes the .log files in komando's folder dir (tunnels, vpn,
// login) that nothing running writes to (inUse) and that were not
// changed for logKeep. It runs where such logs are made, so the folder
// never grows without end. Links and other files are left alone.
func sweepLogs(dir string, inUse map[string]bool) {
	ents, err := os.ReadDir(store.Path(dir))
	if err != nil {
		return
	}
	for _, e := range ents {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		p := store.Path(dir, e.Name())
		if inUse[filepath.Clean(p)] {
			continue
		}
		if fi, err := e.Info(); err == nil && time.Since(fi.ModTime()) > logKeep {
			_ = os.Remove(p)
		}
	}
}

// liveLogs are the log files of the tunnels, logins and VPN sessions st
// says are running (whether they still run or not: a log of one komando
// has not yet seen end stays until its record goes).
func liveLogs(st *store.State) map[string]bool {
	m := map[string]bool{}
	for _, t := range st.Tunnels {
		m[filepath.Clean(t.LogFile)] = true
	}
	for _, s := range st.Sessions {
		m[filepath.Clean(s.LogFile)] = true
	}
	for _, l := range st.Logins {
		m[filepath.Clean(l.LogFile)] = true
	}
	return m
}
