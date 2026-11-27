package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// WinRM settings that give up the server check or the password's
// protection (tls=skip-verify, tls=off, auth=basic) need a person's yes
// from an AI agent, on host add, host edit and import, as a conn's weak
// TLS does: a stored password would go to a server komando cannot tell
// from an impostor.
func TestWinRMWeakSettingsNeedAPerson(t *testing.T) {
	stored := func(t *testing.T, name string) *store.Host {
		t.Helper()
		closeStoreAtEnd(t)
		st, err := loadState()
		if err != nil {
			t.Fatal(err)
		}
		return st.Hosts[name]
	}
	for _, q := range []string{"tls=skip-verify", "tls=off", "auth=basic"} {
		t.Run(q, func(t *testing.T) {
			invHome(t)
			noAgent(t)
			mustRun(t, "host", "winrm", "add", "win1", "winrm://Administrator@10.0.0.9")
			n := asAgent(t, false, true)
			wantCode(t, "SAFETY_SETTING", "host", "winrm", "add", "win2", "winrm://Administrator@10.0.0.10?"+q)
			wantCode(t, "SAFETY_SETTING", "host", "winrm", "edit", "win1", "--address", "winrm://Administrator@10.0.0.9?"+q)
			k, v, _ := strings.Cut(q, "=")
			f := writeTemp(t, "exp.json", `{"format":"komando-export/1","hosts":[{"name":"win3","address":"10.0.0.11","user":"Administrator","transport":"winrm","os":"windows","winrm":{"`+k+`":"`+v+`"}}]}`)
			wantCode(t, "SAFETY_SETTING", "import", "komando", f)
			if stored(t, "win2") != nil || stored(t, "win3") != nil || *stored(t, "win1").WinRMOpts != (store.WinRMOpts{}) {
				t.Fatal("a weak WinRM setting was saved without a person's yes")
			}
			if *n != 0 {
				t.Fatalf("windows without --yes: %d", *n)
			}
			// a person, or a setting the server had already, asks nothing
			noAgent(t)
			mustRun(t, "host", "winrm", "edit", "win1", "--address", "winrm://Administrator@10.0.0.9?"+q)
			asAgent(t, false, true)
			mustRun(t, "host", "ssh", "edit", "win1", "--notes", "same settings")
		})
	}
}
