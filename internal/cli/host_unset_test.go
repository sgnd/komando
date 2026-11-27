package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// --unset of host ssh|winrm edit takes the leaf's own words only: the old
// body words and the settings a WinRM server does not have are refused.
func TestHostUnsetTakesTheLeafWords(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web1", "u@10.0.0.1", "--credential", "secret:web1-pw", "--sudo-credential", "secret:web1-sudo")
	mustRun(t, "host", "winrm", "add", "win1", "Administrator@10.0.0.9")
	for _, args := range [][]string{
		{"host", "ssh", "edit", "web1", "--unset", "password-ref"},
		{"host", "ssh", "edit", "web1", "--unset", "sudo-ref"},
		{"host", "ssh", "edit", "web1", "--unset", "via,sudo-ref"},
		{"host", "winrm", "edit", "win1", "--unset", "key"},
	} {
		if e := wantCode(t, "USAGE", args...); !strings.Contains(e.Message, "--unset takes") {
			t.Errorf("%v: %s", args, e.Message)
		}
	}
	mustRun(t, "host", "ssh", "edit", "web1", "--unset", "credential,sudo-credential")
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if h := st.Hosts["web1"]; h.PasswordRef != "" || h.SudoRef != "" {
		t.Errorf("--unset credential,sudo-credential: %+v", h)
	}
}

// A setting given and unset in one edit is refused in the leaf's words.
func TestHostSetAndUnsetNameTheLeafFlags(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web1", "u@10.0.0.1")
	for flag, word := range map[string]string{"--credential": "credential", "--sudo-credential": "sudo-credential"} {
		e := wantCode(t, "USAGE", "host", "ssh", "edit", "web1", flag, "secret:x", "--unset", word)
		if !strings.Contains(e.Message, flag+" and --unset "+word) || strings.Contains(e.Message, "-ref") {
			t.Errorf("%s: %s", flag, e.Message)
		}
	}
}

// A reference komando does not know is refused in the leaf's words.
func TestHostRefErrorNamesNoBodyFlag(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web1", "u@10.0.0.1")
	for _, flag := range []string{"--credential", "--sudo-credential"} {
		e := wantCode(t, "USAGE", "host", "ssh", "edit", "web1", flag, "nosuch:x")
		if strings.Contains(e.Message, "-ref") || !strings.Contains(e.Message, "takes a reference") {
			t.Errorf("%s: %s", flag, e.Message)
		}
	}
}
