package cli

import (
	"fmt"
	"strings"
	"testing"
)

// vpn add/edit take --label, --protected and --unset like host and conn,
// and rm and edit take NAME|TARGET... (S-10.2, C-F26).
func TestVpnParityWithHost(t *testing.T) {
	root := newRoot(tcl)
	for _, verb := range []string{"add", "edit"} {
		h, v := findCmd(t, root, "host", "ssh", verb), findCmd(t, root, "vpn", "socks", verb)
		for _, flag := range []string{"label", "protected"} {
			if h.Flags().Lookup(flag) == nil || v.Flags().Lookup(flag) == nil {
				t.Errorf("%s: --%s missing on host or vpn", verb, flag)
			}
		}
	}
	if findCmd(t, root, "vpn", "socks", "edit").Flags().Lookup("unset") == nil {
		t.Error("vpn edit --unset")
	}
	for _, verbs := range [][2]string{{"edit", "edit"}, {"remove", "remove"}} {
		_, h, _ := strings.Cut(findCmd(t, root, "host", "ssh", verbs[0]).Use, " ")
		_, v, _ := strings.Cut(findCmd(t, root, "vpn", "socks", verbs[1]).Use, " ")
		if h != v {
			t.Errorf("%s: host takes %q, vpn takes %q", verbs[0], h, v)
		}
	}
}

func TestVpnLabelsProtectedUnset(t *testing.T) {
	invHome(t)
	mustRun(t, "vpn", "socks", "add", "lab", "--proxy-address", "127.0.0.1:1080", "--label", "site=jkt", "--group", "office", "--notes", "n")
	mustRun(t, "vpn", "socks", "add", "lab2", "--proxy-address", "127.0.0.1:1081", "--group", "office")
	d := mustRun(t, "vpn", "socks", "show", "lab")
	if !strings.Contains(jsonOf(d), `"labels":{"site":"jkt"}`) {
		t.Errorf("labels: %s", jsonOf(d))
	}
	mustRun(t, "vpn", "socks", "edit", "lab", "--label", "site=", "--label", "env=prod", "--unset", "notes")
	if s := jsonOf(mustRun(t, "vpn", "socks", "show", "lab")); !strings.Contains(s, `"labels":{"env":"prod"}`) || strings.Contains(s, `"notes"`) {
		t.Errorf("after edit: %s", s)
	}
	for _, w := range []string{"mfa", "protected"} {
		if e := wantCode(t, "USAGE", "vpn", "socks", "edit", "lab", "--unset", w); !strings.Contains(e.Hint, "--"+w+"=false") {
			t.Errorf("--unset %s: %+v", w, e)
		}
	}
	wantCode(t, "USAGE", "vpn", "socks", "edit", "lab", "--unset", "psk-credential") // not a socks setting
	wantCode(t, "USAGE", "vpn", "socks", "edit", "lab", "--notes", "x", "--unset", "notes")

	// several at once, by a selector
	d = mustRun(t, "vpn", "socks", "edit", "@office", "--protected")
	if jsonOf(d["changed"]) != `["lab","lab2"]` {
		t.Errorf("edit @office: %s", jsonOf(d))
	}
	// a protected VPN: changing or removing it needs a person's yes; turning
	// protection or --mfa off weakens a check
	wantCode(t, "PROTECTED_TARGET", "vpn", "socks", "edit", "lab", "--notes", "x")
	wantCode(t, "PROTECTED_TARGET", "vpn", "socks", "remove", "lab")
	wantCode(t, "PROTECTED_TARGET", "vpn", "socks", "remove", "@office")
	wantCode(t, "SAFETY_SETTING", "vpn", "socks", "edit", "lab", "--protected=false")
	wantCode(t, "PROTECTED_TARGET", "vpn", "socks", "add", "lab", "--proxy-address", "127.0.0.1:1082", "--overwrite")
	_, e := invRun(t, "--dry-run", "vpn", "socks", "remove", "@office")
	if e != nil {
		t.Errorf("dry run: %+v", e)
	}
	mustRun(t, "vpn", "socks", "add", "sso", "--proxy-address", "127.0.0.1:1083", "--mfa")
	wantCode(t, "SAFETY_SETTING", "vpn", "socks", "edit", "sso", "--mfa=false")
	if d := mustRun(t, "vpn", "socks", "remove", "sso"); fmt.Sprint(d["removed"]) != "[sso]" {
		t.Errorf("rm one: %v", d)
	}
}
