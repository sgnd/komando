package cli

import (
	"strings"
	"testing"
)

// vpn add/edit take --label, --protected and --unset like host and conn,
// and rm and edit take NAME|TARGET... (S-10.2, C-F26).
func TestVpnParityWithHost(t *testing.T) {
	root := newRoot()
	for _, verb := range []string{"add", "edit"} {
		h, v := findCmd(t, root, "host", verb), findCmd(t, root, "vpn", verb)
		for _, flag := range []string{"label", "protected"} {
			if h.Flags().Lookup(flag) == nil || v.Flags().Lookup(flag) == nil {
				t.Errorf("%s: --%s missing on host or vpn", verb, flag)
			}
		}
	}
	if findCmd(t, root, "vpn", "edit").Flags().Lookup("unset") == nil {
		t.Error("vpn edit --unset")
	}
	for _, verb := range []string{"edit", "rm"} {
		if h, v := findCmd(t, root, "host", verb).Use, findCmd(t, root, "vpn", verb).Use; h != v {
			t.Errorf("%s: host %q, vpn %q", verb, h, v)
		}
	}
}

func TestVpnLabelsProtectedUnset(t *testing.T) {
	invHome(t)
	mustRun(t, "vpn", "add", "lab", "socks", "--proxy-address", "127.0.0.1:1080", "--label", "site=jkt", "-g", "office", "--notes", "n")
	mustRun(t, "vpn", "add", "lab2", "socks", "--proxy-address", "127.0.0.1:1081", "-g", "office")
	d := mustRun(t, "vpn", "show", "lab")
	if !strings.Contains(jsonOf(d), `"labels":{"site":"jkt"}`) {
		t.Errorf("labels: %s", jsonOf(d))
	}
	mustRun(t, "vpn", "edit", "lab", "--label", "site=", "--label", "env=prod", "--unset", "notes")
	if s := jsonOf(mustRun(t, "vpn", "show", "lab")); !strings.Contains(s, `"labels":{"env":"prod"}`) || strings.Contains(s, `"notes"`) {
		t.Errorf("after edit: %s", s)
	}
	for _, w := range []string{"mfa", "protected"} {
		if e := wantCode(t, "USAGE", "vpn", "edit", "lab", "--unset", w); !strings.Contains(e.Hint, "--"+w+"=false") {
			t.Errorf("--unset %s: %+v", w, e)
		}
	}
	wantCode(t, "USAGE", "vpn", "edit", "lab", "--unset", "psk-ref") // not a socks setting
	wantCode(t, "USAGE", "vpn", "edit", "lab", "--notes", "x", "--unset", "notes")

	// several at once, by a selector
	d = mustRun(t, "vpn", "edit", "@office", "--protected")
	if jsonOf(d["changed"]) != `["lab","lab2"]` {
		t.Errorf("edit @office: %s", jsonOf(d))
	}
	// a protected VPN: changing or removing it needs a person's yes; turning
	// protection or --mfa off weakens a check
	wantCode(t, "PROTECTED_TARGET", "vpn", "edit", "lab", "--notes", "x")
	wantCode(t, "PROTECTED_TARGET", "vpn", "rm", "lab")
	wantCode(t, "PROTECTED_TARGET", "vpn", "rm", "@office")
	wantCode(t, "SAFETY_SETTING", "vpn", "edit", "lab", "--protected=false")
	wantCode(t, "PROTECTED_TARGET", "vpn", "add", "lab", "socks", "--proxy-address", "127.0.0.1:1082", "--overwrite")
	_, e := invRun(t, "--dry-run", "vpn", "rm", "@office")
	if e != nil {
		t.Errorf("dry run: %+v", e)
	}
	mustRun(t, "vpn", "add", "sso", "socks", "--proxy-address", "127.0.0.1:1083", "--mfa")
	wantCode(t, "SAFETY_SETTING", "vpn", "edit", "sso", "--mfa=false")
	if d := mustRun(t, "vpn", "rm", "sso"); d["removed"] != "sso" {
		t.Errorf("rm one: %v", d)
	}
}
