package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// An export file cannot turn on a safety-lowering setting that host edit
// and vpn edit ask a person for: lending the ssh-agent to a server, old
// IKEv1 ciphers and PAP for a VPN.
func TestImportSafetySettingsNeedAPerson(t *testing.T) {
	stored := func(t *testing.T) *store.State {
		t.Helper()
		closeStoreAtEnd(t)
		st, err := loadState()
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	for _, c := range []struct{ name, file string }{
		{"forward_agent new", `{"format":"komando-export/1","hosts":[{"name":"newhost","address":"203.0.113.7","forward_agent":true}]}`},
		{"forward_agent overwrite", `{"format":"komando-export/1","hosts":[{"name":"bast1","address":"10.0.0.9","user":"ops","forward_agent":true}]}`},
		{"legacy_crypto", `{"format":"komando-export/1","vpns":[{"name":"office","kind":"l2tp","server":"203.0.113.9","legacy_crypto":true}]}`},
		{"allow_pap", `{"format":"komando-export/1","vpns":[{"name":"office","kind":"l2tp","server":"203.0.113.9","allow_pap":true}]}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			invHome(t)
			mustRun(t, "host", "add", "bast1", "ops@10.0.0.9")
			f := writeTemp(t, "exp.json", c.file)
			n := asAgent(t, false, true)
			wantCode(t, "SAFETY_SETTING", "import", "komando", f, "--overwrite")
			st := stored(t)
			if st.Hosts["newhost"] != nil || st.Hosts["bast1"].ForwardAgent || st.Vpns["office"] != nil {
				t.Fatalf("imported without a person's yes: hosts %v vpns %v", st.Hosts, st.Vpns)
			}
			if *n != 0 {
				t.Fatalf("a window opened without --yes: %d", *n)
			}
			// the person says yes in the window
			asAgent(t, true, true)
			tcl.flags.yes = true
			if _, e := invRun(t, "import", "komando", f, "--overwrite", "--yes"); e != nil {
				t.Fatalf("with the person's yes: %+v", e)
			}
		})
	}
	// a server that already lends the agent keeps it with no question
	invHome(t)
	mustRun(t, "host", "add", "bast1", "ops@10.0.0.9")
	if err := store.Update(tcl.storeWrite(), func(s *store.State) error { s.Hosts["bast1"].ForwardAgent = true; return nil }); err != nil {
		t.Fatal(err)
	}
	asAgent(t, false, true)
	mustRun(t, "import", "komando", writeTemp(t, "exp.json", `{"format":"komando-export/1","hosts":[{"name":"bast1","address":"10.0.0.9","user":"ops","forward_agent":true}]}`), "--overwrite")
	if !stored(t).Hosts["bast1"].ForwardAgent {
		t.Fatal("forward_agent dropped")
	}
}

// Replacing a VPN by import asks what vpn edit would: a protected VPN is
// left as it is without --yes, and a CA it no longer checks against or
// --mfa turned off needs a person's yes. Settings in the file are never
// applied (host_key_policy off stays a suggestion).
func TestImportReplacingAVpnNeedsAPerson(t *testing.T) {
	ca := "-----BEGIN CERTIFICATE-----\nMIIA\n-----END CERTIFICATE-----\n"
	setup := func(t *testing.T, edit func(v *store.Vpn)) {
		t.Helper()
		invHome(t)
		noAgent(t)
		mustRun(t, "vpn", "add", "cloud", "ikev2", "--server", "vpn.example.com", "--user", "alice")
		if err := store.Update(tcl.storeWrite(), func(s *store.State) error { edit(s.Vpns["cloud"]); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	file := `{"format":"komando-export/1","vpns":[{"name":"cloud","kind":"ikev2","server":"vpn.example.com","user":"alice"}]}`
	t.Run("protected", func(t *testing.T) {
		setup(t, func(v *store.Vpn) { v.Protected = true; v.Notes = "keep" })
		asAgent(t, false, true)
		d, e := invRun(t, "import", "komando", writeTemp(t, "exp.json", file), "--overwrite")
		if e != nil || len(d["vpns"].([]any)) != 0 {
			t.Fatalf("import: %v %+v", d, e)
		}
		if st, _ := loadState(); st.Vpns["cloud"].Notes != "keep" || !st.Vpns["cloud"].Protected {
			t.Fatalf("a protected VPN was replaced: %+v", st.Vpns["cloud"])
		}
		closeStoreAtEnd(t)
	})
	for name, edit := range map[string]func(v *store.Vpn){
		"ca":  func(v *store.Vpn) { v.CA = ca },
		"mfa": func(v *store.Vpn) { v.MFA = true },
	} {
		t.Run(name, func(t *testing.T) {
			setup(t, edit)
			asAgent(t, false, true)
			wantCode(t, "SAFETY_SETTING", "import", "komando", writeTemp(t, "exp.json", file), "--overwrite")
			st, _ := loadState()
			closeStoreAtEnd(t)
			if v := st.Vpns["cloud"]; v.CA == "" && !v.MFA {
				t.Fatalf("replaced without a person's yes: %+v", v)
			}
		})
	}
	t.Run("settings", func(t *testing.T) {
		invHome(t)
		asAgent(t, false, true)
		mustRun(t, "import", "komando", writeTemp(t, "exp.json", `{"format":"komando-export/1","settings":{"host_key_policy":"off","audit":"off"}}`))
		st, _ := loadState()
		closeStoreAtEnd(t)
		if st.Settings.HostKeyPolicy == "off" {
			t.Fatal("an imported setting was applied")
		}
	})
}

// A dry run records the stop the real run hits: a server whose proxy
// command the real import leaves out (an AI agent without --yes; a
// destructive command without --allow-dangerous) shows that stop in the
// preview's would_be_blocked.
func TestImportDryRunRecordsTheProxyCommandStop(t *testing.T) {
	for _, tc := range []struct{ name, proxy, code string }{
		{"a proxy command", "nc %h %p", "SAFETY_SETTING"},
		{"a destructive proxy command", "rm -rf /", "POLICY_BLOCKED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invHome(t)
			f := filepath.Join(t.TempDir(), "ssh_config")
			if err := os.WriteFile(f, []byte("Host imp\n  HostName 10.0.0.7\n  ProxyCommand "+tc.proxy+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			setCallerEnv(t, "CLAUDECODE", "1")
			d, _ := invRun(t, "import", "ssh-config", f, "--dry-run")
			tcl.flags.dryRun = false
			if blockedCode(d) != tc.code {
				t.Fatalf("want %s in would_be_blocked: %v", tc.code, d)
			}
		})
	}
}
