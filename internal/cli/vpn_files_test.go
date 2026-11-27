package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// certPEM is a throwaway self-signed CA certificate in PEM.
func certPEM(t *testing.T) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now(),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// vpn add --config takes a file whose secrets go to the vault, so an AI
// agent may name any file, but no error may quote its text: the first
// word of a .pgpass or a token file used to come back in POLICY_BLOCKED.
// komando's own folder is refused outright.
func TestVpnConfigErrorsQuoteNoContent(t *testing.T) {
	invHome(t)
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	dir := t.TempDir()
	pgpass := filepath.Join(dir, "pgpass")
	os.WriteFile(pgpass, []byte("db.internal:5432:app:app:PgDummyPw77\n"), 0o600)
	for _, kind := range []string{"openvpn", "wireguard"} {
		_, e := invRun(t, "--dry-run", "vpn", kind, "add", "x", "--config", pgpass, "--check", "10.0.0.1:22")
		if e == nil || strings.Contains(e.Message+e.Hint, "PgDummyPw77") || strings.Contains(e.Message+e.Hint, "db.internal") {
			t.Fatalf("%s: %+v", kind, e)
		}
	}
	tok := store.Path("zz-token")
	os.WriteFile(tok, []byte("s3cretvalue123\n"), 0o600)
	if e := wantCode(t, "SENSITIVE_FILE", "--dry-run", "vpn", "openvpn", "add", "x", "--config", tok, "--check", "10.0.0.1:22"); strings.Contains(e.Message, "s3cret") {
		t.Fatal(e.Message)
	}
	// a known refused option is still named, for the person to fix
	up := filepath.Join(dir, "up.ovpn")
	os.WriteFile(up, []byte("client\nup /tmp/x.sh\n"), 0o600)
	if _, e := invRun(t, "--dry-run", "vpn", "openvpn", "add", "x", "--config", up, "--check", "10.0.0.1:22"); e == nil || !strings.Contains(e.Message, `"up" is not allowed`) {
		t.Fatalf("a known option: %+v", e)
	}
}

// --ca is read as any local file (SENSITIVE_FILE for an agent on a secret
// file) and keeps only the certificates: an .ovpn profile with a static
// key and a login used to be stored and shown whole.
func TestVpnCAKeepsOnlyCertificates(t *testing.T) {
	invHome(t)
	dir := t.TempDir()
	ca := certPEM(t)
	profile := filepath.Join(dir, "client.ovpn")
	os.WriteFile(profile, []byte("client\n<ca>\n"+ca+"</ca>\n<tls-crypt>\n-----BEGIN OpenVPN Static key V1-----\n6b3f0e1a\n-----END OpenVPN Static key V1-----\n</tls-crypt>\n<auth-user-pass>\nalice\nZZ-dummy-vpn-pw-4711\n</auth-user-pass>\n"), 0o600)
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	wantCode(t, "SENSITIVE_FILE", "--dry-run", "vpn", "ikev2", "add", "x", "--server", "vpn.example.com", "--user", "alice", "--ca", profile)
	noAgent(t)
	d := mustRun(t, "--dry-run", "vpn", "ikev2", "add", "x", "--server", "vpn.example.com", "--user", "alice", "--ca", profile)
	got, _ := d["would_add"].(map[string]any)["ca"].(string)
	if got != ca {
		t.Fatalf("ca kept %q", got)
	}
	notCA := filepath.Join(dir, "notes.txt")
	os.WriteFile(notCA, []byte("hello\n"), 0o600)
	wantCode(t, "USAGE", "--dry-run", "vpn", "ikev2", "add", "x", "--server", "vpn.example.com", "--user", "alice", "--ca", notCA)
}

// A VPN without a stored login gets the one a person types at `vpn up`.
// An AI agent that moves where it goes would get that login, so the move
// is for a person: NEEDS_PERSON, and no window. A stored reference keeps
// its SECRET_DESTINATION; other edits go on.
func TestVpnTypedLoginMoveNeedsAPerson(t *testing.T) {
	invHome(t)
	noAgent(t)
	mustRun(t, "vpn", "globalprotect", "add", "corp", "--portal", "vpn.corp.example", "--user", "alice", "--mfa")
	mustRun(t, "vpn", "ikev2", "add", "cloud", "--server", "vpn.corp.example", "--user", "alice")
	texts := windowText(t, false)
	for _, args := range [][]string{
		{"vpn", "globalprotect", "edit", "corp", "--portal", "vpn.attacker.example"},
		{"vpn", "ikev2", "edit", "cloud", "--server", "vpn.attacker.example"},
	} {
		e := wantCode(t, "NEEDS_PERSON", args...)
		if e.Exit != 6 {
			t.Fatalf("%v: exit %d", args, e.Exit)
		}
		if want := "komando vpn " + args[1] + " edit"; !strings.Contains(e.Hint, want) || !strings.Contains(e.Message, "vpn "+args[1]+" start") {
			t.Errorf("%v: the hint names %q and the message the start of that kind: %q, %q", args, want, e.Hint, e.Message)
		}
	}
	if len(*texts) != 0 {
		t.Fatalf("a window: %q", *texts)
	}
	// an --mfa VPN with a stored password: a person types the code, so
	// its move is for a person too, not an approvable SECRET_DESTINATION
	noAgent(t)
	mustRun(t, "vpn", "ikev2", "add", "mfa", "--server", "vpn.corp.example", "--user", "alice", "--credential", "db-pass", "--mfa")
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	wantCode(t, "NEEDS_PERSON", "vpn", "ikev2", "edit", "mfa", "--server", "vpn.attacker.example")
	mustRun(t, "vpn", "globalprotect", "edit", "corp", "--notes", "head office")
	st, _ := store.Load()
	if st.Vpns["corp"].Portal != "vpn.corp.example" || st.Vpns["cloud"].Server != "vpn.corp.example" {
		t.Fatal("a refused move was saved")
	}
}

// A Tailscale VPN replaced by `vpn add --overwrite` or an import starts
// with a fresh node: the old one's keys must not carry over to it.
func TestReplacedTailscaleStartsFresh(t *testing.T) {
	invHome(t)
	noAgent(t)
	stateOf := func(name string) (string, bool) {
		st, _ := store.Load()
		v := st.Vpns[name]
		id := v.Rec.ID
		if id == "" {
			id = "name:" + v.Name
		}
		_, ok, _ := store.VPNState(id, "_machinekey")
		return id, ok
	}
	plant := func(name string) {
		id, _ := stateOf(name)
		if err := store.SetVPNState(id, map[string][]byte{"_machinekey": []byte("old node")}); err != nil {
			t.Fatal(err)
		}
	}
	mustRun(t, "vpn", "tailscale", "add", "tnet")
	plant("tnet")
	mustRun(t, "vpn", "tailscale", "add", "tnet", "--overwrite")
	if _, ok := stateOf("tnet"); ok {
		t.Fatal("vpn add --overwrite kept the old node state")
	}
	plant("tnet")
	file := writeTemp(t, "exp.json", `{"format":"komando-export/1","vpns":[{"name":"tnet","kind":"tailscale","mfa":true}]}`)
	mustRun(t, "import", "komando", file, "--overwrite")
	if _, ok := stateOf("tnet"); ok {
		t.Fatal("import --overwrite kept the old node state")
	}
}

// import --overwrite must not do what vpn edit may not: move a VPN whose
// login a person types somewhere else, for an AI agent.
func TestImportMovesNoTypedLogin(t *testing.T) {
	invHome(t)
	noAgent(t)
	mustRun(t, "vpn", "globalprotect", "add", "corp", "--portal", "vpn.corp.example", "--user", "alice", "--mfa")
	windowText(t, false)
	file := writeTemp(t, "exp.json", `{"format":"komando-export/1","vpns":[{"name":"corp","kind":"globalprotect","portal":"vpn.attacker.example","user":"alice","mfa":true}]}`)
	wantCode(t, "NEEDS_PERSON", "import", "komando", file, "--overwrite")
	if st, _ := store.Load(); st.Vpns["corp"].Portal != "vpn.corp.example" {
		t.Fatalf("the portal moved to %q", st.Vpns["corp"].Portal)
	}
}

// The hints of VPN_DOWN, VPN_STOP_FAILED and NEEDS_PERSON name the path of
// the VPN's own kind. A session left from a removed VPN has no kind, and its
// stop hint names no path.
func TestVpnHintsNameTheKindsPath(t *testing.T) {
	invHome(t)
	mustRun(t, "vpn", "socks", "add", "office", "--proxy-address", "127.0.0.1:1")
	if got := vpnKindWord("office"); got != "socks" {
		t.Errorf("the kind of office is %q, want socks", got)
	}
	if got := vpnKindWord("gone"); got != "KIND" {
		t.Errorf("a VPN not saved gives %q, want the word KIND", got)
	}
	if got, want := vpnStopAgain("socks", "office"), "run `komando vpn socks stop office` again"; got != want {
		t.Errorf("stop hint: %q, want %q", got, want)
	}
	if got := vpnStopAgain("", "gone"); strings.Contains(got, "vpn  ") || strings.Contains(got, "KIND") || !strings.Contains(got, "stop again") {
		t.Errorf("a session of a removed VPN gets a hint with no path: %q", got)
	}
}

// A VPN is run by the path of its own kind. A selector that picks VPNs of
// two kinds is refused at the first one of another kind, and `add
// --overwrite` replaces a VPN of its own kind only (a VPN of another kind
// under that name is WRONG_KIND with the path that fits).
func TestVpnWrongKindOfSelectorAndOverwrite(t *testing.T) {
	invHome(t)
	mustRun(t, "vpn", "socks", "add", "lab", "--proxy-address", "127.0.0.1:1", "--tag", "mixed")
	mustRun(t, "vpn", "ikev2", "add", "cloud", "--server", "vpn.corp.example", "--user", "alice", "--tag", "mixed")
	if e := wantCode(t, "WRONG_KIND", "vpn", "socks", "remove", "tag:mixed", "--dry-run"); !strings.Contains(e.Hint, "komando vpn ikev2 remove cloud") {
		t.Errorf("a selector over two kinds: the hint names the path that fits: %q", e.Hint)
	}
	e := wantCode(t, "WRONG_KIND", "vpn", "ikev2", "add", "lab", "--server", "vpn.corp.example", "--user", "alice", "--overwrite", "--dry-run")
	if !strings.Contains(e.Hint, "komando vpn socks add lab") {
		t.Errorf("--overwrite of another kind: the hint names the path that fits: %q", e.Hint)
	}
	if st, _ := store.Load(); st.Vpns["lab"].Kind != "socks" {
		t.Errorf("the refused overwrite changed lab to %s", st.Vpns["lab"].Kind)
	}
	mustRun(t, "vpn", "socks", "add", "lab", "--proxy-address", "127.0.0.1:2", "--overwrite")
}
