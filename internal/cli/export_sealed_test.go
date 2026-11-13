package cli

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealfile"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

const sealPass = "a sealed file passphrase"

// sealPerson makes this test a person at a terminal who types these
// hidden answers, in order.
func sealPerson(t *testing.T, typed ...string) {
	t.Helper()
	savedI, savedR := tcl.terminal, readPassword
	tcl.terminal = true
	readPassword = func(*call, string) (string, error) {
		if len(typed) == 0 {
			t.Fatal("komando asked for more than the test typed")
		}
		s := typed[0]
		typed = typed[1:]
		return s, nil
	}
	t.Cleanup(func() { tcl.terminal, readPassword = savedI, savedR; resetApproval() })
}

// sealLab is a list with two servers, a conn, a key komando made and
// three secrets, one of them missing from the vault.
func sealLab(t *testing.T) {
	t.Helper()
	invHome(t)
	setSecret(t, "web1-pass", "s3cret value")
	setSecret(t, "shop-pass", "db s3cret")
	mustRun(t, "key", "gen", "deploy")
	mustRun(t, "host", "add", "web1", "u@10.0.0.5", "--password-ref", "secret:web1-pass", "--key", "deploy")
	mustRun(t, "host", "add", "web2", "u@10.0.0.6", "--password-ref", "secret:missing-pass")
	mustRun(t, "conn", "add", "shop", "postgres://app@db.example.com/shop", "--password-ref", "secret:shop-pass")
}

func TestExportSealedRoundTrip(t *testing.T) {
	sealLab(t)
	file := filepath.Join(t.TempDir(), "move.kmdseal")
	sealPerson(t, sealPass, sealPass)
	d := mustRun(t, "export", "--sealed", "--with-keys", "--to", file)
	if d["sealed"] != "passphrase" || asJSON(d["secrets_in_file"]) != `["shop-pass","web1-pass"]` || asJSON(d["keys_in_file"]) != `["deploy"]` ||
		asJSON(d["secrets_needed"]) != `["missing-pass"]` || len(d["check_phrase"].([]any)) != 6 {
		t.Fatalf("%v", d)
	}
	if strings.Contains(asJSON(d), "s3cret") {
		t.Fatal("a secret value in the output")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	// Unix mode bits mean nothing on Windows (it shows 0666 for every file)
	if fi, _ := os.Stat(file); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
	if strings.Contains(string(raw), "s3cret") || strings.Contains(string(raw), "web1") {
		t.Fatal("the file shows what it holds")
	}
	if got := sealfile.CheckPhrase(raw); asJSON(got) != asJSON(d["check_phrase"]) {
		t.Errorf("check phrase %v, the output says %v", got, d["check_phrase"])
	}
	h, _ := sealfile.ReadHeader(raw)
	if h.MadeBy != "komando "+Version || h.Mode != "passphrase" {
		t.Errorf("header %+v", h)
	}
	// on another computer: a new home, the passphrase typed once
	invHome(t)
	sealPerson(t, sealPass)
	d = mustRun(t, "import", "komando", file)
	if asJSON(d["hosts"]) != `["web1","web2"]` || asJSON(d["conns"]) != `["shop"]` || asJSON(d["secrets"]) != `["shop-pass","web1-pass"]` || asJSON(d["keys"]) != `["deploy"]` {
		t.Fatalf("%v", d)
	}
	if strings.Contains(asJSON(d), "s3cret") || !strings.Contains(asJSON(d["not_imported"]), "missing-pass") {
		t.Errorf("%v", d)
	}
	if v, err := vault.Get("web1-pass"); err != nil || v != "s3cret value" {
		t.Errorf("web1-pass: %q %v", v, err)
	}
	st, _ := store.Load()
	if h := st.Hosts["web1"]; h.Key != "deploy" || h.PasswordRef != "secret:web1-pass" {
		t.Errorf("web1 %+v", h)
	}
	if st.Conns["shop"].PasswordRef != "secret:shop-pass" {
		t.Errorf("shop %+v", st.Conns["shop"])
	}
	k := st.Keys["deploy"]
	if k == nil || !k.Managed || !store.SealedKey(k) || k.Fingerprint == "" {
		t.Fatalf("key %+v", k)
	}
	if b, err := store.ReadPrivateKey(k); err != nil || !strings.Contains(string(b), "PRIVATE KEY") {
		t.Errorf("private key: %v", err)
	}
	// the same file again changes nothing
	sealPerson(t, sealPass)
	d = mustRun(t, "import", "komando", file)
	if asJSON(d["hosts"]) != `[]` || asJSON(d["secrets"]) != `[]` || d["keys"] != nil {
		t.Errorf("second import: %v", d)
	}
}

// A secret that is here with another value stays, and the servers of the
// file do not get it; --overwrite replaces it after the person's yes.
func TestImportSealedKeepsOtherSecrets(t *testing.T) {
	sealLab(t)
	file := filepath.Join(t.TempDir(), "move.kmdseal")
	sealPerson(t, sealPass, sealPass)
	mustRun(t, "export", "--sealed", "--to", file)
	invHome(t)
	setSecret(t, "web1-pass", "mine")
	sealPerson(t, sealPass)
	d := mustRun(t, "import", "komando", file)
	if v, _ := vault.Get("web1-pass"); v != "mine" || strings.Contains(asJSON(d["secrets"]), "web1-pass") {
		t.Fatalf("%v (web1-pass %q)", d, v)
	}
	if st, _ := store.Load(); st.Hosts["web1"].PasswordRef != "" {
		t.Errorf("web1 points at this computer's secret: %+v", st.Hosts["web1"])
	}
	if !strings.Contains(asJSON(d["not_imported"]), "web1-pass: kept the value here") {
		t.Errorf("%v", d["not_imported"])
	}
	sealPerson(t, sealPass)
	personAnswers(t, "y\n")
	d = mustRun(t, "import", "komando", file, "--overwrite")
	if v, _ := vault.Get("web1-pass"); v != "s3cret value" || !strings.Contains(asJSON(d["secrets"]), "web1-pass") {
		t.Fatalf("%v (web1-pass %q)", d, v)
	}
	if st, _ := store.Load(); st.Hosts["web1"].PasswordRef != "secret:web1-pass" {
		t.Errorf("web1 %+v", st.Hosts["web1"])
	}
}

// Only a person at a terminal makes or opens a sealed file. An AI agent
// and a script get NEEDS_PERSON, which no flag lifts; a dry run says what
// would be sealed.
func TestSealedNeedsPerson(t *testing.T) {
	sealLab(t)
	file := filepath.Join(t.TempDir(), "move.kmdseal")
	sealed, err := sealfile.SealPassphrase([]byte(`{"format":"komando-export/1"}`), sealPass, sealfile.Made{By: "komando test"})
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "other.kmdseal")
	if err := os.WriteFile(other, sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, agent := range []bool{false, true} {
		if agent {
			t.Setenv("KOMANDO_AGENT", "1")
			resetApproval()
			t.Cleanup(resetApproval)
		}
		for _, args := range [][]string{{"export", "--sealed", "--to", file}, {"export", "--for-phone", "--to", file, "--yes"}, {"import", "komando", other}} {
			if e := wantCode(t, "NEEDS_PERSON", args...); e.Exit != out.ExitPolicy || strings.Contains(e.Hint, "add the flag") {
				t.Errorf("agent %v %v: %+v", agent, args, e)
			}
		}
		if _, err := os.Stat(file); err == nil {
			t.Fatal("a file was written")
		}
		d := mustRun(t, "export", "--sealed", "--with-keys", "--to", file, "--dry-run")
		if d["dry_run"] != true || asJSON(d["secrets_in_file"]) != `["shop-pass","web1-pass"]` || asJSON(d["secrets_needed"]) != `["missing-pass"]` ||
			asJSON(d["keys_in_file"]) != `["deploy"]` {
			t.Errorf("agent %v dry run: %v", agent, d)
		}
		if wb, _ := d["_meta"].(map[string]any)["would_be_blocked"].(map[string]any); wb["code"] != "NEEDS_PERSON" {
			t.Errorf("agent %v dry run: %v", agent, d["_meta"])
		}
		if strings.Contains(asJSON(d), "s3cret") {
			t.Error("a secret value in the dry run")
		}
		d = mustRun(t, "import", "komando", other, "--dry-run")
		if wb, _ := d["_meta"].(map[string]any)["would_be_blocked"].(map[string]any); wb["code"] != "NEEDS_PERSON" || !strings.Contains(asJSON(d["not_imported"]), "sealed") {
			t.Errorf("agent %v import dry run: %v", agent, d)
		}
	}
}

func TestExportSealedFlags(t *testing.T) {
	sealLab(t)
	file := filepath.Join(t.TempDir(), "f")
	for _, args := range [][]string{
		{"export", "--sealed", "--for-phone", "--to", file},
		{"export", "--with-keys", "--to", file},
		{"export", "--sealed"},
		{"export", "--for-phone", "--to", "-"},
	} {
		wantCode(t, "USAGE", args...)
	}
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sealPerson(t)
	wantCode(t, "FILE_EXISTS", "export", "--sealed", "--to", file)
}

// A short passphrase or two that differ: nothing is written.
func TestExportSealedPassphraseRules(t *testing.T) {
	sealLab(t)
	file := filepath.Join(t.TempDir(), "f")
	for code, typed := range map[string][]string{
		"WEAK_PASSPHRASE":     {"too short"},
		"PASSPHRASE_MISMATCH": {sealPass, sealPass + "!"},
	} {
		sealPerson(t, typed...)
		wantCode(t, code, "export", "--sealed", "--to", file)
		if _, err := os.Stat(file); err == nil {
			t.Fatalf("%s: a file was written", code)
		}
	}
}

// A wrong passphrase, a changed or cut file, a newer version and a file
// for the phone are each refused, with nothing imported.
func TestImportSealedRefused(t *testing.T) {
	sealLab(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "move.kmdseal")
	sealPerson(t, sealPass, sealPass)
	mustRun(t, "export", "--sealed", "--to", file)
	raw, _ := os.ReadFile(file)
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	body := slices.Clone(raw)
	body[len(body)-40] ^= 1
	header := []byte(strings.Replace(string(raw), `"compression":"deflate"`, `"compression":"deflatE"`, 1))
	when := []byte(strings.Replace(string(raw), `"created_at":"2`, `"created_at":"3`, 1))
	newer := []byte(strings.Replace(string(raw), `{"v":1,`, `{"v":2,`, 1))
	k, _ := ecdh.X25519().GenerateKey(rand.Reader)
	phone, _ := sealfile.SealRecipient([]byte(`{}`), k.PublicKey().Bytes(), sealfile.Made{})
	invHome(t)
	for _, c := range []struct {
		code, file, pass string
	}{
		{"WRONG_PASSPHRASE", file, "not the passphrase at all"},
		{"WRONG_PASSPHRASE", write("body", body), sealPass},
		{"WRONG_PASSPHRASE", write("when", when), sealPass},
		{"SEALED_FILE_UNSUPPORTED", write("header", header), sealPass},
		{"SEALED_FILE_INVALID", write("cut", raw[:30]), sealPass},
		{"SEALED_FILE_UNSUPPORTED", write("newer", newer), sealPass},
		{"SEALED_FILE_UNSUPPORTED", write("phone", phone), sealPass},
	} {
		sealPerson(t, c.pass)
		e := wantCode(t, c.code, "import", "komando", c.file)
		if strings.Contains(e.Message, sealPass) {
			t.Errorf("%s: the passphrase in the message", c.file)
		}
	}
	if st, _ := store.Load(); len(st.Hosts) != 0 {
		t.Errorf("imported: %v", st.Hosts)
	}
	if _, err := vault.Get("web1-pass"); err != vault.ErrNotFound {
		t.Errorf("a secret came in: %v", err)
	}
}

// phoneAnswers makes this test a person who gives the phone's key and
// types the key check.
func phoneAnswers(t *testing.T, key, check string) {
	t.Helper()
	saved := readPhoneAnswer
	answers := []string{key, check}
	readPhoneAnswer = func(*call, string, bool) (string, error) {
		s := answers[0]
		answers = answers[1:]
		return s, nil
	}
	t.Cleanup(func() { readPhoneAnswer = saved })
	sealPerson(t)
}

func TestExportForPhone(t *testing.T) {
	sealLab(t)
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := k.PublicKey().Bytes()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "phone.key")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id := sealfile.KeyID(pub)
	var grouped []string
	for i := 0; i < len(id); i += 4 {
		grouped = append(grouped, strings.ToUpper(id[i:i+4]))
	}
	file := filepath.Join(dir, "phone.kmdseal")
	// a key check that does not match: nothing is written
	phoneAnswers(t, keyFile, strings.Repeat("0", 64))
	wantCode(t, "PHONE_KEY_INVALID", "export", "--for-phone", "--to", file)
	phoneAnswers(t, filepath.Join(dir, "nothing-here"), id)
	wantCode(t, "PHONE_KEY_INVALID", "export", "--for-phone", "--to", file)
	if _, err := os.Stat(file); err == nil {
		t.Fatal("a file was written")
	}
	phoneAnswers(t, keyFile, strings.Join(grouped, " "))
	d := mustRun(t, "export", "--for-phone", "--to", file)
	if d["sealed"] != "recipient" || d["phone_key_id"] != id || len(d["check_phrase"].([]any)) != 6 {
		t.Fatalf("%v", d)
	}
	raw, _ := os.ReadFile(file)
	content, h, err := sealfile.OpenRecipient(raw, k.Bytes())
	if err != nil || h.KEM.KeyID != id {
		t.Fatal(err)
	}
	var c sealedContent
	if err := json.Unmarshal(content, &c); err != nil || c.Format != exportFormat || c.SecretValues["web1-pass"] != "s3cret value" || len(c.Hosts) != 2 || len(c.KeyTexts) != 0 {
		t.Fatalf("%+v %v", c, err)
	}
	// the key given as text, the check in lower case
	phoneAnswers(t, base64.StdEncoding.EncodeToString(pub), id)
	mustRun(t, "export", "--for-phone", "--to", file, "--overwrite")
}

func TestReadPhoneKey(t *testing.T) {
	pub := make([]byte, 32)
	pub[0] = 9
	raw := filepath.Join(t.TempDir(), "raw")
	if err := os.WriteFile(raw, pub, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{raw, base64.StdEncoding.EncodeToString(pub), base64.RawURLEncoding.EncodeToString(pub), "09" + strings.Repeat("00", 31)} {
		if k, err := readPhoneKey(in); err != nil || k[0] != 9 {
			t.Errorf("%q: %v", in, err)
		}
	}
	for _, in := range []string{"", "short", base64.StdEncoding.EncodeToString(pub[:31])} {
		if _, err := readPhoneKey(in); err == nil {
			t.Errorf("%q taken", in)
		}
	}
	id := sealfile.KeyID(pub)
	if !sameKeyCheck(" "+strings.ToUpper(id[:8])+"-"+id[8:]+"\n", pub) || sameKeyCheck(id[:60], pub) {
		t.Error("sameKeyCheck")
	}
}
