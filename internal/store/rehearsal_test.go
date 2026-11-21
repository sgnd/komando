//go:build rehearsal

package store

// The rehearsal of the store's format 1 → 2 upgrade (C187 D, #373): the
// last release before #373 makes synthetic stores, the komando of this
// tree opens them. It builds both binaries into temp folders and runs
// every command in a throwaway home with KOMANDO_KEYCHAIN=off,
// KOMANDO_NO_DIALOG=1 and an environment of its own (no AI agent
// variables, so komando follows HOME and KOMANDO_HOME). It never touches
// the real home, the keychain or a window. It stays out of the normal
// suite and CI; run it by hand before a tag:
//
//	go test -p 1 -tags rehearsal -timeout 60m -run Rehearsal -v ./internal/store/
//
// KOMANDO_REHEARSAL_OLD names the old release (default: the newest tag
// without #373's merge); KOMANDO_REHEARSAL_OUT, a file for the results
// table.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/testhome"
)

// policyMerge is #373's merge: the old binary is the newest tag before it.
const policyMerge = "d456044e"

const (
	sshPass   = "rehearsal-ssh-pw"
	vaultPass = "rehearsal-vault-pass-0123456789"
)

type rehearsalBins struct {
	old, seed, new, dir          string
	oldRef, oldCommit, newCommit string
}

type rehearsalRow struct{ fixture, step, status, note string }

var rehearsalRows []rehearsalRow

// record notes a step's outcome; a fail also fails the test.
func record(t *testing.T, fixture, step, status, format string, args ...any) {
	t.Helper()
	note := fmt.Sprintf(format, args...)
	rehearsalRows = append(rehearsalRows, rehearsalRow{fixture, step, status, note})
	t.Logf("RESULT | %s | %s | %s | %s", fixture, step, status, note)
	if status == "fail" {
		t.Errorf("%s step %s: %s", fixture, step, note)
	}
}

func passFail(ok bool) string {
	if ok {
		return "pass"
	}
	return "fail"
}

func TestRehearsal(t *testing.T) {
	b := buildRehearsalBins(t)
	record(t, "all", "binaries", "pass", "old %s (%s), new %s", b.oldRef, b.oldCommit, b.newCommit)
	srv := startRehearsalSSH(t)

	t.Run("F1", func(t *testing.T) {
		record(t, "F1", "all", "skipped", "keychain mode: komando has no fake keychain backend, and the login keychain is never touched; the upgrade path is the same for every key mode (only the master key's source differs), so F2 and F3 cover it")
		t.Skip("keychain mode: no fake keychain backend")
	})
	for _, f := range []rehearsalFixture{
		{name: "F2", tunnel: true},
		{name: "F3", pass: vaultPass},
		{name: "F4", large: true},
	} {
		t.Run(f.name, func(t *testing.T) { rehearseFixture(t, b, srv, f) })
	}
	if out := os.Getenv("KOMANDO_REHEARSAL_OUT"); out != "" {
		var sb strings.Builder
		sb.WriteString("| Fixture | Step | Result | Note |\n|---|---|---|---|\n")
		for _, r := range rehearsalRows {
			fmt.Fprintf(&sb, "| %s | %s | %s | %s |\n", r.fixture, r.step, r.status, strings.ReplaceAll(r.note, "|", "\\|"))
		}
		if err := os.WriteFile(out, []byte(sb.String()), 0o600); err != nil {
			t.Error(err)
		}
	}
}

// ---- binaries

func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	c := exec.Command("git", args...)
	c.Dir = dir
	b, err := c.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(string(b))
}

func goBuild(t *testing.T, dir, out, pkg string) {
	t.Helper()
	c := exec.Command("go", "build", "-o", out, pkg)
	c.Dir = dir
	if b, err := c.CombinedOutput(); err != nil {
		t.Fatalf("go build %s in %s: %v\n%s", pkg, dir, err, b)
	}
}

func buildRehearsalBins(t *testing.T) rehearsalBins {
	root := gitOut(t, ".", "rev-parse", "--show-toplevel")
	ref := os.Getenv("KOMANDO_REHEARSAL_OLD")
	if ref == "" {
		ref, _, _ = strings.Cut(gitOut(t, root, "tag", "--sort=-v:refname", "--no-contains", policyMerge, "--list", "v*"), "\n")
	}
	b := rehearsalBins{dir: t.TempDir(), oldRef: ref,
		oldCommit: gitOut(t, root, "rev-parse", ref+"^{commit}"), newCommit: gitOut(t, root, "rev-parse", "HEAD")}
	if gitOut(t, root, "status", "--porcelain", "--untracked-files=no", "--", ".", ":!internal/store/rehearsal_test.go") != "" {
		b.newCommit += " (with uncommitted changes)"
	}
	src := t.TempDir()
	archive := exec.Command("git", "archive", "--format=tar", ref)
	archive.Dir = root
	untar := exec.Command("tar", "-x", "-C", src)
	pipe, err := archive.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	untar.Stdin = pipe
	if err := untar.Start(); err != nil {
		t.Fatal(err)
	}
	if err := archive.Run(); err != nil {
		t.Fatalf("git archive %s: %v", ref, err)
	}
	if err := untar.Wait(); err != nil {
		t.Fatalf("tar: %v", err)
	}
	seedDir := filepath.Join(src, "cmd", "rehearsal-seed")
	if err := os.MkdirAll(seedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(seedDir, "main.go"), []byte(seedSource), 0o644); err != nil {
		t.Fatal(err)
	}
	// both are named komando, as after an update in place: komando knows
	// its background processes by the program's name
	b.old, b.seed, b.new = filepath.Join(b.dir, "old", "komando"), filepath.Join(b.dir, "seed-old"), filepath.Join(b.dir, "new", "komando")
	goBuild(t, src, b.old, "./cmd/komando")
	goBuild(t, src, b.seed, "./cmd/rehearsal-seed")
	goBuild(t, root, b.new, "./cmd/komando")
	// the first start of a new binary is slow on macOS (it is checked
	// once): not part of the timings
	warm := newRehearsalHome(t)
	for _, bin := range []string{b.old, b.new} {
		for i := 0; i < 2; i++ {
			mustK(t, bin, warm, "", nil, "version")
		}
	}
	return b
}

// seedSource is built inside the old release's tree: it writes what the
// old komando's commands cannot make without a server or a person
// (revoked host keys, many pins, a long audit log, a VPN session that
// gives runtime.json its mark), through the old release's own code.
const seedSource = `package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	_ "github.com/sgnd/komando/internal/vault"
)

func main() {
	if len(os.Args) != 3 {
		fail(fmt.Errorf("usage: rehearsal-seed OP N"))
	}
	n, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fail(err)
	}
	switch os.Args[1] {
	case "hosts":
		err = hosts(n)
	case "pins":
		err = pins(n)
	case "revoke":
		err = revoke(n)
	case "audit":
		err = audit(n)
	case "session":
		err = session(n)
	case "approvalstep":
		err = store.Update(store.Save(), func(s *store.State) error { s.Settings.ApprovalCodeStep = int64(n); return nil })
	default:
		err = fmt.Errorf("unknown op %q", os.Args[1])
	}
	store.Close()
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "rehearsal-seed:", err)
	os.Exit(1)
}

func newKey() (ssh.PublicKey, error) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewPublicKey(pub)
}

func bulkAddr(i int) string { return fmt.Sprintf("10.8.%d.%d", i/250, i%250+1) }

func hosts(n int) error {
	now := time.Now().UTC()
	return store.Update(store.Save(), func(s *store.State) error {
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("bulk-%03d", i)
			s.Hosts[name] = &store.Host{Name: name, Address: bulkAddr(i), User: "root", Protected: i%5 == 0,
				Groups: []string{"bulk"}, CreatedAt: now, UpdatedAt: now}
		}
		return nil
	})
}

func pins(n int) error {
	d, err := store.DB(true)
	if err != nil {
		return err
	}
	return d.Update(context.Background(), func(tx *sealdb.Tx) error {
		for i := 0; i < n; i++ {
			k, err := newKey()
			if err != nil {
				return err
			}
			line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
			b, err := json.Marshal(map[string]any{"addr": knownhosts.Normalize(bulkAddr(i) + ":22"), "keys": []string{line}})
			if err != nil {
				return err
			}
			if _, err := tx.Put("pin", "", b); err != nil {
				return err
			}
		}
		return nil
	})
}

func revoke(n int) error {
	var keys []ssh.PublicKey
	for i := 0; i < n; i++ {
		k, err := newKey()
		if err != nil {
			return err
		}
		keys = append(keys, k)
	}
	return sshx.RevokeHostKeys(keys)
}

func audit(n int) error {
	d, err := store.DB(true)
	if err != nil {
		return err
	}
	for done := 0; done < n; done += 500 {
		err := d.Update(context.Background(), func(tx *sealdb.Tx) error {
			for i := done; i < n && i < done+500; i++ {
				b, err := json.Marshal(map[string]any{"actor": "rehearsal", "command": "host.edit", "dry_run": false,
					"hosts": []string{fmt.Sprintf("bulk-%03d", i%500)}, "ok": true, "ts": time.Now().UTC()})
				if err != nil {
					return err
				}
				if err := tx.AppendAudit(b); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func session(pid int) error {
	now := time.Now().UTC()
	return store.UpdateRuntime(store.Save(), func(s *store.State) error {
		if s.Sessions == nil {
			s.Sessions = map[string]*store.VpnSession{}
		}
		s.Sessions["vp2"] = &store.VpnSession{Vpn: "vp2", PID: pid, Exe: "/bin/sleep", ProcStart: netx.ProcessStart(pid), StartedAt: now, LastUsed: now}
		return nil
	})
}
`

// ---- running komando

type runResult struct {
	ok       bool
	code     string
	message  string
	data     json.RawMessage
	stdout   string
	stderr   string
	exit     int
	duration time.Duration
}

// newRehearsalHome makes a throwaway home in the temp folder.
func newRehearsalHome(t *testing.T) string {
	t.Helper()
	h := testhome.Path(t, t.TempDir())
	if err := os.MkdirAll(filepath.Join(h, "tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	return h
}

func komandoDir(h string) string { return filepath.Join(h, ".komando") }
func storeDB(h string) string    { return filepath.Join(komandoDir(h), StoreFile) }

// rehearsalEnv is the whole environment of a run: no variable of the
// test's own (an AI agent's would make komando read the account's real
// home), HOME and KOMANDO_HOME in the throwaway home.
func rehearsalEnv(h, pass string, extra ...string) []string {
	env := []string{
		"PATH=/usr/bin:/bin", "HOME=" + h, "KOMANDO_HOME=" + komandoDir(h), "TMPDIR=" + filepath.Join(h, "tmp"),
		"USER=rehearsal", "KOMANDO_KEYCHAIN=off", "KOMANDO_NO_DIALOG=1", "KOMANDO_OUTPUT=json",
	}
	if pass != "" {
		env = append(env, "KOMANDO_VAULT_PASS="+pass)
	}
	return append(env, extra...)
}

func rehearsalCmd(ctx context.Context, bin, h, pass string, extra []string, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, bin, args...)
	c.Dir = h
	c.Env = rehearsalEnv(h, pass, extra...)
	c.Stdin = nil
	return c
}

func runK(t *testing.T, bin, h, pass string, extra []string, args ...string) runResult {
	t.Helper()
	testhome.Path(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c := rehearsalCmd(ctx, bin, h, pass, extra, args...)
	var so, se bytes.Buffer
	c.Stdout, c.Stderr = &so, &se
	start := time.Now()
	err := c.Run()
	r := runResult{stdout: so.String(), stderr: se.String(), duration: time.Since(start)}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		r.exit = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("%s %v: %v", filepath.Base(bin), args, err)
	}
	var doc struct {
		OK    bool            `json:"ok"`
		Data  json.RawMessage `json:"data"`
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(so.Bytes(), &doc) == nil {
		r.ok, r.data, r.code, r.message = doc.OK, doc.Data, doc.Error.Code, doc.Error.Message
	}
	if filepath.Base(bin) == "seed-old" {
		r.ok = err == nil
	}
	return r
}

func mustK(t *testing.T, bin, h, pass string, extra []string, args ...string) runResult {
	t.Helper()
	r := runK(t, bin, h, pass, extra, args...)
	if !r.ok {
		t.Fatalf("%s %v failed: exit %d %s %s\nstdout: %.600s\nstderr: %.600s", filepath.Base(bin), args, r.exit, r.code, r.message, r.stdout, r.stderr)
	}
	return r
}

// ---- files

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	testhome.Path(t, dst)
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		to := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return os.MkdirAll(to, info.Mode().Perm()|0o700)
		case !info.Mode().IsRegular():
			return nil // sockets and links: not part of a store copy
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(to, b, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
}

// storeSum is the SHA-256 of store.db and its write-ahead log.
func storeSum(t *testing.T, h string) string {
	t.Helper()
	s := sha256.New()
	for _, n := range []string{StoreFile, StoreFile + "-wal"} {
		b, err := os.ReadFile(filepath.Join(komandoDir(h), n))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		fmt.Fprintf(s, "%s:%d:", n, len(b))
		s.Write(b)
	}
	return hex.EncodeToString(s.Sum(nil))[:16]
}

func storeFormat(t *testing.T, h string) string {
	t.Helper()
	meta, err := sealdb.Peek(context.Background(), storeDB(h))
	if err != nil {
		t.Fatalf("peek %s: %v", storeDB(h), err)
	}
	return meta["format"]
}

// ---- the store, opened as komando does (the master key from the home's
// key file or the passphrase)

func rehearsalMaster(t *testing.T, h, pass string) []byte {
	t.Helper()
	meta, err := sealdb.Peek(context.Background(), storeDB(h))
	if err != nil {
		t.Fatal(err)
	}
	switch meta["key_mode"] {
	case "keyfile":
		b, err := os.ReadFile(filepath.Join(komandoDir(h), "store.key"))
		if err != nil || len(b) < 32 {
			t.Fatalf("key file: %v (%d bytes)", err, len(b))
		}
		return b[:32]
	case "passphrase":
		salt, err := hex.DecodeString(meta["salt"])
		n, nerr := strconv.Atoi(meta["scrypt_n"])
		if err != nil || nerr != nil {
			t.Fatalf("passphrase settings: %v %v", err, nerr)
		}
		k, err := scrypt.Key([]byte(pass), salt, n, 8, 1, 32)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	t.Fatalf("key mode %q", meta["key_mode"])
	return nil
}

// openRaw opens h's store with its format's row key, without the policy
// check: what a program that holds the row key could do.
func openRaw(t *testing.T, h, pass string) (*sealdb.DB, storeKeys, string) {
	t.Helper()
	format := storeFormat(t, h)
	ks, err := keysFor(rehearsalMaster(t, h, pass), format)
	if err != nil {
		t.Fatal(err)
	}
	d, err := sealdb.Open(context.Background(), storeDB(h), ks.row)
	if err != nil {
		t.Fatalf("open %s (format %s): %v", storeDB(h), format, err)
	}
	return d, ks, format
}

type storeDump struct {
	format  string
	records map[string]string // id → type + "\x00" + data
	audit   []string
	types   map[string]int
	policy  error // format 2: the policy check; nil when it matches
}

func recordTypes(t *testing.T, h string) []string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+storeDB(h)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT DISTINCT type FROM records`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// dumpStore opens every record and audit entry of h's store.
func dumpStore(t *testing.T, h, pass string) storeDump {
	t.Helper()
	types := recordTypes(t, h)
	d, ks, format := openRaw(t, h, pass)
	defer d.Close()
	dump := storeDump{format: format, records: map[string]string{}, types: map[string]int{}}
	err := d.View(context.Background(), func(tx *sealdb.Tx) error {
		for _, typ := range types {
			recs, err := tx.List(typ)
			if err != nil {
				return fmt.Errorf("type %s: %w", typ, err)
			}
			for _, r := range recs {
				dump.records[r.ID] = r.Type + "\x00" + string(r.Data)
				dump.types[typ]++
			}
		}
		rows, err := tx.Audit(0, 1<<30)
		if err != nil {
			return err
		}
		for _, a := range rows {
			dump.audit = append(dump.audit, string(a.Data))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("dump %s: %v", h, err)
	}
	if ks.policy != nil {
		dump.policy = d.SetPolicy(context.Background(), ks.policy)
	}
	return dump
}

// sameContent reports how after differs from before: every record and
// audit entry of before is in after, unchanged; after may add only the
// policy MAC (and audit entries of its own commands, at the end), and
// the change count goes up.
func sameContent(before, after storeDump) string {
	var diffs []string
	for id, v := range before.records {
		if strings.HasPrefix(v, "generation\x00") {
			continue // the store's change count: every write step raises it
		}
		if w, ok := after.records[id]; !ok {
			diffs = append(diffs, "record "+id+" lost")
		} else if w != v {
			diffs = append(diffs, "record "+id+" changed")
		}
	}
	for id, w := range after.records {
		if _, ok := before.records[id]; !ok && !strings.HasPrefix(w, "policymac\x00") {
			typ, _, _ := strings.Cut(w, "\x00")
			diffs = append(diffs, "record "+id+" ("+typ+") added")
		}
	}
	if len(after.audit) < len(before.audit) || !slices.Equal(before.audit, after.audit[:len(before.audit)]) {
		diffs = append(diffs, fmt.Sprintf("audit log differs (%d → %d entries)", len(before.audit), len(after.audit)))
	}
	if len(diffs) > 5 {
		diffs = append(diffs[:5], fmt.Sprintf("and %d more", len(diffs)-5))
	}
	return strings.Join(diffs, "; ")
}

func typeCounts(d storeDump) string {
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(d.types)) {
		parts = append(parts, fmt.Sprintf("%s %d", k, d.types[k]))
	}
	return strings.Join(parts, ", ") + fmt.Sprintf("; audit %d", len(d.audit))
}

// ---- an SSH server for host trust and tunnels

type rehearsalSSH struct {
	port int
	echo string // an address that echoes, behind the tunnel
}

func startRehearsalSSH(t *testing.T) rehearsalSSH {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if string(p) == sshPass {
				return nil, nil
			}
			return nil, errors.New("wrong password")
		},
		KeyboardInteractiveCallback: func(_ ssh.ConnMetadata, ask ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			a, err := ask("", "", []string{"Password: "}, []bool{false})
			if err == nil && len(a) == 1 && a[0] == sshPass {
				return nil, nil
			}
			return nil, errors.New("wrong password")
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSSH(c, cfg)
		}
	}()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return rehearsalSSH{port: ln.Addr().(*net.TCPAddr).Port, echo: echo.Addr().String()}
}

func serveSSH(c net.Conn, cfg *ssh.ServerConfig) {
	defer c.Close()
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		switch nc.ChannelType() {
		case "direct-tcpip":
			var p struct {
				Host     string
				Port     uint32
				OrigHost string
				OrigPort uint32
			}
			if ssh.Unmarshal(nc.ExtraData(), &p) != nil {
				_ = nc.Reject(ssh.ConnectionFailed, "bad request")
				continue
			}
			to, err := net.Dial("tcp", net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port))))
			if err != nil {
				_ = nc.Reject(ssh.ConnectionFailed, err.Error())
				continue
			}
			ch, creqs, err := nc.Accept()
			if err != nil {
				to.Close()
				continue
			}
			go ssh.DiscardRequests(creqs)
			go func() { _, _ = io.Copy(ch, to); ch.CloseWrite() }()
			go func() { _, _ = io.Copy(to, ch); to.Close() }()
		case "session":
			ch, creqs, err := nc.Accept()
			if err != nil {
				continue
			}
			go func() {
				for r := range creqs {
					if r.Type == "exec" || r.Type == "shell" {
						_ = r.Reply(true, nil)
						_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{0}))
						ch.Close()
						return
					}
					_ = r.Reply(false, nil)
				}
			}()
		default:
			_ = nc.Reject(ssh.UnknownChannelType, "no")
		}
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// forwards reports whether 127.0.0.1:port carries a round trip to the
// echo address.
func forwards(port int) error {
	var last error
	for i := 0; i < 20; i++ {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 2*time.Second)
		if err != nil {
			last = err
			time.Sleep(250 * time.Millisecond)
			continue
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = c.Write([]byte("ping"))
		buf := make([]byte, 4)
		if err == nil {
			_, err = io.ReadFull(c, buf)
		}
		c.Close()
		if err == nil && string(buf) == "ping" {
			return nil
		}
		last = fmt.Errorf("round trip: %v %q", err, buf)
		time.Sleep(250 * time.Millisecond)
	}
	return last
}

// ---- runtime.json

func readRuntimeFile(t *testing.T, h, pass string) (*Runtime, error) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(komandoDir(h), "runtime.json"))
	if err != nil {
		return nil, err
	}
	rest, ok := bytes.CutPrefix(b, runtimeMagic)
	if !ok {
		return nil, errors.New("runtime.json is not sealed")
	}
	k, err := runtimeKeyFrom(rehearsalMaster(t, h, pass))
	if err != nil {
		return nil, err
	}
	plain, err := k.Open(runtimeRow, rest)
	if err != nil {
		return nil, err
	}
	rt := &Runtime{}
	return rt, json.Unmarshal(plain, rt)
}

func storeMark(t *testing.T, h, pass string) string {
	t.Helper()
	d, _, _ := openRaw(t, h, pass)
	defer d.Close()
	var m string
	err := d.View(context.Background(), func(tx *sealdb.Tx) error {
		var err error
		m, err = readRuntimeMark(tx)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func pidAlive(pid int) bool { return pid > 0 && syscall.Kill(pid, 0) == nil }

// stopOurPID ends pid only when it runs one of this rehearsal's binaries.
func stopOurPID(pid int, binDir string) {
	if !pidAlive(pid) {
		return
	}
	out, err := exec.Command("/bin/ps", "-o", "command=", "-p", strconv.Itoa(pid)).Output()
	if err != nil || !strings.Contains(string(out), binDir) {
		return
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
}

// ---- fixtures

type rehearsalFixture struct {
	name   string
	pass   string // passphrase mode
	large  bool   // F4: 500 servers, 200 pins, 50 secrets, a long audit log
	tunnel bool   // a background tunnel started by the old binary (step 8)
}

type builtFixture struct {
	home       string
	secrets    map[string]string
	tunnelPort int
	webPin     string // the record ID of web1's pin
}

func buildFixture(t *testing.T, b rehearsalBins, srv rehearsalSSH, f rehearsalFixture) builtFixture {
	h := newRehearsalHome(t)
	old := func(args ...string) runResult { return mustK(t, b.old, h, f.pass, nil, args...) }
	setSecret := func(name, value string) {
		mustK(t, b.old, h, f.pass, []string{"SV=" + value}, "secret", "set", name, "--from-env", "SV")
	}
	seed := func(op string, n int) {
		t.Helper()
		r := runK(t, b.seed, h, f.pass, nil, op, strconv.Itoa(n))
		if r.exit != 0 {
			t.Fatalf("seed %s %d: exit %d\n%s%s", op, n, r.exit, r.stdout, r.stderr)
		}
	}
	bf := builtFixture{home: h, secrets: map[string]string{
		"web1-pass": sshPass,
		"l2-psk":    "psk-Plain-77",
		"s-plain":   "alpha-123",
		"s-space":   "two words  and\ttab",
		"s-unicode": "kunci-ключ-🔑-ü",
		"s-long":    strings.Repeat("0123456789abcdef", 256),
	}}
	if f.large {
		for i := 0; i < 50; i++ {
			bf.secrets[fmt.Sprintf("bulk-%02d", i)] = fmt.Sprintf("bulk-value-%02d-%x", i, sha256.Sum256([]byte(strconv.Itoa(i))))
		}
	}
	for _, n := range slices.Sorted(maps.Keys(bf.secrets)) {
		setSecret(n, bf.secrets[n])
	}
	old("host", "add", "web1", fmt.Sprintf("rehearsal@127.0.0.1:%d", srv.port), "--password-ref", "secret:web1-pass")
	old("host", "add", "db1", "root@10.0.0.2", "--protected")
	old("host", "add", "web2", "root@10.0.0.3")
	old("host", "edit", "web2", "--forward-agent", "--yes")
	old("host", "add", "jump1", "root@10.0.0.4", "--proxy-command", "/usr/bin/nc %h %p", "--yes")
	old("conn", "add", "pg1", "postgres://app@10.0.0.5:5432/app", "--protected")
	old("conn", "add", "rd1", "redis://default@10.0.0.7:6379/0?insecure=1")
	old("vpn", "add", "vp1", "socks", "--proxy-address", "127.0.0.1:1080", "--protected", "--mfa")
	old("vpn", "add", "vp2", "socks", "--proxy-address", "127.0.0.1:1081")
	old("vpn", "add", "l2", "l2tp", "--server", "10.0.0.9", "--user", "u", "--psk-ref", "secret:l2-psk", "--legacy-crypto", "--allow-pap", "--yes")
	old("host", "trust", "web1")
	old("config", "set", "host_key_policy", "strict")
	old("config", "set", "login_for", "2h")
	old("config", "set", "vpn_idle", "10m")
	old("config", "set", "mask_personal", "all")
	old("config", "set", "audit_sql", "hash")
	old("config", "set", "audit_syslog", "udp://127.0.0.1:9", "--yes")
	old("policy", "deny", "rm -rf /srv/data")
	seed("revoke", 2)
	seed("approvalstep", 987654)
	if f.large {
		seed("hosts", 500)
		seed("pins", 200)
		seed("audit", 5000)
	}
	// a live VPN session gives runtime.json its mark
	sleeper := exec.Command("/bin/sleep", "3600")
	if err := sleeper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sleeper.Process.Kill(); _ = sleeper.Wait() })
	seed("session", sleeper.Process.Pid)
	if f.tunnel {
		bf.tunnelPort = freePort(t)
		old("tunnel", "start", "web1", "-L", fmt.Sprintf("127.0.0.1:%d:%s", bf.tunnelPort, srv.echo))
		if rt, err := readRuntimeFile(t, h, f.pass); err == nil {
			for _, tu := range rt.Tunnels {
				pid := tu.PID // the tunnel process the old binary started for this test
				t.Cleanup(func() { stopOurPID(pid, b.dir) })
			}
		}
		if err := forwards(bf.tunnelPort); err != nil {
			t.Fatalf("the old binary's tunnel does not forward: %v", err)
		}
	}
	// web1's pin, for the tamper test
	d, _, _ := openRaw(t, h, f.pass)
	_ = d.View(context.Background(), func(tx *sealdb.Tx) error {
		recs, err := tx.List(KindPin)
		for _, r := range recs {
			if strings.Contains(string(r.Data), "127.0.0.1") {
				bf.webPin = r.ID
			}
		}
		return err
	})
	d.Close()
	if bf.webPin == "" {
		t.Fatal("host trust web1 pinned no key")
	}
	mustK(t, b.old, h, f.pass, nil, "list")
	return bf
}

// ---- the steps

// rehearseFixture runs the steps on one fixture.
func rehearseFixture(t *testing.T, b rehearsalBins, srv rehearsalSSH, f rehearsalFixture) {
	fx := f.name
	bf := buildFixture(t, b, srv, f)
	h, pass := bf.home, f.pass
	newK := func(args ...string) runResult { return runK(t, b.new, h, pass, nil, args...) }
	oldK := func(args ...string) runResult { return runK(t, b.old, h, pass, nil, args...) }

	// 1. a byte copy of the format-1 store
	if got := storeFormat(t, h); got != "1" {
		t.Fatalf("the fixture is of format %q, not 1", got)
	}
	beforeHome := newRehearsalHome(t)
	copyTree(t, komandoDir(h), komandoDir(beforeHome))
	oldList := oldK("list")
	oldConfig := oldK("config", "show")
	record(t, fx, "1", passFail(oldList.ok), "format-1 copy taken (sum %s)", storeSum(t, beforeHome))

	// 2. the new binary upgrades it on the first command
	up := newK("host", "list")
	format := storeFormat(t, h)
	record(t, fx, "2", passFail(up.ok && format == "2"), "host list ok=%v %s; format on disk %s", up.ok, up.code, format)
	if !up.ok || format != "2" {
		t.Logf("stdout %.800s\nstderr %.800s", up.stdout, up.stderr)
		return
	}

	// 5. no second upgrade: read-only commands leave the file as it is
	sum1 := storeSum(t, h)
	second := newK("host", "list")
	third := newK("config", "show")
	sum2 := storeSum(t, h)
	record(t, fx, "5", passFail(second.ok && third.ok && sum1 == sum2 && storeFormat(t, h) == "2"),
		"host list and config show again: sum %s → %s", sum1, sum2)

	// 10. timings, the fastest of three runs each on fresh copies
	rehearseTimings(t, b, beforeHome, pass, fx)

	// 3. every record, audit entry and secret value as before
	before := dumpStore(t, beforeHome, pass)
	after := dumpStore(t, h, pass)
	diff := sameContent(before, after)
	record(t, fx, "3a", passFail(diff == "" && after.policy == nil),
		"records and audit opened unchanged after the upgrade (%s); policy check: %v; diff: %s", typeCounts(after), after.policy, cmpOr(diff, "none"))
	bad := 0
	for _, n := range slices.Sorted(maps.Keys(bf.secrets)) {
		want := fmt.Sprintf("%x", sha256.Sum256([]byte(bf.secrets[n])))
		r := newK("secret", "run", "--env", "X=secret:"+n, "--", "/bin/sh", "-c", `printf %s "$X" | /usr/bin/shasum -a 256`)
		if !strings.HasPrefix(r.stdout, want) {
			bad++
			t.Logf("secret %s: exit %d %s %.200s", n, r.exit, r.code, r.stderr)
		}
	}
	record(t, fx, "3b", passFail(bad == 0), "%d secret values opened to their known plaintext through `secret run`, %d did not", len(bf.secrets)-bad, bad)
	var oldSettings, newSettings struct {
		Settings map[string]json.RawMessage `json:"settings"`
	}
	_ = json.Unmarshal(oldConfig.data, &oldSettings)
	_ = json.Unmarshal(third.data, &newSettings)
	var changed []string
	for k, v := range oldSettings.Settings {
		if !bytes.Equal(v, newSettings.Settings[k]) {
			changed = append(changed, k)
		}
	}
	record(t, fx, "3c", passFail(len(oldSettings.Settings) > 0 && len(changed) == 0),
		"config show: %d settings the same before and after, changed: %v", len(oldSettings.Settings), changed)

	// 4. runtime.json still opens, and its mark matches store.db's
	rt, err := readRuntimeFile(t, h, pass)
	mark := storeMark(t, h, pass)
	ok4 := err == nil && rt.Mark != "" && rt.Mark == mark && rt.Sessions["vp2"] != nil
	record(t, fx, "4", passFail(ok4), "runtime.json opens: %v; its mark %q, store.db's %q; vp2 session kept: %v",
		err == nil, shortMark(rt), shortStr(mark), err == nil && rt.Sessions["vp2"] != nil)

	// 6. tampering with a safety row of the upgraded store
	rehearseTamper(t, b, bf, h, pass, fx)

	// 7. the old binary on the upgraded store: STORE_NEWER, no write
	s7 := storeSum(t, h)
	r7a := oldK("list")
	r7b := oldK("host", "add", "late1", "root@10.0.0.99")
	s7b := storeSum(t, h)
	record(t, fx, "7", passFail(r7a.code == "STORE_NEWER" && r7b.code == "STORE_NEWER" && s7 == s7b),
		"old list: %s; old host add: %s; store sum %s → %s", cmpOr(r7a.code, "ok"), cmpOr(r7b.code, "ok"), s7, s7b)

	// 8. a tunnel the old binary started before the upgrade
	if f.tunnel {
		rehearseTunnel(t, b, srv, bf, h, pass, fx)
	} else {
		record(t, fx, "8", "skipped", "the background tunnel runs in F2 only")
	}

	// 11. a format-1 store planted after the upgrade
	rehearsePlant(t, b, beforeHome, h, pass, fx)

	// 9. an upgrade killed part way (the large fixture: its upgrade is long
	// enough to stop in the middle)
	if f.large {
		rehearseInterrupt(t, b, beforeHome)
	} else {
		record(t, fx, "9", "skipped", "the interrupted upgrade runs on F4 only")
	}
}

func cmpOr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func shortStr(s string) string {
	if len(s) > 8 {
		return s[:8] + "…"
	}
	return s
}

func shortMark(rt *Runtime) string {
	if rt == nil {
		return ""
	}
	return shortStr(rt.Mark)
}

// tamperCopy is a copy of the upgraded home h, for one tamper test.
func tamperCopy(t *testing.T, h string) string {
	c := newRehearsalHome(t)
	copyTree(t, komandoDir(h), komandoDir(c))
	return c
}

func editRecords(t *testing.T, h, pass string, fn func(tx *sealdb.Tx) error) {
	t.Helper()
	d, _, _ := openRaw(t, h, pass)
	defer d.Close()
	if err := d.Update(context.Background(), fn); err != nil {
		t.Fatalf("tamper: %v", err)
	}
}

func editJSON(tx *sealdb.Tx, typ string, match func(map[string]any) bool, change func(map[string]any)) error {
	recs, err := tx.List(typ)
	if err != nil {
		return err
	}
	for _, r := range recs {
		m := map[string]any{}
		if err := json.Unmarshal(r.Data, &m); err != nil {
			return err
		}
		if !match(m) {
			continue
		}
		change(m)
		b, err := json.Marshal(m)
		if err != nil {
			return err
		}
		_, err = tx.Put(typ, r.ID, b)
		return err
	}
	return fmt.Errorf("no %s record matched", typ)
}

func rehearseTamper(t *testing.T, b rehearsalBins, bf builtFixture, h, pass, fx string) {
	cases := []struct {
		name, want string
		tamper     func(t *testing.T, c string)
	}{
		{"flip a protected mark (db1)", "server db1", func(t *testing.T, c string) {
			editRecords(t, c, pass, func(tx *sealdb.Tx) error {
				return editJSON(tx, KindHost, func(m map[string]any) bool { return m["name"] == "db1" }, func(m map[string]any) { delete(m, "protected") })
			})
		}},
		{"delete web1's pin", bf.webPin, func(t *testing.T, c string) {
			editRecords(t, c, pass, func(tx *sealdb.Tx) error { return tx.Delete(bf.webPin) })
		}},
		{"edit extra_deny_patterns", "settings", func(t *testing.T, c string) {
			editRecords(t, c, pass, func(tx *sealdb.Tx) error {
				return editJSON(tx, kindSettings, func(map[string]any) bool { return true }, func(m map[string]any) { m["extra_deny_patterns"] = []string{} })
			})
		}},
		{"remove the policymac record", "no policy MAC", func(t *testing.T, c string) {
			editRecords(t, c, pass, func(tx *sealdb.Tx) error { return tx.Delete("policymac") })
		}},
		{"set the format back to 1", "", func(t *testing.T, c string) {
			db, err := sql.Open("sqlite", "file:"+storeDB(c))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(`UPDATE meta SET v='1' WHERE k='format'`); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for i, tc := range cases {
		c := tamperCopy(t, h)
		tc.tamper(t, c)
		sum := storeSum(t, c)
		r := runK(t, b.new, c, pass, nil, "host", "list")
		step := fmt.Sprintf("6%c", 'a'+i)
		if tc.want == "" { // fails closed with any error, and changes nothing
			record(t, fx, step, passFail(!r.ok && storeSum(t, c) == sum && storeFormat(t, c) == "1"),
				"%s: ok=%v %s: %.220s", tc.name, r.ok, r.code, r.message)
			continue
		}
		record(t, fx, step, passFail(!r.ok && r.code == "POLICY_MAC_FAILED" && strings.Contains(r.message, tc.want)),
			"%s: %s, names %q: %v: %.260s", tc.name, cmpOr(r.code, "ok"), tc.want, strings.Contains(r.message, tc.want), r.message)
	}
}

func rehearseTunnel(t *testing.T, b rehearsalBins, srv rehearsalSSH, bf builtFixture, h, pass, fx string) {
	rt, err := readRuntimeFile(t, h, pass)
	if err != nil || len(rt.Tunnels) != 1 {
		n := 0
		if rt != nil {
			n = len(rt.Tunnels)
		}
		record(t, fx, "8", "fail", "runtime.json after the upgrade: %v, %d tunnels", err, n)
		return
	}
	var oldPID int
	for _, tu := range rt.Tunnels {
		oldPID = tu.PID
	}
	alive := pidAlive(oldPID)
	fwd := forwards(bf.tunnelPort)
	oldList := runK(t, b.old, h, pass, nil, "tunnel", "list")
	newList := runK(t, b.new, h, pass, nil, "tunnel", "list")
	listed := newList.ok && strings.Contains(string(newList.data), strconv.Itoa(bf.tunnelPort))
	stop := runK(t, b.new, h, pass, nil, "tunnel", "stop", "--all")
	gone := false
	for i := 0; i < 40 && !gone; i++ {
		if gone = !pidAlive(oldPID); !gone {
			time.Sleep(250 * time.Millisecond)
		}
	}
	port := freePort(t)
	start := runK(t, b.new, h, pass, nil, "tunnel", "start", "web1", "-L", fmt.Sprintf("127.0.0.1:%d:%s", port, srv.echo))
	if rt, err := readRuntimeFile(t, h, pass); err == nil {
		for _, tu := range rt.Tunnels {
			pid := tu.PID
			t.Cleanup(func() { stopOurPID(pid, b.dir) })
		}
	}
	fwd2 := forwards(port)
	stop2 := runK(t, b.new, h, pass, nil, "tunnel", "stop", "--all")
	ok := oldList.code == "STORE_NEWER" && listed && stop.ok && gone && start.ok && fwd2 == nil && stop2.ok
	record(t, fx, "8", passFail(ok),
		"old tunnel pid alive after upgrade: %v, still forwards: %v; old tunnel list: %s; new tunnel list shows it: %v; new tunnel stop --all: %v, process gone: %v; new tunnel start: %v %s, forwards: %v; stop: %v",
		alive, fwd == nil, cmpOr(oldList.code, "ok"), listed, stop.ok, gone, start.ok, start.code, fwd2 == nil, stop2.ok)
}

// rehearsePlant puts a format-1 store with the same master key but another
// safety row (db1 no longer protected) in place of the upgraded store.
func rehearsePlant(t *testing.T, b rehearsalBins, beforeHome, h, pass, fx string) {
	c := tamperCopy(t, h)
	plant := tamperCopy(t, beforeHome)
	editRecords(t, plant, pass, func(tx *sealdb.Tx) error {
		return editJSON(tx, KindHost, func(m map[string]any) bool { return m["name"] == "db1" }, func(m map[string]any) { delete(m, "protected") })
	})
	for _, n := range []string{StoreFile, StoreFile + "-wal", StoreFile + "-shm"} {
		_ = os.Remove(testhome.Path(t, filepath.Join(komandoDir(c), n)))
		if bb, err := os.ReadFile(filepath.Join(komandoDir(plant), n)); err == nil {
			if err := os.WriteFile(testhome.Path(t, filepath.Join(komandoDir(c), n)), bb, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	r := runK(t, b.new, c, pass, nil, "list")
	format := storeFormat(t, c)
	var lst struct {
		Targets []struct {
			Name      string `json:"name"`
			Protected bool   `json:"protected"`
		} `json:"targets"`
	}
	_ = json.Unmarshal(r.data, &lst)
	db1 := "missing"
	for _, x := range lst.Targets {
		if x.Name == "db1" {
			db1 = strconv.FormatBool(x.Protected)
		}
	}
	status := "observed (known gap)"
	if !r.ok {
		status = "observed (refused)"
	}
	record(t, fx, "11", status, "planted format-1 store, db1 unprotected: new list ok=%v %s; format after %s; db1 protected=%s",
		r.ok, r.code, format, db1)
}

// rehearseInterrupt kills the upgrade of F4 at points across its run and
// checks the store is one format or the other, whole, and that the next
// run finishes it.
func rehearseInterrupt(t *testing.T, b rehearsalBins, beforeHome string) {
	before := dumpStore(t, beforeHome, "")
	// how long an upgrade takes here
	probe := tamperCopy(t, beforeHome)
	full := runK(t, b.new, probe, "", nil, "host", "list")
	if !full.ok {
		record(t, "F4", "9", "fail", "the uninterrupted upgrade failed: %s", full.code)
		return
	}
	var notes []string
	allOK := true
	counts := map[string]int{}
	// every 10 ms over the first 250 ms (the reseal itself commits early),
	// then every 100 ms to past the end of the command
	var waits []time.Duration
	for w := 20 * time.Millisecond; w <= 250*time.Millisecond; w += 10 * time.Millisecond {
		waits = append(waits, w)
	}
	for w := 350 * time.Millisecond; w <= full.duration+200*time.Millisecond; w += 100 * time.Millisecond {
		waits = append(waits, w)
	}
	for _, wait := range waits {
		c := tamperCopy(t, beforeHome)
		cmd := rehearsalCmd(context.Background(), b.new, c, "", nil, "host", "list")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(wait)
		killed := cmd.Process.Kill() == nil // the PID this test started
		werr := cmd.Wait()
		finished := werr == nil
		format := storeFormat(t, c)
		mid := dumpStore(t, c, "")
		whole := sameContent(before, mid) == "" && (format == "1" || mid.policy == nil)
		next := runK(t, b.new, c, "", nil, "host", "list")
		end := dumpStore(t, c, "")
		done := next.ok && storeFormat(t, c) == "2" && end.policy == nil && sameContent(before, end) == ""
		state := "format " + format
		if finished {
			state += " (the run had finished)"
		} else if !killed {
			state += " (kill failed)"
		}
		allOK = allOK && whole && done
		counts[state]++
		if !whole || !done {
			notes = append(notes, fmt.Sprintf("kill at %v: %s, whole: %v, next run finishes: %v", wait.Round(time.Millisecond), state, whole, done))
		} else {
			t.Logf("kill at %v: %s, whole, the next run finished it", wait.Round(time.Millisecond), state)
		}
	}
	var seen []string
	for _, k := range slices.Sorted(maps.Keys(counts)) {
		seen = append(seen, fmt.Sprintf("%s ×%d", k, counts[k]))
	}
	record(t, "F4", "9", passFail(allOK), "a whole upgrade command takes %v here; killed %d times (every 10 ms over the first 250 ms, then every 100 ms): %s; every store whole, and the next run finished it: %v %s",
		full.duration.Round(time.Millisecond), len(waits), strings.Join(seen, ", "), allOK, strings.Join(notes, "; "))
}

// rehearseTimings times host list with the old binary on the format-1
// store, the upgrade (the new binary's first host list) and the new
// binary's host list after it: the fastest of three runs, each upgrade on
// a fresh copy of the format-1 store.
func rehearseTimings(t *testing.T, b rehearsalBins, beforeHome, pass, fx string) {
	fastest := func(runs []time.Duration) time.Duration { return slices.Min(runs).Round(time.Millisecond) }
	var oldRuns, upRuns, afterRuns []time.Duration
	for i := 0; i < 3; i++ {
		c := tamperCopy(t, beforeHome)
		oldRuns = append(oldRuns, mustK(t, b.old, c, pass, nil, "host", "list").duration)
		upRuns = append(upRuns, mustK(t, b.new, c, pass, nil, "host", "list").duration)
		afterRuns = append(afterRuns, mustK(t, b.new, c, pass, nil, "host", "list").duration)
	}
	record(t, fx, "10", "pass", "fastest of 3: old host list on format 1 %v; upgrade (new binary's first host list) %v; new host list after %v (all runs: old %v, upgrade %v, after %v)",
		fastest(oldRuns), fastest(upRuns), fastest(afterRuns), rounded(oldRuns), rounded(upRuns), rounded(afterRuns))
}

func rounded(runs []time.Duration) []time.Duration {
	out := make([]time.Duration, len(runs))
	for i, r := range runs {
		out[i] = r.Round(10 * time.Millisecond)
	}
	return out
}

// TestRehearsalListMedian times `host list` (KOMANDO_OUTPUT=json) on a store of N servers
// (KOMANDO_REHEARSAL_N, default 50), store.key mode: five runs on the
// upgraded store (format 2) and five with the old binary on a format-1
// copy; it reports the median of each. The new build's threshold is 200 ms.
func TestRehearsalListMedian(t *testing.T) {
	n := 50
	if v := os.Getenv("KOMANDO_REHEARSAL_N"); v != "" {
		var err error
		if n, err = strconv.Atoi(v); err != nil {
			t.Fatal(err)
		}
	}
	b := buildRehearsalBins(t)
	h := newRehearsalHome(t)
	mustK(t, b.old, h, "", nil, "host", "add", "first", "root@10.0.0.1")
	if r := runK(t, b.seed, h, "", nil, "hosts", strconv.Itoa(n)); r.exit != 0 {
		t.Fatalf("seed hosts: %s%s", r.stdout, r.stderr)
	}
	for _, op := range strings.Fields(os.Getenv("KOMANDO_REHEARSAL_SEED")) { // e.g. "pins=200 audit=5000"
		name, count, _ := strings.Cut(op, "=")
		if r := runK(t, b.seed, h, "", nil, name, count); r.exit != 0 {
			t.Fatalf("seed %s: %s%s", op, r.stdout, r.stderr)
		}
	}
	if got := storeFormat(t, h); got != "1" {
		t.Fatalf("format %q, not 1", got)
	}
	formatOne := newRehearsalHome(t)
	copyTree(t, komandoDir(h), komandoDir(formatOne))
	median := func(runs []time.Duration) time.Duration {
		s := slices.Clone(runs)
		slices.Sort(s)
		return s[len(s)/2].Round(time.Millisecond)
	}
	var oldRuns, newRuns []time.Duration
	for i := 0; i < 5; i++ {
		oldRuns = append(oldRuns, mustK(t, b.old, formatOne, "", nil, "host", "list").duration)
	}
	upgrade := mustK(t, b.new, h, "", nil, "host", "list").duration // not in the median
	if got := storeFormat(t, h); got != "2" {
		t.Fatalf("format %q after upgrade, not 2", got)
	}
	for i := 0; i < 5; i++ {
		newRuns = append(newRuns, mustK(t, b.new, h, "", nil, "host", "list").duration)
	}
	m := median(newRuns)
	for _, args := range [][]string{{"list"}, {"config", "show"}, {"host", "show", "bulk-250"}} {
		t.Logf("new %v: %v (old on format 1: %v)", args, mustK(t, b.new, h, "", nil, args...).duration.Round(time.Millisecond),
			mustK(t, b.old, formatOne, "", nil, args...).duration.Round(time.Millisecond))
	}
	t.Logf("RESULT n=%d servers: upgrade run %v; new (format 2) median %v runs %v; old (format 1) median %v runs %v; threshold 200ms: %s",
		n, upgrade.Round(time.Millisecond), m, rounded(newRuns), median(oldRuns), rounded(oldRuns), passFail(m <= 200*time.Millisecond))
}
