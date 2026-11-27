package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// Command-level goldens for the reads that become ready-made snippets.
//
// A case replays what a server printed (testdata/snippets/NAME/FAMILY.in is
// stdout, FAMILY.err is stderr when the command reads it) to today's command
// and compares the whole JSON the command prints with FAMILY.out.json. The
// goldens pin the command's output, not one parser: sorting, filters,
// warnings and masking are inside them.
//
// To record again after a deliberate change: KOMANDO_RECORD_GOLDENS=1 go test
// ./internal/cli -run TestSnippetGoldens, then read every diff.

// replayServer is a loopback SSH server that answers each exec with the next
// step: stdout, stderr and an exit code. It runs nothing.
type replayServer struct {
	mu    sync.Mutex
	steps []replayStep
	execs []string
	sent  []string // what each exec sent: the command, and a PowerShell script decoded
	sftp  sftp.Handlers
}

type replayStep struct {
	stdout, stderr string
	exit           uint32
}

// startReplayServerWith points the host "dev" of startFakeServer's home at a
// new server that replays steps and serves files over SFTP: an in-memory tree
// of path to content (a path ending in / is a folder).
func startReplayServerWith(t *testing.T, files map[string]string, steps ...replayStep) *replayServer {
	t.Helper()
	startFakeServer(t) // the komando home, the client key and the hosts
	_, hostKey, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &replayServer{steps: steps, sftp: sftp.InMemHandler()}
	for _, p := range sortedFilePaths(files) {
		if strings.HasSuffix(p, "/") {
			if err := s.sftp.FileCmd.Filecmd(sftp.NewRequest("Mkdir", strings.TrimSuffix(p, "/"))); err != nil {
				t.Fatal(err)
			}
			continue
		}
		req := sftp.NewRequest("Put", p)
		req.Flags = 0x2 | 0x8 | 0x10 // write, create, truncate
		w, err := s.sftp.FilePut.Filewrite(req)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.WriteAt([]byte(files[p]), 0); err != nil {
			t.Fatal(err)
		}
	}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(nc, cfg)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	if err := store.Update(store.Save(), func(st *store.State) error {
		st.Hosts["dev"].Port = port
		st.Hosts["dev"].Protected = false
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *replayServer) serve(nc net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "session" {
			_ = nch.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, creqs, err := nch.Accept()
		if err != nil {
			continue
		}
		go func() {
			for r := range creqs {
				if r.WantReply {
					_ = r.Reply(r.Type == "exec" || r.Type == "env" || r.Type == "pty-req" || r.Type == "subsystem", nil)
				}
				if r.Type == "subsystem" {
					go func() {
						srv := sftp.NewRequestServer(ch, s.sftp)
						_ = srv.Serve()
						_ = ch.Close()
					}()
					continue
				}
				if r.Type != "exec" {
					continue
				}
				var p struct{ Cmd string }
				_ = ssh.Unmarshal(r.Payload, &p)
				s.mu.Lock()
				s.execs = append(s.execs, p.Cmd)
				var step replayStep
				if len(s.steps) > 0 {
					step, s.steps = s.steps[0], s.steps[1:]
				}
				s.mu.Unlock()
				go func() {
					// read what the client sends (a Windows command sends its script on
					// stdin) before answering: closing early gives the client an EOF
					var in []byte
					done := make(chan struct{})
					go func() { in, _ = io.ReadAll(ch); close(done) }()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
					}
					s.mu.Lock()
					s.sent = append(s.sent, sentText(p.Cmd, in))
					s.mu.Unlock()
					_, _ = ch.Write([]byte(step.stdout))
					_, _ = ch.Stderr().Write([]byte(step.stderr))
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{step.exit}))
					_ = ch.Close()
				}()
			}
		}()
	}
}

func sortedFilePaths(files map[string]string) []string {
	var ps []string
	for p := range files {
		ps = append(ps, p)
	}
	sort.Strings(ps) // a folder before what it holds
	return ps
}

// sentText is what an exec sent, as text a person can read: the command, and
// for the PowerShell bootstrap the script its first input line carries.
func sentText(cmd string, stdin []byte) string {
	if cmd == sshx.PSCommandLine {
		line, _, _ := strings.Cut(string(stdin), "\n")
		if b, err := base64.StdEncoding.DecodeString(line); err == nil {
			return "powershell script:\n" + string(b)
		}
	}
	return cmd
}

// snippetCase is one golden: the command, the files it replays, the name of
// the golden.
type snippetCase struct {
	snippet string // the ready-made snippet this pins: testdata/snippets/<snippet>/
	family  string // the OS or tool family: "linux", "apt", "apk"
	args    []string
	steps   []string          // the stdout files of the steps
	files   map[string]string // files served over SFTP; a path ending in / is a folder
	// setup runs after the server is up, with a new folder it may fill; the
	// folder's path is replaced by <tmp> in the compared text
	setup func(t *testing.T, tmp string)
	// volatile are patterns whose matches change between runs (a database
	// version, a file size); each is replaced by a fixed word
	volatile []*regexp.Regexp
}

// appTree is the file tree the SFTP cases read.
var appTree = map[string]string{
	"/srv/":                  "",
	"/srv/app/":              "",
	"/srv/app/env.conf":      "PORT=8080\nMODE=prod\n",
	"/srv/app/b.txt":         "bee\n",
	"/srv/app/a.txt":         "ay\n",
	"/srv/app/.hidden":       "x\n",
	"/srv/app/sub/":          "",
	"/srv/app/sub/inner.txt": "in\n",
}

// liteDB makes a SQLite file with a fixed schema and registers it as the
// conn "lite".
func liteDB(t *testing.T, tmp string) {
	path := filepath.Join(tmp, "app.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT)`,
		`CREATE UNIQUE INDEX users_email ON users(email)`,
		`CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, total REAL)`,
		`INSERT INTO users (name, email) VALUES ('ana', 'ana@example.test'), ('budi', 'budi@example.test')`,
		`INSERT INTO orders (user_id, total) VALUES (1, 12.5), (1, 7), (2, 30)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "conn", "add", "lite", "sqlite://"+path)
}

// memcachedConn starts the fake memcached of the cache tests and registers
// it as the conn "m".
func memcachedConn(t *testing.T, _ string) {
	addr, _ := fakeMemcached(t)
	mustRun(t, "conn", "add", "m", "memcached://"+addr)
}

// kubeConn starts the fake Kubernetes API of the cluster tests and imports
// a kubeconfig for it as the conn "prod".
func kubeConn(t *testing.T, _ string) {
	// the kubeconfig's context is called prod, as the test home's host
	if err := store.Update(store.Save(), func(st *store.State) error { delete(st.Hosts, "prod"); return nil }); err != nil {
		t.Fatal(err)
	}
	d := newDetailCluster(t)
	mustRun(t, "import", "kubeconfig", d.kubeconfig(t))
}

// liteVolatile cuts what a SQLite version or file layout can change.
var liteVolatile = []*regexp.Regexp{
	regexp.MustCompile(`"(version|size_bytes|started|uptime_seconds)":\s*("[^"]*"|\d+(\.\d+)?|null)`),
}

var snippetCases = []snippetCase{
	{snippet: "docker-ps", family: "docker", args: []string{"docker", "ps", "dev"}, steps: []string{"docker.in"}},
	{snippet: "docker-images", family: "docker", args: []string{"docker", "images", "dev"}, steps: []string{"docker.in"}},
	{snippet: "docker-stats", family: "docker", args: []string{"docker", "stats", "dev"}, steps: []string{"docker.in"}},
	{snippet: "pkg-upgradable", family: "apt", args: []string{"pkg", "upgradable", "dev"}, steps: []string{"apt.in"}},
	{snippet: "pkg-security", family: "apt", args: []string{"pkg", "security", "dev"}, steps: []string{"apt.in"}},
	{snippet: "logs", family: "journal", args: []string{"logs", "dev", "--unit", "nginx", "--limit", "3"}, steps: []string{"journal.in"}},
	{snippet: "docker-logs", family: "docker", args: []string{"docker", "logs", "dev", "api", "--limit", "3"}, steps: []string{"docker.in"}},
	{snippet: "docker-prune-preview", family: "docker", args: []string{"docker", "prune", "dev", "--dry-run"}, steps: []string{"docker.in"}},
	{snippet: "fs-list", family: "sftp", args: []string{"fs", "list", "dev", "/srv/app"}, files: appTree},
	{snippet: "fs-list", family: "sftp-all", args: []string{"fs", "list", "dev", "/srv/app", "--all", "--limit", "3"}, files: appTree},
	{snippet: "fs-cat", family: "sftp", args: []string{"fs", "cat", "dev", "/srv/app/env.conf"}, files: appTree},
	{snippet: "fs-write-preview", family: "sftp", args: []string{"fs", "write", "dev", "/srv/app/env.conf", "--content", "PORT=9090\nMODE=prod\n", "--dry-run"}, files: appTree},
	{snippet: "fs-write-preview", family: "sftp-same", args: []string{"fs", "write", "dev", "/srv/app/env.conf", "--content", "PORT=8080\nMODE=prod\n", "--dry-run"}, files: appTree},
	{snippet: "fs-write-preview", family: "sftp-new", args: []string{"fs", "write", "dev", "/srv/app/new.conf", "--content", "A=1\n", "--dry-run"}, files: appTree},
	{snippet: "db-info", family: "sqlite", args: []string{"db", "info", "lite"}, setup: liteDB, volatile: liteVolatile},
	{snippet: "db-sizes", family: "sqlite", args: []string{"db", "sizes", "lite"}, setup: liteDB, volatile: append([]*regexp.Regexp{regexp.MustCompile(`"bytes":\s*\d+`)}, liteVolatile...)},
	{snippet: "db-schema", family: "sqlite-table", args: []string{"db", "schema", "lite", "orders"}, setup: liteDB, volatile: liteVolatile},
	{snippet: "db-schema", family: "sqlite", args: []string{"db", "schema", "lite"}, setup: liteDB, volatile: liteVolatile},
	{snippet: "cache-keys", family: "memcached", args: []string{"cache", "keys", "m"}, setup: memcachedConn},
	{snippet: "cache-info", family: "memcached", args: []string{"cache", "info", "m"}, setup: memcachedConn},
	{snippet: "cluster-describe", family: "pod", args: []string{"cluster", "describe", "prod", "pod/api-1"}, setup: kubeConn},
	{snippet: "cluster-describe", family: "deployment", args: []string{"cluster", "describe", "prod", "deployment/api"}, setup: kubeConn},
	{snippet: "cluster-logs", family: "pod", args: []string{"cluster", "logs", "prod", "pod/api-1"}, setup: kubeConn},
	{snippet: "pkg-security-refresh", family: "apt", args: []string{"pkg", "security", "dev", "--refresh"}, steps: []string{"apt.in"}},
	{snippet: "security-upgrade", family: "apt", args: []string{"pkg", "upgrade", "dev", "--security", "--allow-dangerous"}, steps: []string{"apt.in"}},
	{snippet: "pkg-upgradable", family: "apk", args: []string{"pkg", "upgradable", "dev"}, steps: []string{"apk.in"}},
}

// volatile fields change from run to run; each is replaced by a fixed word.
var volatile = []*regexp.Regexp{
	regexp.MustCompile(`"(last_age|age)":\s*"[^"]*"`),
	regexp.MustCompile(`"mod_time":\s*"[^"]*"`), // the in-memory files are made now
}

// dropped are keys that depend on the platform or the run: Linux leaves a
// timing of zero out and Windows prints it, and an SFTP file's owner comes from
// the system data of the file, which Windows does not have. The key is cut
// with its comma, so the text is the same where the key is absent.
var dropped = regexp.MustCompile(`,"(duration_ms|latency_ms|elapsed_ms|uid|gid)":\s*\d+`)

func normalizeGolden(s string, tmp string, extra []*regexp.Regexp) string {
	s = dropped.ReplaceAllString(s, "")
	// the hint shows the command line the test binary was started with
	s = strings.ReplaceAll(s, "`komando version --allow-dangerous`", "`komando --allow-dangerous`")
	if tmp != "" {
		s = strings.ReplaceAll(s, tmp, "<tmp>")
	}
	for _, re := range extra {
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			k, _, _ := strings.Cut(m, ":")
			return k + `:"<volatile>"`
		})
	}
	// meta holds the version, the run time and the host key of a throwaway
	// server (a new port and key every run); the data is what is pinned
	if i := strings.LastIndex(s, `,"meta":`); i >= 0 {
		s = s[:i] + "}"
	}
	for _, re := range volatile {
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			k, _, _ := strings.Cut(m, ":")
			return k + `:"<volatile>"`
		})
	}
	return strings.TrimSpace(s) + "\n"
}

func TestSnippetGoldens(t *testing.T) {
	record := os.Getenv("KOMANDO_RECORD_GOLDENS") == "1"
	for _, c := range snippetCases {
		t.Run(c.snippet+"/"+c.family, func(t *testing.T) {
			dir := filepath.Join("testdata", "snippets", c.snippet)
			var steps []replayStep
			for _, f := range c.steps {
				in, err := os.ReadFile(filepath.Join(dir, f))
				if err != nil {
					t.Fatal(err)
				}
				st := replayStep{stdout: string(in)}
				if b, err := os.ReadFile(filepath.Join(dir, strings.TrimSuffix(f, ".in")+".err")); err == nil {
					st.stderr = string(b)
				}
				steps = append(steps, st)
			}
			rs := startReplayServerWith(t, c.files, steps...)
			tmpDir := ""
			if c.setup != nil {
				tmpDir = t.TempDir()
				c.setup(t, tmpDir)
			}
			got := captureOutput(t, func() error { return runRoot(t, append([]string{"-o", "json"}, c.args...)...) })
			got = normalizeGolden(got, tmpDir, c.volatile)
			if strings.Contains(got, `"message":"EOF"`) || strings.Contains(got, "CONNECTION_LOST") {
				t.Fatalf("the replay connection broke; this is not output to record:\n%s", got)
			}
			if strings.TrimSpace(got) == "" {
				t.Fatal("the command printed nothing: it failed before its output (a golden of nothing pins nothing)")
			}
			rs.mu.Lock()
			sent := strings.Join(rs.sent, "\n----\n") + "\n"
			rs.mu.Unlock()
			for _, g := range []struct{ name, text string }{{c.family + ".out.json", got}, {c.family + ".sent.txt", sent}} {
				golden := filepath.Join(dir, g.name)
				if record {
					if err := os.WriteFile(golden, []byte(g.text), 0o644); err != nil {
						t.Fatal(err)
					}
					continue
				}
				want, err := os.ReadFile(golden)
				if err != nil {
					t.Fatalf("no golden %s: record it with KOMANDO_RECORD_GOLDENS=1", golden)
				}
				if g.text != string(want) {
					t.Errorf("%s differs from its golden\n got:  %s\n want: %s", golden, g.text, want)
				}
			}
		})
	}
}
