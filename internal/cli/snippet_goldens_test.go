package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

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
}

type replayStep struct {
	stdout, stderr string
	exit           uint32
}

// startReplayServer points the host "dev" of startFakeServer's home at a new
// server that replays steps.
func startReplayServer(t *testing.T, steps ...replayStep) *replayServer {
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
	s := &replayServer{steps: steps}
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
					_ = r.Reply(r.Type == "exec" || r.Type == "env" || r.Type == "pty-req", nil)
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
					go func() { _, _ = io.Copy(io.Discard, ch) }()
					_, _ = ch.Write([]byte(step.stdout))
					_, _ = ch.Stderr().Write([]byte(step.stderr))
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{step.exit}))
					_ = ch.Close()
				}()
			}
		}()
	}
}

// snippetCase is one golden: the command, the files it replays, the name of
// the golden.
type snippetCase struct {
	snippet string // the ready-made snippet this pins: testdata/snippets/<snippet>/
	family  string // the OS or tool family: "linux", "apt", "apk"
	args    []string
	steps   []string // the stdout files of the steps; "name:exit" adds an exit code
}

var snippetCases = []snippetCase{
	{snippet: "svc-list", family: "systemd", args: []string{"svc", "list", "dev"}, steps: []string{"systemd.in"}},
	{snippet: "docker-ps", family: "docker", args: []string{"docker", "ps", "dev"}, steps: []string{"docker.in"}},
	{snippet: "docker-images", family: "docker", args: []string{"docker", "images", "dev"}, steps: []string{"docker.in"}},
	{snippet: "docker-stats", family: "docker", args: []string{"docker", "stats", "dev"}, steps: []string{"docker.in"}},
	{snippet: "pkg-upgradable", family: "apt", args: []string{"pkg", "upgradable", "dev"}, steps: []string{"apt.in"}},
	{snippet: "facts", family: "centos7", args: []string{"facts", "dev"}, steps: []string{"centos7.in"}},
	{snippet: "svc-status", family: "systemd", args: []string{"svc", "status", "dev", "nginx", "postfix"}, steps: []string{"systemd.in"}},
	{snippet: "pkg-security", family: "apt", args: []string{"pkg", "security", "dev"}, steps: []string{"apt.in"}},
	{snippet: "logs", family: "journal", args: []string{"logs", "dev", "--unit", "nginx", "--limit", "3"}, steps: []string{"journal.in"}},
	{snippet: "docker-logs", family: "docker", args: []string{"docker", "logs", "dev", "api", "--limit", "3"}, steps: []string{"docker.in"}},
	{snippet: "pkg-upgradable", family: "apk", args: []string{"pkg", "upgradable", "dev"}, steps: []string{"apk.in"}},
}

// volatile fields change from run to run; each is replaced by a fixed word.
var volatile = []*regexp.Regexp{
	regexp.MustCompile(`"(duration_ms|latency_ms|elapsed_ms)":\s*\d+`),
	regexp.MustCompile(`"(last_age|age)":\s*"[^"]*"`),
}

func normalizeGolden(s string) string {
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
			startReplayServer(t, steps...)
			got := captureOutput(t, func() error { return runRoot(t, append([]string{"-o", "json"}, c.args...)...) })
			got = normalizeGolden(got)
			golden := filepath.Join(dir, c.family+".out.json")
			if record {
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("no golden %s: record it with KOMANDO_RECORD_GOLDENS=1", golden)
			}
			if got != string(want) {
				t.Errorf("%s differs from its golden\n got:  %s\n want: %s", golden, got, want)
			}
		})
	}
}
