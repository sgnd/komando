package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// fakeServer is a loopback SSH server that runs nothing: it records each
// exec (command and input) and answers with chunks, a pause between them,
// so the client reads them as separate reads.
type fakeServer struct {
	port   int
	mu     sync.Mutex
	execs  []fakeExec
	chunks []string
}

type fakeExec struct{ cmd, stdin string }

// dropMark as a reply chunk breaks the connection there.
const dropMark = "\x00drop"

func (s *fakeServer) take() []fakeExec {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.execs
	s.execs = nil
	return e
}

func (s *fakeServer) reply(chunks ...string) {
	s.mu.Lock()
	s.chunks = chunks
	s.mu.Unlock()
}

// startFakeServer starts the server and a temporary komando home with the
// hosts prod (protected) and dev pointing at it (dev counts as protected
// too: it is the same server).
func startFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("KOMANDO_HOME", filepath.Join(tmp, ".komando"))
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("KOMANDO_OUTPUT", "json")

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
	s := &fakeServer{port: ln.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(nc, cfg)
		}
	}()

	_, clientKey, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKey(clientKey, "")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(tmp, "id_test")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(st *store.State) error {
		st.Hosts["prod"] = &store.Host{Name: "prod", Address: "127.0.0.1", Port: s.port, User: "deploy", Identity: keyPath, Protected: true}
		st.Hosts["dev"] = &store.Host{Name: "dev", Address: "localhost", Port: s.port, User: "deploy", Identity: keyPath}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	savedW := out.P.W
	out.P.W = io.Discard
	t.Cleanup(func() { out.P.W = savedW })
	return s
}

func (s *fakeServer) serve(nc net.Conn, cfg *ssh.ServerConfig) {
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
				s.execs = append(s.execs, fakeExec{cmd: p.Cmd})
				i, chunks := len(s.execs)-1, s.chunks
				s.mu.Unlock()
				go func() {
					read := make(chan struct{})
					go func() {
						b, _ := io.ReadAll(ch)
						s.mu.Lock()
						if i < len(s.execs) {
							s.execs[i].stdin = string(b)
						}
						s.mu.Unlock()
						close(read)
					}()
					for _, c := range chunks {
						if c == dropMark { // the link breaks mid-command
							_ = nc.Close()
							return
						}
						_, _ = ch.Write([]byte(c))
						time.Sleep(40 * time.Millisecond)
					}
					select {
					case <-read:
					case <-time.After(time.Second):
					}
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{0}))
					_ = ch.Close()
				}()
			}
		}()
	}
}

func runRoot(t *testing.T, args ...string) error {
	t.Helper()
	root := newRoot()
	root.SetArgs(append([]string{"--host-key-policy", "accept-new"}, args...))
	root.SilenceErrors, root.SilenceUsage = true, true
	_, err := root.ExecuteContextC(context.Background())
	return err
}

// The input of exec --stdin-file and the interpreter of script are
// checked like the command itself.
func TestStdinAndInterpreterChecked(t *testing.T) {
	srv := startFakeServer(t)
	tmp := t.TempDir()
	evil := filepath.Join(tmp, "evil.sh")
	_ = os.WriteFile(evil, []byte("rm -rf / --no-preserve-root\n"), 0o600)
	writes := filepath.Join(tmp, "writes.sh")
	_ = os.WriteFile(writes, []byte("uptime\necho pwned | tee /etc/motd\n"), 0o600)
	benign := filepath.Join(tmp, "benign.sh")
	_ = os.WriteFile(benign, []byte("uptime\ndf -h /\n"), 0o600)
	file := func(name, body string) string {
		p := filepath.Join(tmp, name)
		_ = os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	const bashScript = "#!/bin/bash\nset -eu\n# it's a check\ndf -h /\n"
	const envScript = "#!/usr/bin/env bash\ncat <<EOF\ndon't panic\nEOF\nuptime\n"
	shebang, envBang := file("check.sh", bashScript), file("check2.sh", envScript)
	positional := file("pos.sh", "find /data \"$1\"\n")
	data := file("data.csv", "id,cmd\n1,rm -rf /x\n2,a > b\n")
	report := file("report.sql", "select count(*) from t where n > 5;\n")
	escape := file("escape.sql", "select 1;\n\\! rm -rf /data\n")

	cases := []struct {
		name  string
		args  []string
		code  string // "" = it runs
		stdin string // what the server got, when it runs
	}{
		{"policy reads the input", []string{"exec", "dev", "--stdin-file", evil, "--", "bash -s"}, "POLICY_BLOCKED", ""},
		{"read-only input that writes", []string{"exec", "prod", "--read-only", "--stdin-file", writes, "--", "bash -s"}, "READ_ONLY_VIOLATION", ""},
		{"read-only input, destructive", []string{"exec", "prod", "--read-only", "--stdin-file", evil, "--", "bash -s"}, "POLICY_BLOCKED", ""},
		{"read-only bash -s with a read-only script", []string{"exec", "prod", "--read-only", "--stdin-file", benign, "--", "bash -s"}, "", "uptime\ndf -h /\n"},
		{"read-only reader of data", []string{"exec", "prod", "--read-only", "--stdin-file", data, "--", "wc -l"}, "", "id,cmd\n1,rm -rf /x\n2,a > b\n"},
		{"read-only SQL as input", []string{"exec", "prod", "--read-only", "--stdin-file", report, "--", "psql app"}, "", "select count(*) from t where n > 5;\n"},
		{"read-only SQL input with a shell escape", []string{"exec", "prod", "--read-only", "--stdin-file", escape, "--", "psql app"}, "READ_ONLY_VIOLATION", ""},
		{"script arguments after --", []string{"exec", "prod", "--read-only", "--stdin-file", positional, "--", "bash -s -- -delete"}, "READ_ONLY_VIOLATION", ""},
		{"script --arg", []string{"script", "prod", positional, "--read-only", "--arg", "-delete"}, "READ_ONLY_VIOLATION", ""},
		{"script with #!/bin/bash", []string{"script", "prod", shebang, "--read-only"}, "", bashScript},
		{"script with #!/usr/bin/env bash", []string{"script", "prod", envBang, "--read-only"}, "", envScript},
		{"bash -s with #!/bin/bash", []string{"exec", "prod", "--read-only", "--stdin-file", shebang, "--", "bash -s"}, "", bashScript},
		{"bash -s with #!/usr/bin/env bash", []string{"exec", "prod", "--read-only", "--stdin-file", envBang, "--", "bash -s"}, "", envScript},
		{"env value that runs code", []string{"exec", "prod", "--read-only", "-e", "PS4=$(rm -rf /data)", "--", "bash -xc :"}, "READ_ONLY_VIOLATION", ""},
		{"env value filled in, read-only", []string{"exec", "prod", "--read-only", "-e", "DIR=/var/log", "--", "find $DIR -name '*.gz'"}, "", ""},
		{"read-only, input piped into a shell", []string{"exec", "prod", "--read-only", "--stdin-file", benign, "--", "cat | sh"}, "READ_ONLY_VIOLATION", ""},
		{"no --read-only on protected", []string{"exec", "prod", "--stdin-file", benign, "--", "bash -s"}, "PROTECTED_HOST", ""},
		{"interpreter tee", []string{"script", "prod", "--read-only", "--interpreter", "tee /etc/passwd", benign}, "READ_ONLY_VIOLATION", ""},
		{"interpreter with -c", []string{"script", "prod", "--read-only", "--interpreter", `sh -c "systemctl stop nginx" #`, benign}, "READ_ONLY_VIOLATION", ""},
		{"interpreter python", []string{"script", "prod", "--read-only", "--interpreter", "python3", benign}, "READ_ONLY_VIOLATION", ""},
		{"read-only shell script", []string{"script", "prod", "--read-only", "--interpreter", "bash -eu", benign}, "", "uptime\ndf -h /\n"},
		{"read-only script that writes", []string{"script", "prod", "--read-only", writes}, "READ_ONLY_VIOLATION", ""},
		{"env value turns find into a delete", []string{"exec", "prod", "--read-only", "-e", "X=-delete", "--", "find /srv $X"}, "READ_ONLY_VIOLATION", ""},
		{"job: env value", []string{"job", "start", "prod", "--read-only", "-e", "X=-delete", "--", "find /srv $X"}, "READ_ONLY_VIOLATION", ""},
		// --read-only is an allowlist on a protected target: a command
		// komando does not know reads still needs --yes, even though the
		// denylist lets it pass (it changes nothing komando can see)
		{"allowlist: unknown command needs --yes", []string{"exec", "prod", "--read-only", "--", "mytool --status"}, "PROTECTED_HOST", ""},
		{"allowlist: unknown in a pipe needs --yes", []string{"exec", "prod", "--read-only", "--", "cat /etc/hosts | mytool"}, "PROTECTED_HOST", ""},
		{"allowlist: unknown in a shell needs --yes", []string{"exec", "prod", "--read-only", "--", "sh -c 'mytool --status'"}, "PROTECTED_HOST", ""},
		{"allowlist: unknown script command needs --yes", []string{"exec", "prod", "--read-only", "--stdin-file", benign, "--", "bash -s"}, "", "uptime\ndf -h /\n"},
		{"allowlist: known read runs", []string{"exec", "prod", "--read-only", "--", "cat /etc/hostname"}, "", ""},
		{"allowlist: ps runs", []string{"exec", "prod", "--read-only", "--", "ps aux | grep nginx"}, "", ""},
		{"allowlist: docker ps runs", []string{"exec", "prod", "--read-only", "--", "docker ps"}, "", ""},
		{"allowlist: docker rm is a clear write", []string{"exec", "prod", "--read-only", "--", "docker rm web"}, "READ_ONLY_VIOLATION", ""},
		{"allowlist: systemctl status runs", []string{"exec", "prod", "--read-only", "--", "systemctl status nginx"}, "", ""},
		{"allowlist: job unknown needs --yes", []string{"job", "start", "prod", "--read-only", "--", "mytool --status"}, "PROTECTED_HOST", ""},
	}
	for _, c := range cases {
		err := runRoot(t, c.args...)
		code := ""
		if err != nil {
			code = toErr(err).Code
		}
		execs := srv.take()
		if code != c.code {
			t.Errorf("%s: error %q, want %q (%v)", c.name, code, c.code, err)
		}
		if c.code != "" && len(execs) != 0 {
			t.Errorf("%s: the server ran %d command(s): %+v", c.name, len(execs), execs)
		}
		if c.code == "" && (len(execs) != 1 || execs[0].stdin != c.stdin) {
			t.Errorf("%s: the server got %+v, want one run with input %q", c.name, execs, c.stdin)
		}
	}
}

// A --var value cannot turn into an option, and a read-only recipe is
// held to its promise once filled in.
func TestRecipeVarsChecked(t *testing.T) {
	srv := startFakeServer(t)
	cases := []struct {
		args []string
		code string
	}{
		{[]string{"recipe", "run", "big-files", "prod", "--var", "path=-delete"}, "OPTION_LIKE_VAR"},
		{[]string{"recipe", "run", "big-dirs", "prod", "--var", "path=--files0-from=/etc/x"}, "OPTION_LIKE_VAR"},
		{[]string{"recipe", "run", "big-dirs", "prod", "--var", "path=-o/etc/x"}, "OPTION_LIKE_VAR"},
		{[]string{"recipe", "run", "oom", "prod", "--var", "since=-2h"}, ""}, // a relative time
		{[]string{"recipe", "run", "big-files", "prod", "--var", "path=./-odd-dir"}, ""},
		{[]string{"recipe", "add", "wipe", "find {{path=/srv}} -delete", "--read-only"}, "READ_ONLY_VIOLATION"},
	}
	for _, c := range cases {
		err := runRoot(t, c.args...)
		code := ""
		if err != nil {
			code = toErr(err).Code
		}
		n := len(srv.take())
		if code != c.code {
			t.Errorf("%v: error %q, want %q (%v)", c.args, code, c.code, err)
		}
		if c.code != "" && n != 0 {
			t.Errorf("%v: the server ran it", c.args)
		}
	}
	// a saved read-only recipe that does not keep the promise once filled
	// in (or under a stricter check than when it was saved) runs as a
	// change: a protected server needs --yes, and then it runs
	if err := store.Update(func(st *store.State) error {
		st.Snippets["peek"] = &store.Snippet{Name: "peek", Command: "cat {{f}}", ReadOnly: true}
		st.Snippets["finder"] = &store.Snippet{Name: "finder", Command: "find /data/app -name {{n}} -exec {{x}} {} +", ReadOnly: true}
		st.Snippets["procs"] = &store.Snippet{Name: "procs", Command: "ps aux | python3 -c 'import sys'", ReadOnly: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"finder", "procs"} {
		args := []string{"recipe", "run", name, "prod", "--var", "n=x", "--var", "x=rm"}
		if name == "procs" {
			args = args[:4]
		}
		if err := runRoot(t, args...); toErr(err) == nil || toErr(err).Code != "PROTECTED_HOST" {
			t.Errorf("%s: %v", name, err)
		}
		if n := len(srv.take()); n != 0 {
			t.Errorf("%s ran without --yes", name)
		}
		if err := runRoot(t, append([]string{"--yes"}, args...)...); err != nil {
			t.Errorf("%s --yes: %v", name, err)
		}
		if n := len(srv.take()); n != 1 {
			t.Errorf("%s --yes: %d runs", name, n)
		}
	}
	if err := runRoot(t, "recipe", "run", "peek", "prod", "--var", "f=/etc/hosts"); err != nil {
		t.Errorf("peek: %v", err)
	}
	srv.take()
}

// Every built-in read-only recipe, filled in with its defaults, passes the
// read-only check (recipe run applies it).
func TestBuiltinRecipesAreReadOnly(t *testing.T) {
	for _, r := range recipes {
		if r.Mutating {
			continue
		}
		vars := map[string]string{}
		for _, m := range tmplRe.FindAllStringSubmatch(r.Cmd, -1) {
			if d, ok := r.Params[m[1]]; ok && d == "" {
				vars[m[1]] = "example.com"
			}
		}
		cmd, err := render(r.Cmd, r.Params, vars)
		if err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		if w := readOnlyViolation(cmd); w != "" {
			t.Errorf("%s: %q", r.Name, w)
		}
	}
}

// Streamed output is redacted by whole lines, so a secret split across
// two reads does not reach the agent in pieces.
func TestStreamRedactsSplitSecrets(t *testing.T) {
	srv := startFakeServer(t)
	asAgent(t, false, true) // agents get masking
	cases := []struct {
		chunks []string
		leaks  []string
	}{
		{[]string{"export DB_PASS", "WORD=hunter2hunter2\n"}, []string{"hunter2hunter2"}},
		{[]string{"line one\nAPI_TOKEN=abcd", "efgh1234ijkl\n"}, []string{"efgh1234ijkl"}},
		{[]string{"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAE\n", "QyNTUxOQAAACDUMMYBODYKEY\n-----END OPENSSH PRIVATE KEY-----\n"}, []string{"b3BlbnNzaC1rZXkt", "DUMMYBODYKEY"}},
		{[]string{"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAE\nQyNTUxOQAAACDUMMYBODYKEY\n-----END OPENSSH PRIVATE KEY-----\n"}, []string{"b3BlbnNzaC1rZXkt", "DUMMYBODYKEY"}},
	}
	for i, c := range cases {
		srv.reply(c.chunks...)
		for _, format := range []string{"json", "text"} {
			got := captureOutput(t, func() error {
				return runRoot(t, "-o", format, "exec", "prod", "--read-only", "--stream", "--", "tail -f /var/log/app.log")
			})
			for _, l := range c.leaks {
				if strings.Contains(got, l) {
					t.Errorf("case %d, %s: %q leaked:\n%s", i, format, l, got)
				}
			}
			if format == "json" && !strings.Contains(got, `"event":"output"`) {
				t.Errorf("case %d: no output events:\n%s", i, got)
			}
		}
		srv.take()
	}
}

// captureOutput collects what komando prints, both through out.P and on
// stdout and stderr (the text stream).
func captureOutput(t *testing.T, run func() error) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	savedOut, savedErr, savedW := os.Stdout, os.Stderr, out.P.W
	os.Stdout, os.Stderr, out.P.W = w, w, w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	err = run()
	_ = w.Close()
	os.Stdout, os.Stderr, out.P.W = savedOut, savedErr, savedW
	got := <-done
	if err != nil {
		t.Logf("run: %v", err)
	}
	return got
}

func TestLineBuffer(t *testing.T) {
	p := &out.Printer{Mask: true, Secrets: func() map[string]string { return map[string]string{"DB_PASS": "S3cretVaultValue-9921"} }}
	long := strings.Repeat("x", streamCap+10)
	cases := []struct {
		chunks []string
		leaks  []string
	}{
		{[]string{"db password is S3cretVaul", "tValue-9921 ok\n"}, []string{"S3cretVaul", "tValue-9921"}},
		{[]string{"a\nb S3cret", "VaultValue-9921", " c\nd"}, []string{"S3cretVaultValue-9921", "VaultValue"}},
		{[]string{"-----BEGIN RSA PRIV", "ATE KEY-----\nMIIEdummyKEYbody1\n", "MIIEdummyKEYbody2\n-----END RSA PRIVATE KEY-----\nok\n"}, []string{"dummyKEYbody"}},
		{[]string{"-----BEGIN EC PRIVATE KEY-----\nMIIEdummyKEYbody1\n"}, []string{"dummyKEYbody"}}, // never closed: hidden to the end
		{[]string{long, "S3cretVaultValue-9921\n"}, []string{"S3cretVaultValue-9921"}},
	}
	for i, c := range cases {
		var b lineBuffer
		var got, whole strings.Builder
		for _, ch := range c.chunks {
			got.WriteString(p.Redact(b.add([]byte(ch))))
			whole.WriteString(ch)
		}
		got.WriteString(p.Redact(b.flush()))
		for _, l := range c.leaks {
			if strings.Contains(got.String(), l) {
				t.Errorf("case %d: %q leaked: %.200q", i, l, got.String())
			}
		}
		if want := p.Redact(whole.String()); got.String() != want {
			t.Errorf("case %d: got %.200q, want %.200q", i, got.String(), want)
		}
	}
	var b lineBuffer
	if s := b.add([]byte("one\ntw")); s != "one\n" {
		t.Errorf("add = %q", s)
	}
	if s := b.add([]byte("o\n")); s != "two\n" {
		t.Errorf("add = %q", s)
	}
	if s := b.add([]byte(strings.Repeat("y", streamCap+1))); len(s) != streamCap+1-streamKeep {
		t.Errorf("a long line: %d bytes out", len(s))
	}
}

// A custom deny pattern that does not compile fails doctor and is marked in
// policy list, and every command is blocked until it is fixed.
func TestInvalidDenyPatternReported(t *testing.T) {
	startFakeServer(t)
	if err := store.Update(func(st *store.State) error {
		st.Settings.ExtraDenyPattern = []string{`kubectl\s+delete(`}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	st, err := loadState()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range securityChecks(st) {
		if c.Name == "security:deny_rule:custom-0" {
			found = !c.OK && strings.Contains(c.Detail, "not a valid regular expression")
		}
	}
	if !found {
		t.Error("doctor does not report the broken deny rule")
	}
	got := captureOutput(t, func() error { return runRoot(t, "policy", "list") })
	if !strings.Contains(got, `"error":"custom deny pattern`) {
		t.Errorf("policy list: %s", got)
	}
	if err := runRoot(t, "exec", "prod", "--read-only", "--", "uptime"); toErr(err) == nil || toErr(err).Code != "POLICY_BLOCKED" {
		t.Errorf("exec with a broken rule: %v", err)
	}
}

// Forms that slipped past the read-only check, and everyday reads that
// must stay read-only.
func TestReadOnlyBypassesClosed(t *testing.T) {
	writes := []string{
		// options and arguments around -c
		`bash -c -- 'rm -rf /data'`,
		`bash -c -e 'rm -rf /data'`,
		`bash -o pipefail -c -- 'rm -rf /data'`,
		`sh -c 'find /data "$0"' -delete`,
		`bash -c 'find /data $1' x -delete`,
		`bash -c 'r"$1" -rf /data' x m`,
		// values komando cannot see, in a command whose arguments decide
		`X=-delete; find /data $X`,
		`find /data $(echo -delete)`,
		"find /data `echo -delete`",
		`set -- -delete; find /data "$1"`,
		`echo -delete | xargs find /data`,
		`printf -- '-exec\nrm\n{}\n;' | xargs find /data`,
		`ls | xargs sh -c 'rm $0'`,
		`kubectl -n "$NS" delete pod x`,
		// comments, here-documents and case in $( )
		"echo hi # it's\nrm -rf /data\n#'",
		"cat <<EOF\nit's\nEOF\nrm -rf /data",
		"cat <<-'EOF'\n\tit's\n\tEOF\nrm -rf /data",
		"cat <<EOF\n$(rm -rf /data)\nEOF",
		`echo $(case 1 in *) rm -rf /data;; esac)`,
		`echo 'unclosed`,
		`echo "unclosed`,
		`echo $(ls`,
		// brace expansion
		`{rm,-rf,/data}`,
		// variables that run code
		`PS4='$(rm -rf /data)' bash -xc :`,
		`echo 'rm -rf /data' | BASH_ENV=/dev/stdin bash -c :`,
		`env 'BASH_FUNC_x%%=() { rm -rf /data; }' bash -c x`,
		`LD_PRELOAD=/tmp/x.so ls`,
		`export PROMPT_COMMAND='rm -rf /data'`,
		`sudo GIT_SSH_COMMAND='rm -rf /data' git ls-remote x`,
		// builtins and tools that run commands or write
		`hash -p /bin/rm cat; cat /data/x`,
		`git -c alias.zz='!rm -rf /data' zz`,
		`git --config-env=core.pager=X log`,
		`echo x | sed 'e rm -rf /data'`,
		`sed -n 'w /etc/cron.d/x' f`,
		`sed 's/a/b/w /etc/x' f`,
		`sed '1e id' f`,
		`sed -e 's/x/rm -rf \/data/e' f`,
		`sed -f prog.sed f`,
		`gawk --source='BEGIN{system("rm")}'`,
		`gawk -e 'BEGIN{system("rm")}'`,
		`gawk 'BEGIN{f="sys" "tem"; @f("rm -rf /data")}'`,
		`awk '{print | "sh"}' f`,
		`awk 'BEGIN{"rm x" | getline}'`,
		`tar -cf /dev/null /etc --checkpoint=1 --checkpoint-action=exec='rm -rf /data'`,
		`tar xzf a.tgz`,
		`tar -xf a.tar`,
		`tar -cf /tmp/backup.tar /etc`,
		`tar -I 'sh -c x' -tf a`,
		`vim -es -c '!rm -rf /data' -c q`,
		`script -qc 'rm -rf /data' /dev/null`,
		`sg root -c 'rm -rf /data'`,
		`psql -c '\! rm -rf /data'`,
		`psql -Atc '\o /tmp/x'`,
		`psql -f report.sql`,
		`echo '\! rm' | psql app`,
		`psql app < q.sql`,
		`mysql -e 'system rm -rf /data'`,
		`psql -c 'DROP TABLE users'`,
		`psql -Atc "delete from users where id = 1"`,
		`psql -c 'select 1; update t set a = 1'`,
		`psql -c 'with x as (delete from t returning *) select * from x'`,
		`psql -c 'select * into t2 from t'`,
		`psql -c 'select pg_terminate_backend(42)'`,
		`mysql -e 'TRUNCATE t'`,
		`mysql -e "SET GLOBAL max_connections = 10"`,
		`mysql -e $'select 1 # comment\n; insert into t values (1)'`,
		`mariadb --execute='insert into t values (1)'`,
		`psql -c "select 'a\\'; delete from t; select '"`,
		`sort -o /etc/hosts /etc/hosts`,
		`sort -uo out.txt in.txt`,
		`uniq a /tmp/out`,
		`split -l 1 f /tmp/p`,
		`openssl rand -out /tmp/x 8`,
		`openssl req -new -keyout k.pem -nodes`,
		`date -s 2020-01-01`,
		`date --set='2020-01-01'`,
		`date 010100002020`,
		`hostname newname`,
		`hostname -F /etc/hostname`,
		`dmesg -C`,
		`dmesg -c`,
		`dmesg -n 1`,
		`less +'!rm x' f`,
		`less -o /tmp/copy f`,
		`redis-cli flushall`,
		`redis-cli -h r1 -n 2 del session:1`,
		`redis-cli config set maxmemory 1mb`,
		`redis-cli --pipe < cmds.txt`,
		`valkey-cli -a pw set k v`,
		`redis-cli --cluster reshard r1:6379`,
		`echo 'del k' | redis-cli`,
		`mysql --pager='rm -rf /data'`,
		`chrt -o 0 rm /data/x`,
		`taskset 1 rm /data/x`,
		`taskset 0x3 rm /data/x`,
		`numactl -N 0 rm /data/x`,
		`faketime '2020-01-01' rm /data/x`,
		// global options before the subcommand
		`kubectl -n prod delete pod x`,
		`systemctl -H db1 restart nginx`,
		`docker --context prod rm -f x`,
		`apt-get -o Dpkg::Options::=x install evil`,
		`iptables -t nat -A PREROUTING -j DROP`,
		// commands that write files
		`gzip /data/db.sql`,
		`gunzip /data/db.sql.gz`,
		`xz -T0 /data/x`,
		`unzip a.zip`,
		`patch -p1 < x.diff`,
		`curl -o /etc/x http://h/`,
		`curl -O http://h/x`,
		`curl -sSLo /etc/x http://h/`,
		`curl -X DELETE http://localhost:9200/idx`,
		`curl -d '{}' http://h/`,
		`curl -T f ftp://h/`,
		`wget http://h/x`,
		`wget -O /etc/x http://h/`,
		`sqlite3 app.db 'DELETE FROM t'`,
		`crontab file`,
		`crontab`,
		`docker exec c rm /x`,
		`kubectl exec pod -- rm /x`,
		`git branch -D main`,
		`git tag v1`,
		`git config user.name x`,
		`git stash`,
		`git diff --output=/etc/x`,
		`npm run build`,
	}
	for _, c := range writes {
		if w := readOnlyViolation(c); w == "" {
			t.Errorf("%q: read-only, want a violation", c)
		}
	}
	reads := []string{
		"#!/bin/bash\nset -eu\ndf -h\n",
		"#!/bin/sh\nls\n",
		"#!/usr/bin/env bash\n# check disk\ndf -h / # root\n",
		"cat <<EOF\nit's fine, don't worry\nEOF\nuptime",
		"cat <<'EOF'\n$(rm -rf /data)\nEOF",
		`echo $(case x in a) echo a;; esac)`,
		`ps aux | awk '/systemd/'`,
		`awk '/filesystem/' f`,
		`awk '/ERROR|WARN/' log`,
		`awk '$1 == "a" || $2 == "b"' f`,
		`awk '{print "a > b"}' f`,
		`node -v`,
		`php -v`,
		`perl -v`,
		`bash --version`,
		"exec 2>&1; ls",
		`bash -c 'ls $1' x /etc`,
		`sed -n '1,5p' f`,
		`sed 's/a/b/g' f`,
		`sed -e '/^#/d' -e 's/x/y/' f`,
		`sed -n '/start/,/end/p' f`,
		`tar -tzf a.tgz`,
		`tar tzf a.tgz`,
		`tar -czf - /etc | wc -c`,
		`curl -s http://localhost/health`,
		`curl -fsS -o /dev/null -w '%{http_code}' http://h/`,
		`curl -H 'Accept: x' -X GET http://h/`,
		`wget -qO- http://h/`,
		`wget --spider http://h/`,
		`gzip -dc x.gz | head`,
		`zcat x.gz`,
		`cat x | gzip | wc -c`,
		`unzip -l a.zip`,
		`patch --dry-run -p1 < x.diff`,
		`crontab -l`,
		`crontab -u bob -l`,
		`kubectl -n prod get pods`,
		`systemctl -H db1 status nginx`,
		`docker --context prod ps`,
		`git log --oneline -5`,
		`git -C /srv/app status`,
		`git branch -a`,
		`git branch`,
		`git tag -l 'v*'`,
		`git config --get user.name`,
		`git config user.name`,
		`git remote -v`,
		`git stash list`,
		`psql -Atc 'select 1'`,
		`mysql -e 'SHOW PROCESSLIST'`,
		`psql -c '\dt'`,
		`sort -n -k2 f`,
		`sort -u f | head`,
		`uniq -c f`,
		`uniq -f 2 f`,
		`openssl x509 -in c.pem -noout -text`,
		`date +%s`,
		`date -d @1700000000 -u`,
		`date --date='yesterday' +%F`,
		`date --date tomorrow`,
		`psql -c "select E'it\\'s' as a"`,
		`hostname`,
		`hostname -I`,
		`dmesg -T --level=err,warn`,
		`dmesg -H -x`,
		`less -R f`,
		`redis-cli -h r1 -p 6380 info memory`,
		`redis-cli --scan --pattern 'sess:*' --count 100`,
		`redis-cli -n 2 get k`,
		`redis-cli --bigkeys`,
		`redis-cli config get maxmemory`,
		`redis-cli --cluster check r1:6379`,
		`psql -c "select 'drop table x; delete' as note, comment, role from t"`,
		`psql -c 'select replace(name, $$a$$, $$b$$) from t -- update later'`,
		`psql -c 'explain select * from t'`,
		`psql -c 'set statement_timeout = 1000; select 1'`,
		`mysql -e $'select a # delete\n from t'`,
		`chrt -p 1234`,
		`taskset -c 0 ls`,
		`echo it\'s`,
		`grep "it's" f`,
		`find /var/log -name '*.log' -mtime +7`,
		`ls {a,b}`,
		`FOO=1 ls`,
		`for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u"; done`,
	}
	for _, c := range reads {
		if w := readOnlyViolation(c); w != "" {
			t.Errorf("%q: %q, want read-only", c, w)
		}
	}
}

// --dry-run is never blocked by the check of the input or of the
// read-only promise; it says what the real run would need.
func TestDryRunReportsInputStops(t *testing.T) {
	srv := startFakeServer(t)
	tmp := t.TempDir()
	evil := filepath.Join(tmp, "evil.sh")
	_ = os.WriteFile(evil, []byte("rm -rf / --no-preserve-root\n"), 0o600)
	writes := filepath.Join(tmp, "writes.sh")
	_ = os.WriteFile(writes, []byte("echo x | tee /etc/motd\n"), 0o600)
	cases := []struct {
		args []string
		code string
	}{
		{[]string{"--dry-run", "exec", "dev", "--stdin-file", evil, "--", "bash -s"}, "POLICY_BLOCKED"},
		{[]string{"--dry-run", "script", "dev", evil}, "POLICY_BLOCKED"},
		{[]string{"--dry-run", "exec", "prod", "--read-only", "--stdin-file", writes, "--", "bash -s"}, "READ_ONLY_VIOLATION"},
	}
	for _, c := range cases {
		out.P.Reset()
		var err error
		got := captureOutput(t, func() error { err = runRoot(t, c.args...); return err })
		if err != nil {
			t.Errorf("%v: %v", c.args, err)
		}
		if !strings.Contains(got, `"would_be_blocked"`) || !strings.Contains(got, c.code) {
			t.Errorf("%v: no would_be_blocked %s:\n%s", c.args, c.code, got)
		}
		if n := len(srv.take()); n != 0 {
			t.Errorf("%v: the server ran it", c.args)
		}
	}
	out.P.Reset()
}

// A line that only mentions a key header (a log, a grep) holds the
// stream for at most pemHold; then the lines after it come out, and the
// key-like lines right after the header stay hidden.
func TestLineBufferPEMMention(t *testing.T) {
	var b lineBuffer
	var got strings.Builder
	got.WriteString(b.add([]byte("before\naudit: found -----BEGIN RSA PRIVATE KEY----- in /tmp/x\nMIIEdummyKEYbody1\n")))
	if got.String() != "before\n" {
		t.Errorf("held too little: %q", got.String())
	}
	line := "2026-11-05 GET /health 200 ok\n"
	for i := 0; i < 2*pemHold/len(line); i++ {
		got.WriteString(b.add([]byte(line)))
	}
	s := got.String()
	if !strings.Contains(s, "[hidden: private key]\n"+line) || strings.Count(s, line) < pemHold/len(line) {
		t.Errorf("the lines after the mention did not come out (%d bytes): %.300q", len(s), s)
	}
	if strings.Contains(s, "dummyKEYbody") || strings.Contains(s, "BEGIN RSA") {
		t.Errorf("key-like text leaked: %.300q", s)
	}
	// a real key, even a long one, is still held to its END line
	var k lineBuffer
	body := strings.Repeat("MIIEdummyKEYbodyMIIEdummyKEYbodyMIIEdummyKEYbodyMIIEdummyKEYbody\n", 100)
	if s := k.add([]byte("-----BEGIN OPENSSH PRIVATE KEY-----\n" + body)); s != "" {
		t.Errorf("a key was let out: %.100q", s)
	}
	if s := k.add([]byte("-----END OPENSSH PRIVATE KEY-----\n")); !strings.Contains(s, "END OPENSSH") {
		t.Errorf("the key did not come out whole: %.100q", s)
	}
}
