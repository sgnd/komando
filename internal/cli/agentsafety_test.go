package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// noAgent runs the rest of a test with none of the agent variables there
// (an empty one still names an agent).
func noAgent(t *testing.T) {
	t.Helper()
	for _, a := range agentVars {
		t.Setenv(a.env, "") // restored after the test
		os.Unsetenv(a.env)
		resetApproval()
	}
	resetApproval() // the caller is read when a call starts
	t.Cleanup(resetApproval)
}

// An agent cannot opt out by changing its own variables: komando counts
// any value, a second variable still names the agent, and the guard stops
// the shell lines that change them.
func TestAgentCannotClearItsVariables(t *testing.T) {
	for _, v := range []string{"0", "false", "1"} {
		t.Setenv("CLAUDECODE", v)
		resetApproval()
		t.Cleanup(resetApproval)
		if agentName() != "Claude Code" {
			t.Errorf("CLAUDECODE=%s: agentName = %q", v, agentName())
		}
	}
	t.Setenv("CLAUDECODE", "")
	resetApproval()
	t.Cleanup(resetApproval)
	if agentName() != "Claude Code" {
		t.Errorf("CLAUDECODE empty: agentName = %q", agentName())
	}
	noAgent(t)
	t.Setenv("CLAUDE_CODE_ENTRYPOINT", "cli")
	resetApproval()
	t.Cleanup(resetApproval)
	if agentName() != "Claude Code" {
		t.Errorf("CLAUDECODE cleared, CLAUDE_CODE_ENTRYPOINT set: agentName = %q", agentName())
	}

	home := "/Users/me"
	t.Setenv("KOMANDO_HOME", "")
	for line, block := range map[string]bool{
		"CLAUDECODE=0 komando exec prod --yes --allow-dangerous -- 'rm -rf /srv'": true,
		"CLAUDECODE= komando fs cat prod /app/.env":                               true,
		"CLAUDE_CODE_ENTRYPOINT= CLAUDECODE= komando list":                        true,
		"env -u CLAUDECODE komando exec prod --yes -- reboot":                     true,
		"env -uCLAUDECODE komando list":                                           true,
		"env --unset=CLAUDECODE komando list":                                     true,
		"/usr/bin/env -u CLAUDE_CODE_ENTRYPOINT komando list":                     true,
		"env -i PATH=/usr/bin komando list":                                       true,
		"env - komando list":                                                      true,
		"env CLAUDECODE=0 komando list":                                           true,
		"unset CLAUDECODE; komando fs cat prod /app/.env":                         true,
		"unset -v GEMINI_CLI CURSOR_AGENT":                                        true,
		"export CLAUDECODE=0 && komando cp prod:/app/.env ./notes.txt":            true,
		"export -n CLAUDECODE":                                                    true,
		"sudo -u app CLAUDECODE=0 komando list":                                   true,
		"bash -c 'unset CLAUDECODE; komando list'":                                true,
		`sh -c "env -u CLAUDECODE komando list"`:                                  true,
		"eval 'CLAUDECODE=0 komando list'":                                        true,
		// a wrapper's flag value is not the program: these are still ssh
		"env -u FOO ssh web1 uptime": true,
		"sudo -u app ssh web1":       true,
		// talking about the variables is fine
		"grep -rn CLAUDECODE= internal/cli":              false,
		"git commit -m 'CLAUDECODE=0 is still an agent'": false,
		`echo "$CLAUDECODE"`:                             false,
		"env GOOS=linux go build ./...":                  false,
		"env -u GOFLAGS go test ./...":                   false,
		// KOMANDO_HOME moves komando's data: a fresh folder knows no
		// protected servers, deny rules or host keys
		"KOMANDO_HOME=$(mktemp -d) komando list":                     true,
		"export KOMANDO_HOME=/tmp/k; komando host add prod 10.0.0.1": true,
		"unset KOMANDO_HOME":                         true,
		"env -u KOMANDO_HOME komando list":           true,
		"env KOMANDO_HOME=/tmp/k komando list":       true,
		"bash -c 'KOMANDO_HOME=/tmp/k komando list'": true,
		"read KOMANDO_HOME </dev/null":               true,
		"unset -m 'KOMANDO_H*'":                      true,
		`echo "$KOMANDO_HOME"`:                       false,
		"KOMANDO_OUTPUT=json komando list":           false,
		"export KOMANDO_ACTOR=claude":                false,
		"CLAUDECODE=1 komando list":                  true, // any change is refused: KISS
		// env's flag clusters, GNU long-option starts and -S
		"env -vu CLAUDECODE -vu CLAUDE_CODE_ENTRYPOINT komando list --reveal": true,
		"env -0u CLAUDECODE komando list":                                     true,
		"env -S '-u CLAUDECODE -u CLAUDE_CODE_ENTRYPOINT komando list'":       true,
		"env --split-string='-i komando list'":                                true,
		"env --ignore-env komando list":                                       true,
		"env --uns=CLAUDECODE komando list":                                   true,
		"env -iv komando list":                                                true,
		"busybox env -u CLAUDECODE komando list":                              true,
		"exec -c komando list --reveal":                                       true,
		"exec -cl komando list":                                               true,
		// names the shell works out: brace lists, prefixes, patterns, $V
		"unset CLAUDE{CODE,_CODE_ENTRYPOINT}": true,
		"unset ${!CLAUDE*}":                   true,
		"unset -m 'CLAUDE*'":                  true,
		"typeset -m 'C?AUDECODE'":             true,
		"v=CLAUDECODE; unset $v":              true,
		"declare +x CLAUDECODE":               true,
		"export CLAUDECODE+=x":                true,
		"unset 'CLAUDECOD[E]'":                true,
		// statements that start with a keyword or a prefix
		"{ unset CLAUDECODE; komando list; }":           true,
		"! unset CLAUDECODE":                            true,
		"if true; then unset CLAUDECODE; fi":            true,
		"while unset CLAUDECODE; do komando list; done": true,
		"builtin unset CLAUDECODE":                      true,
		"command unset CLAUDECODE":                      true,
		"function f { unset CLAUDECODE; }":              true,
		// builtins that set a variable to an empty value
		"read CLAUDECODE CLAUDE_CODE_ENTRYPOINT </dev/null; komando list --reveal": true,
		"read -r -p 'x' CLAUDECODE":                   true,
		"read -a CLAUDECODE":                          true,
		"printf -v CLAUDECODE ''":                     true,
		"for CLAUDECODE in ''; do komando list; done": true,
		"mapfile -t CLAUDECODE </dev/null":            true,
		"getopts ab CLAUDECODE":                       true,
		// more wrappers
		"timeout 10 env -u CLAUDECODE komando list": true,
		"setsid env -u CLAUDECODE komando list":     true,
		"stdbuf -oL env -u CLAUDECODE komando list": true,
		"nohup env -i komando list":                 true,
		"chrt 10 env -i komando list":               true,
		"timeout -s KILL 10 env -i komando list":    true,
		"timeout 10 ssh web1 uptime":                true,
		// sudo starts komando with a clean environment
		"sudo komando list --reveal":       true,
		"sudo -u root komando list":        true,
		"doas komando list":                true,
		"sudo -E komando list":             false,
		"sudo --preserve-env komando list": false,
		// nested shells with -c in a cluster or after other options
		"bash -lc 'unset CLAUDECODE CLAUDE_CODE_ENTRYPOINT; komando list'": true,
		"sh -ec 'env -i komando list'":                                     true,
		"zsh -fc 'unset CLAUDECODE'":                                       true,
		"bash -c -- 'unset CLAUDECODE'":                                    true,
		"bash -o pipefail -c 'unset CLAUDECODE'":                           true,
		"bash <<'EOF'\nunset CLAUDECODE\nkomando list\nEOF":                true,
		// everyday lines stay allowed
		"read -r line < notes.txt":                      false,
		"for f in *.go; do gofmt -l $f; done":           false,
		"printf -v out '%s' x":                          false,
		"unset GOFLAGS; go test ./...":                  false,
		"export PATH=\"$HOME/bin:$PATH\"":               false,
		"timeout 60 go test ./...":                      false,
		"sudo systemctl restart nginx":                  false,
		"bash -lc 'go test ./...'":                      false,
		"if [ -f go.mod ]; then go build ./...; fi":     false,
		"cat <<'EOF' > notes.md\nunset CLAUDECODE\nEOF": false,
	} {
		if d := checkTool("Bash", map[string]any{"command": line}, home, ""); d.Deny != block {
			t.Errorf("%q: deny=%v (%s)", line, d.Deny, d.Reason)
		}
	}
}

// The guard reads relative paths from the hook's cwd, follows cd, and
// treats a glob that could name a protected path as that path.
func TestGuardCwdAndGlobs(t *testing.T) {
	home := "/Users/me"
	t.Setenv("KOMANDO_HOME", "")
	cases := []struct {
		tool, cwd string
		in        map[string]any
		block     bool
	}{
		{"Bash", "", map[string]any{"command": "cat ~/.komand?/vault.ke?"}, true},
		{"Bash", "", map[string]any{"command": "cat ~/.komand*/vault.k*"}, true},
		{"Bash", "", map[string]any{"command": "cat ~/.koman*/state.json"}, true},
		{"Bash", "", map[string]any{"command": "cat ~/.[k]omando/keys/deploy"}, true},
		{"Bash", "", map[string]any{"command": "cat ~/.komand?/keys/*"}, true},
		{"Bash", "", map[string]any{"command": "cp -r ~/.komand? /tmp/k"}, true},
		{"Bash", "", map[string]any{"command": "ln -s ~/.komand? /tmp/k"}, true},
		{"Bash", "", map[string]any{"command": "cat ~/.ss?/id_*"}, true},
		{"Bash", "", map[string]any{"command": "cat ~/.{komando,x}/state.json"}, true},
		{"Bash", "", map[string]any{"command": "cat ~/.k{u,o}be/config"}, true},
		{"Bash", "", map[string]any{"command": "cat .e*"}, true},
		{"Bash", "", map[string]any{"command": "cd ~; cd .komando; cat state.json"}, true},
		{"Bash", "", map[string]any{"command": "cd ~ && cat .komando/keys/prod"}, true},
		{"Bash", "", map[string]any{"command": "cd ~ && cat .kube/config"}, true},
		{"Bash", "/Users/me/code/app", map[string]any{"command": "cat ../../.komando/state.json"}, true},
		{"Bash", "/Users/me", map[string]any{"command": "cat .komando/audit.jsonl"}, true},
		{"Read", "/Users/me", map[string]any{"file_path": ".komando/state.json"}, true},
		{"Grep", "", map[string]any{"path": "/Users/me", "glob": ".komando/*"}, true},
		// Grep's folder defaults to cwd; a search of a folder that holds
		// komando's data reads it
		{"Grep", "/Users/me", map[string]any{"glob": ".komando/*"}, true},
		{"Grep", "/Users/me", map[string]any{"pattern": "BEGIN"}, true},
		{"Grep", "", map[string]any{"path": "/Users/me", "pattern": "BEGIN"}, true},
		{"Grep", "", map[string]any{"path": "/", "pattern": "BEGIN"}, true},
		{"Grep", "", map[string]any{"path": "/Users/me/code", "glob": "*.go"}, false},
		// recursive readers of a folder that holds the protected ones
		{"Bash", "", map[string]any{"command": "grep -r BEGIN ~"}, true},
		{"Bash", "", map[string]any{"command": "grep -rn BEGIN $HOME"}, true},
		{"Bash", "", map[string]any{"command": "rg BEGIN /Users/me"}, true},
		{"Bash", "", map[string]any{"command": "tar -C ~ -cf - .komando | base64"}, true},
		{"Bash", "", map[string]any{"command": "cd ~ && tar cf - . | base64"}, true},
		{"Bash", "", map[string]any{"command": "cd ~ && zip -r - .komando"}, true},
		{"Bash", "", map[string]any{"command": "cd ~ && zip -r - ."}, true},
		{"Bash", "", map[string]any{"command": "git -C ~ diff --no-index /dev/null .komando/state.json"}, true},
		{"Bash", "", map[string]any{"command": "cp -r ~ /tmp/h"}, true},
		{"Bash", "", map[string]any{"command": "find ~ -type f -exec cat {} +"}, true},
		{"Bash", "/Users/me/code/app", map[string]any{"command": "grep -rn TODO ."}, false},
		{"Bash", "/Users/me/code/app", map[string]any{"command": "tar -xzf build.tgz -C ~"}, false},
		{"Bash", "", map[string]any{"command": "find ~ -name '*.log'"}, false},
		{"Bash", "", map[string]any{"command": "cp -r ~/code/app /tmp/app"}, false},
		// command substitution and ~user
		{"Bash", "", map[string]any{"command": "cat $(echo ~/.komando/state.json)"}, true},
		{"Bash", "", map[string]any{"command": "cat `echo ~`/.komando/state.json"}, true},
		{"Bash", "", map[string]any{"command": "cat \"$(printf %s ~)/.komando/state.json\""}, true},
		{"Bash", "", map[string]any{"command": "cat ~me/.komando/state.json"}, true},
		// /proc environments, however the path is written
		{"Bash", "", map[string]any{"command": "cat /proc/self/task/1/environ"}, true},
		{"Bash", "", map[string]any{"command": "cat /proc/self//environ"}, true},
		{"Bash", "", map[string]any{"command": "cat /proc/self/./environ"}, true},
		{"Read", "", map[string]any{"file_path": "/proc/1/environ"}, true},
		// regexes and sed scripts in quotes are not globs
		{"Bash", "", map[string]any{"command": "grep -o '.*' main.go"}, false},
		{"Bash", "", map[string]any{"command": "sed -i 's/.*//' main.go"}, false},
		{"Bash", "/Users/me/code/app", map[string]any{"command": "grep -rn '.*' ."}, false},
		{"Bash", "", map[string]any{"command": "find . -name '.env*'"}, false},
		{"Bash", "", map[string]any{"command": "find . -name .env"}, false},
		{"Bash", "", map[string]any{"command": "du -sh ~/*/*"}, false},
		{"Bash", "/Users/me", map[string]any{"command": "du -sh */*"}, false},
		{"Bash", "", map[string]any{"command": "cat ~/Library/*/login.keychain-db"}, true},
		{"Bash", "", map[string]any{"command": "cat .e*"}, true},
		{"Bash", "", map[string]any{"command": "cat ~/.{komando,x}/state.json"}, true},
		{"Bash", "", map[string]any{"command": "cat ${HOME}/.komando/state.json"}, true},
		// not secrets
		{"Bash", "", map[string]any{"command": "cat ~/.ssh/*.pub"}, false},
		{"Bash", "", map[string]any{"command": "cat ~/.komando/keys/*.pub"}, false},
		{"Bash", "/Users/me/code/app", map[string]any{"command": "cat *.go && grep -rn TODO *"}, false},
		{"Bash", "/Users/me/code/app", map[string]any{"command": "cd src && cat main.go"}, false},
		{"Bash", "", map[string]any{"command": "cd - && cat state.json"}, false},
		{"Bash", "", map[string]any{"command": "grep -E 'a.*b' notes.txt"}, false},
		{"Grep", "", map[string]any{"path": "/Users/me/code", "glob": "*.go"}, false},
	}
	t.Run("unix paths", func(t *testing.T) {
		unixOnly(t, "the cases name a Unix home, /Users/me, which is not a full path on Windows; TestGuardGlobsUnderThisHome covers globs there")
		for _, c := range cases {
			if d := checkTool(c.tool, c.in, home, c.cwd); d.Deny != c.block {
				t.Errorf("%s %v (cwd %q): deny=%v (%s)", c.tool, c.in, c.cwd, d.Deny, d.Reason)
			}
		}
	})

	// files that are there: a glob that matches one, and a link to komando's folder
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	kh := filepath.Join(dir, "kh")
	proj := filepath.Join(dir, "proj")
	for _, d := range []string{kh, proj} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	setHome(t, kh)
	if err := os.WriteFile(filepath.Join(proj, "credentials.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(kh, filepath.Join(proj, "k")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		tool string
		in   map[string]any
	}{
		{"Bash", map[string]any{"command": "grep token cred*"}},
		{"Read", map[string]any{"file_path": filepath.Join(proj, "k", "state.json")}},
		{"Bash", map[string]any{"command": "cat k/state.json"}},
	} {
		if d := checkTool(c.tool, c.in, home, proj); !d.Deny {
			t.Errorf("%s %v: allowed", c.tool, c.in)
		}
	}

	// the other harnesses' hooks send cwd too
	if runtime.GOOS == "windows" {
		return // home is /Users/me, not a full path there
	}
	b, _ := json.Marshal(map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": "cat .komando/state.json"}, "cwd": home})
	t.Setenv("KOMANDO_HOME", "")
	if d := guardAgent("codex", b, home); !d.Deny {
		t.Error("codex hook with cwd: relative path to komando's data allowed")
	}
}

// Globs and /proc under a home that is a full path on every system: on
// Windows its parts are split by \, and /proc is written with /.
func TestGuardGlobsUnderThisHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KOMANDO_HOME", "")
	for line, block := range map[string]bool{
		"cat ~/.komand?/vault.ke?":    true,
		"cat ~/.komand*/keys/*":       true,
		"cat ~/.ss?/id_*":             true,
		"cat ~/.{komando,x}/store.db": true,
		"cat /proc/self/environ":      true,
		"cat ~/.ssh/*.pub":            false,
		"cat ~/code/*.go":             false,
		"du -sh ~/*/*":                false,
	} {
		if d := checkTool("Bash", map[string]any{"command": line}, home, ""); d.Deny != block {
			t.Errorf("%q: deny=%v (%s)", line, d.Deny, d.Reason)
		}
	}
	if d := checkTool("Read", map[string]any{"file_path": "/proc/1/environ"}, home, ""); !d.Deny {
		t.Error("Read /proc/1/environ allowed")
	}
}

// agentFiles makes a home with komando's data, a private key and a project.
func agentFiles(t *testing.T) (kh, home, proj string) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home, kh, proj = filepath.Join(dir, "home"), filepath.Join(dir, "kh"), filepath.Join(dir, "home", "proj")
	for _, d := range []string{kh, filepath.Join(home, ".ssh"), proj} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for p, s := range map[string]string{
		filepath.Join(kh, "vault.key"):                "FAKE-VAULT-KEY",
		filepath.Join(home, ".ssh", "id_ed25519"):     "FAKE-PRIVATE-KEY",
		filepath.Join(proj, ".env"):                   "DB_PASSWORD=x",
		filepath.Join(proj, "office.ovpn"):            "client",
		filepath.Join(proj, "deploy.sh"):              "echo hi",
		filepath.Join(home, ".ssh", "id_ed25519.pub"): "ssh-ed25519 AAAA",
	} {
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(kh, filepath.Join(proj, "link")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir reads USERPROFILE on Windows
	setHome(t, kh)
	t.Setenv("KOMANDO_VAULT_PASS", "test-passphrase-long-enough")
	return kh, home, proj
}

// komando does not read komando's own data, private keys or secret files
// on this computer for an AI agent (to send them to a server).
func TestLocalReadsForAgents(t *testing.T) {
	noAgent(t)
	kh, home, proj := agentFiles(t)
	defer func() { g.reveal = false }()
	read := func(p string) string {
		_, err := readLocalFile(p)
		if e := toErr(err); e != nil {
			return e.Code
		}
		return ""
	}
	// a script reads what it is given
	for _, p := range []string{filepath.Join(kh, "vault.key"), filepath.Join(home, ".ssh", "id_ed25519")} {
		if c := read(p); c != "" {
			t.Errorf("script: %s: %s", p, c)
		}
	}
	n := asAgent(t, true, true) // the person would allow
	cases := map[string]string{
		filepath.Join(kh, "vault.key"):                "SENSITIVE_FILE",
		filepath.Join(proj, "link", "vault.key"):      "SENSITIVE_FILE",
		filepath.Join(home, ".ssh", "id_ed25519"):     "SENSITIVE_FILE",
		filepath.Join(proj, ".env"):                   "SENSITIVE_FILE",
		filepath.Join(proj, "deploy.sh"):              "",
		filepath.Join(home, ".ssh", "id_ed25519.pub"): "",
	}
	// the same files by another case (macOS and Windows do not tell them
	// apart), by a hard link, and process environments
	saved := caseFoldFS
	caseFoldFS = true
	t.Cleanup(func() { caseFoldFS = saved })
	notes := filepath.Join(proj, "notes.txt")
	if err := os.Link(filepath.Join(kh, "vault.key"), notes); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{
		strings.ToUpper(kh) + "/vault.key":           "SENSITIVE_FILE",
		filepath.Join(home, ".SSH", "id_ed25519"):    "SENSITIVE_FILE",
		filepath.Join(home, ".Komando", "keys", "x"): "SENSITIVE_FILE",
		notes:                       "SENSITIVE_FILE",
		"/proc/self/environ":        "SENSITIVE_FILE",
		"/proc/self/task/1/environ": "SENSITIVE_FILE",
	} {
		cases[p] = want
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		// a public key read by another case: only these file systems find it
		cases[filepath.Join(home, ".SSH", "id_ed25519.pub")] = ""
	}
	for p, want := range cases {
		if c := read(p); c != want {
			t.Errorf("agent: %s: %q, want %q", p, c, want)
		}
	}
	if d := checkTool("Read", map[string]any{"file_path": notes}, home, ""); !d.Deny {
		t.Error("guard: a hard link to komando's data is allowed")
	}
	if *n != 0 {
		t.Errorf("no --reveal: %d windows", *n)
	}
	g.reveal = true // the person allows a project secret, never komando's data
	if c := read(filepath.Join(proj, ".env")); c != "" || *n != 1 {
		t.Errorf("--reveal allowed: %q, %d windows", c, *n)
	}
	for _, p := range []string{filepath.Join(kh, "vault.key"), notes, "/proc/self/environ"} {
		if c := read(p); c != "SENSITIVE_FILE" {
			t.Errorf("--reveal and %s: %q", p, c)
		}
	}

	// references a password is read from
	resolve := func(ref string) string {
		_, err := vault.Resolve(ref)
		if e := toErr(err); e != nil && e.Code == "SENSITIVE_FILE" {
			return e.Code
		}
		return ""
	}
	for ref, want := range map[string]string{
		"file:" + filepath.Join(kh, "vault.key"):            "SENSITIVE_FILE",
		"file:" + filepath.Join(home, ".ssh", "id_ed25519"): "SENSITIVE_FILE",
		"file:" + filepath.Join(proj, "office.ovpn"):        "", // what file: refs are for
		"file:" + filepath.Join(home, ".SSH", "id_ed25519"): "SENSITIVE_FILE",
		"file:" + notes:             "SENSITIVE_FILE",
		"file:/proc/self/environ":   "SENSITIVE_FILE",
		"env:KOMANDO_KDBX_PASSWORD": "SENSITIVE_FILE",
		"env:HOME":                  "",
	} {
		if c := resolve(ref); c != want {
			t.Errorf("agent ref %s: %q, want %q", ref, c, want)
		}
	}
	noAgent(t)
	if c := resolve("file:" + filepath.Join(home, ".ssh", "id_ed25519")); c != "" {
		t.Errorf("script ref: %s", c)
	}
}

// Imports move secrets into komando's vault, which the agent never sees,
// so an agent may point them at a credential file; komando's own data still
// never goes, and sending the same file to a server is still refused.
func TestImportsReadCredentialFilesForAgents(t *testing.T) {
	kh, home, _ := agentFiles(t)
	for _, f := range []string{filepath.Join(home, ".kube", "config"), filepath.Join(home, ".pgpass")} {
		if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	asAgent(t, false, false)
	for p, want := range map[string]string{
		filepath.Join(home, ".kube", "config"): "",
		filepath.Join(home, ".pgpass"):         "",
		filepath.Join(kh, "vault.key"):         "SENSITIVE_FILE",
	} {
		c := ""
		if _, err := readSource(p); err != nil {
			c = toErr(err).Code
		}
		if c != want {
			t.Errorf("import %s: %q, want %q", p, c, want)
		}
	}
	if _, err := readLocalFile(filepath.Join(home, ".pgpass")); toErr(err) == nil || toErr(err).Code != "SENSITIVE_FILE" {
		t.Errorf("exec --stdin-file ~/.pgpass: %v", err)
	}
}

// sync up of a folder that holds komando's data or private keys leaves
// those files here, each one checked as cp -r does.
func TestSyncUpChecksEachFileForAgents(t *testing.T) {
	_, home, _ := agentFiles(t)
	t.Cleanup(func() { g.reveal = false; out.P.Reset() })
	if err := os.MkdirAll(filepath.Join(home, ".komando"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".komando", "state.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, reveal := range []bool{false, true} {
		asAgent(t, true, true)
		g.reveal = reveal
		dst := t.TempDir()
		ctx := context.Background()
		if _, err := runSync(ctx, newAgentLocalSide(ctx, home), localSide{dst}, "home", "dst", syncOpts{}); err != nil {
			t.Fatal(err)
		}
		for rel, want := range map[string]bool{
			".komando/state.json": false, // never, even with --reveal
			".ssh/id_ed25519":     reveal,
			"proj/.env":           reveal,
			"proj/deploy.sh":      true,
			".ssh/id_ed25519.pub": true,
		} {
			_, err := os.Stat(filepath.Join(dst, rel))
			if got := err == nil; got != want {
				t.Errorf("reveal=%v: %s copied=%v, want %v", reveal, rel, got, want)
			}
		}
	}
}

// The commands that read a local path refuse before any connection.
func TestLocalReadCommandsForAgents(t *testing.T) {
	kh, home, proj := agentFiles(t)
	t.Cleanup(func() { g.dryRun, g.yes, g.allowDangerous, g.reveal, store.DryRun = false, false, false, false, false })
	mustRun(t, "host", "add", "web", "deploy@127.0.0.1:1")
	asAgent(t, false, false)
	key := filepath.Join(kh, "vault.key")
	for _, args := range [][]string{
		{"exec", "web", "--read-only", "--stdin-file", key, "--", "base64"},
		{"exec", "web", "--read-only", "--stdin-file", filepath.Join(proj, "link", "vault.key"), "--", "base64"},
		{"exec", "web", "--script", filepath.Join(home, ".ssh", "id_ed25519")},
		{"cp", filepath.Join(home, ".ssh", "id_ed25519"), "web:/tmp/k"},
		{"cp", "-r", kh, "web:/tmp/k"},
		{"sync", kh, "web:/tmp/k"},
	} {
		if _, e := invRun(t, args...); e == nil || e.Code != "SENSITIVE_FILE" {
			t.Errorf("%v: %+v", args, e)
		}
	}
}

// --dry-run --reveal shows nothing unmasked: a dry run never asks the
// person, and the preview still prints what it reads.
func TestDryRunRevealStaysMasked(t *testing.T) {
	invHome(t)
	t.Cleanup(func() { g.reveal, out.P.Mask = false, false })
	n := asAgent(t, true, true)
	g.dryRun, g.reveal = true, true
	if revealOK() {
		t.Error("revealOK under --dry-run")
	}
	g.dryRun, g.reveal = false, false
	mustRun(t, "list", "--dry-run", "--reveal")
	if !out.P.Mask || *n != 0 {
		t.Errorf("list --dry-run --reveal: mask=%v windows=%d", out.P.Mask, *n)
	}
	// an agent's preview that connects does it with the usual server
	// identity check
	mustRun(t, "list", "--dry-run", "--host-key-policy", "off")
	if g.hostKeyPolicy != "" || *n != 0 {
		t.Errorf("--dry-run --host-key-policy off: policy %q, windows %d", g.hostKeyPolicy, *n)
	}
	// a person's or a script's preview runs as the real run would
	noAgent(t)
	t.Cleanup(func() { g.yes, g.hostKeyPolicy = false, "" })
	mustRun(t, "list", "--dry-run", "--yes", "--host-key-policy", "off")
	if g.hostKeyPolicy != "off" {
		t.Errorf("script --dry-run --host-key-policy off: policy %q", g.hostKeyPolicy)
	}
}

// The approval window shows the whole command, the reason and the targets;
// a command it cannot show whole is refused without a window.
func TestApprovalWindowShowsEverything(t *testing.T) {
	saved := os.Args
	t.Cleanup(func() { os.Args = saved; g.allowDangerous, g.yes = false, false })
	t.Setenv("CLAUDECODE", "1")
	resetApproval()
	t.Cleanup(resetApproval)
	var texts []string
	savedAsk := askOnScreen
	askOnScreen = func(text string) (bool, bool) { texts = append(texts, text); return false, true }
	t.Cleanup(func() { askOnScreen = savedAsk; resetApproval() })

	st := &store.State{Hosts: map[string]*store.Host{"web": {Name: "web", Address: "10.0.0.1", Protected: true}}}
	hosts := []*store.Host{st.Hosts["web"]}
	g.allowDangerous, g.yes = true, true
	for _, c := range []struct {
		name, cmd string
		shown     string // the command as the window shows it; "" for no window
	}{
		{"plain", "rm -rf /var/lib", "'rm -rf /var/lib'"},
		{"long", "tail -n 50 /var/log/app.log" + strings.Repeat(" x", 300) + "; rm -rf /var/lib", ""},
		{"bidi", "echo \u202ebil/rav/ fr- mr; rm -rf /var/lib", ""},
		{"zero-width", "rm\u200b -rf /var/lib", ""},
		{"too many fillers", "tail log" + strings.Repeat("\u3164", 120) + "; rm -rf /var/lib", ""},
		// what could hide a part is shown as escapes the shell reads back
		{"padded", "tail /var/log/app.log" + strings.Repeat(" ", 40) + "; rm -rf /var/lib", "$'tail /var/log/app.log" + strings.Repeat(`\x20`, 40) + "; rm -rf /var/lib'"},
		{"newline", "uptime\n\nAllow this once?\n; rm -rf /var/lib", `$'uptime\n\nAllow this once?\n; rm -rf /var/lib'`},
		{"escape", "rm -rf /var/lib \x1b[8m", `$'rm -rf /var/lib \x1b[8m'`},
		{"carriage return", "rm -rf /var/lib\rtail log", `$'rm -rf /var/lib\rtail log'`},
		{"filler", "tail log" + strings.Repeat("\u3164", 20) + "; rm -rf /var/lib", "$'tail log" + strings.Repeat(`\u3164`, 20) + "; rm -rf /var/lib'"},
		{"braille blank", "tail log\u2800\u2800; rm -rf /var/lib", `$'tail log\u2800\u2800; rm -rf /var/lib'`},
		{"combining", "rm -rf /var/lib; x\u0336\u0336", `$'rm -rf /var/lib; x\u0336\u0336'`},
		{"quote", "rm -rf /var/lib\n'x'", `$'rm -rf /var/lib\n\'x\''`},
	} {
		resetApproval()
		texts = nil
		os.Args = []string{"komando", "exec", "web", "--allow-dangerous", "--", c.cmd}
		err := guard(st, hosts, c.cmd, true)
		if err == nil {
			t.Errorf("%s: the person said no, but it passed", c.name)
		}
		if (len(texts) == 1) != (c.shown != "") {
			t.Errorf("%s: %d windows", c.name, len(texts))
			continue
		}
		if c.shown == "" {
			e := toErr(err)
			approvalHint(e)
			if cur().sess.Window().Why != "unshowable" || !strings.Contains(e.Hint, "did not ask the user") {
				t.Errorf("%s: why %q, hint %q", c.name, cur().sess.Window().Why, e.Hint)
			}
			continue
		}
		for _, want := range []string{"komando exec web --allow-dangerous -- " + c.shown + "\n", "Why komando asks: [rm-system-dir", "wants to change web (protected)"} {
			if !strings.Contains(texts[0], want) {
				t.Errorf("%s: window text has no %q: %q", c.name, want, texts[0])
			}
		}
		if bad := unshowable(strings.Split(texts[0], "\n")[2]); bad != "" {
			t.Errorf("%s: the shown line is not plain: %s", c.name, bad)
		}
	}

	// a multi-line edit on a protected host gets a window, with the text
	// shown escaped
	resetApproval()
	texts = nil
	g.allowDangerous = false
	os.Args = []string{"komando", "fs", "replace", "web", "/etc/app.yml", "--old", "a: 1", "--new", "a:\n  b: 1\n  c: 2", "--yes"}
	if guard(st, hosts, "", true) == nil {
		t.Error("fs replace: the person said no, but it passed")
	}
	if len(texts) != 1 || !strings.Contains(texts[0], `--new $'a:\n  b: 1\n  c: 2' --yes`) {
		t.Errorf("fs replace window: %q", texts)
	}

}
