package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// noAgent runs the rest of a test with none of the agent variables there
// (an empty one still names an agent).
func noAgent(t *testing.T) {
	t.Helper()
	t.Cleanup(resetApproval) // before t.Setenv: reads the caller once the variables are restored
	for _, a := range agentVars {
		t.Setenv(a.env, "") // restored after the test
		os.Unsetenv(a.env)
		resetApproval()
	}
	resetApproval() // the caller is read when a call starts
}

// An agent cannot opt out by changing its own variables: komando counts
// any value, a second variable still names the agent, and the guard stops
// the shell lines that change them.
func TestAgentCannotClearItsVariables(t *testing.T) {
	for _, v := range []string{"0", "false", "1"} {
		setCallerEnv(t, "CLAUDECODE", v)
		if tcl.caller().Agent != "Claude Code" {
			t.Errorf("CLAUDECODE=%s: agentName = %q", v, tcl.caller().Agent)
		}
	}
	setCallerEnv(t, "CLAUDECODE", "")
	if tcl.caller().Agent != "Claude Code" {
		t.Errorf("CLAUDECODE empty: agentName = %q", tcl.caller().Agent)
	}
	noAgent(t)
	setCallerEnv(t, "CLAUDE_CODE_ENTRYPOINT", "cli")
	if tcl.caller().Agent != "Claude Code" {
		t.Errorf("CLAUDECODE cleared, CLAUDE_CODE_ENTRYPOINT set: agentName = %q", tcl.caller().Agent)
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
		// HOME in front of komando: refused; elsewhere the agent's business
		"HOME=/tmp/k komando host list":      true,
		"env HOME=/tmp/k komando list":       true,
		"USERPROFILE=/tmp/k komando list":    true,
		"bash -c 'HOME=/tmp/k komando list'": true,
		"HOME=/tmp/k go test ./...":          false,
		"export HOME=/tmp/k":                 false,
		"HOME=/tmp/k true; komando list":     false,
		"export KOMANDO_ACTOR=claude":        false,
		"CLAUDECODE=1 komando list":          true, // any change is refused: KISS
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
		if d := checkTool(tcl, "Bash", map[string]any{"command": line}, home, ""); d.Deny != block {
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
			if d := checkTool(tcl, c.tool, c.in, home, c.cwd); d.Deny != c.block {
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
		if d := checkTool(tcl, c.tool, c.in, home, proj); !d.Deny {
			t.Errorf("%s %v: allowed", c.tool, c.in)
		}
	}

	// the other harnesses' hooks send cwd too
	if runtime.GOOS == "windows" {
		return // home is /Users/me, not a full path there
	}
	b, _ := json.Marshal(map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": "cat .komando/state.json"}, "cwd": home})
	t.Setenv("KOMANDO_HOME", "")
	if d := guardAgent(tcl, "codex", b, home); !d.Deny {
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
		if d := checkTool(tcl, "Bash", map[string]any{"command": line}, home, ""); d.Deny != block {
			t.Errorf("%q: deny=%v (%s)", line, d.Deny, d.Reason)
		}
	}
	if d := checkTool(tcl, "Read", map[string]any{"file_path": "/proc/1/environ"}, home, ""); !d.Deny {
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
	defer func() { tcl.flags.reveal = false }()
	read := func(p string) string {
		_, err := readLocalFile(tcl, p)
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
	if d := checkTool(tcl, "Read", map[string]any{"file_path": notes}, home, ""); !d.Deny {
		t.Error("guard: a hard link to komando's data is allowed")
	}
	if *n != 0 {
		t.Errorf("no --reveal: %d windows", *n)
	}
	tcl.flags.reveal = true // the person allows a project secret, never komando's data
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
		if _, err := readSource(tcl, p); err != nil {
			c = toErr(err).Code
		}
		if c != want {
			t.Errorf("import %s: %q, want %q", p, c, want)
		}
	}
	if _, err := readLocalFile(tcl, filepath.Join(home, ".pgpass")); toErr(err) == nil || toErr(err).Code != "SENSITIVE_FILE" {
		t.Errorf("exec --stdin-file ~/.pgpass: %v", err)
	}
}

// sync up of a folder that holds komando's data or private keys leaves
// those files here, each one checked as cp -r does.
func TestSyncUpChecksEachFileForAgents(t *testing.T) {
	_, home, _ := agentFiles(t)
	t.Cleanup(func() { tcl.flags.reveal = false; tcl.out.Reset() })
	if err := os.MkdirAll(filepath.Join(home, ".komando"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".komando", "state.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, reveal := range []bool{false, true} {
		asAgent(t, true, true)
		tcl.flags.reveal = reveal
		dst := t.TempDir()
		ctx := context.Background()
		if _, err := runSync(tcl, ctx, newAgentLocalSide(tcl, ctx, home), localSide{tcl, dst}, "home", "dst", syncOpts{}); err != nil {
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
	t.Cleanup(func() {
		tcl.flags.dryRun, tcl.flags.yes, tcl.flags.allowDangerous, tcl.flags.reveal = false, false, false, false
	})
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
	t.Cleanup(func() { tcl.flags.reveal, tcl.out.Mask = false, false })
	n := asAgent(t, true, true)
	tcl.flags.dryRun, tcl.flags.reveal = true, true
	if tcl.revealOK() {
		t.Error("revealOK under --dry-run")
	}
	tcl.flags.dryRun, tcl.flags.reveal = false, false
	mustRun(t, "list", "--dry-run", "--reveal")
	if !tcl.out.Mask || *n != 0 {
		t.Errorf("list --dry-run --reveal: mask=%v windows=%d", tcl.out.Mask, *n)
	}
	// an agent's preview that connects does it with the usual server
	// identity check
	mustRun(t, "list", "--dry-run", "--host-key-policy", "off")
	if tcl.flags.hostKeyPolicy != "" || *n != 0 {
		t.Errorf("--dry-run --host-key-policy off: policy %q, windows %d", tcl.flags.hostKeyPolicy, *n)
	}
	// a person's or a script's preview runs as the real run would
	noAgent(t)
	t.Cleanup(func() { tcl.flags.yes, tcl.flags.hostKeyPolicy = false, "" })
	mustRun(t, "list", "--dry-run", "--yes", "--host-key-policy", "off")
	if tcl.flags.hostKeyPolicy != "off" {
		t.Errorf("script --dry-run --host-key-policy off: policy %q", tcl.flags.hostKeyPolicy)
	}
}

// The approval window shows the whole command, the reason and the targets;
// a command it cannot show whole is refused without a window.
func TestApprovalWindowShowsEverything(t *testing.T) {
	saved := tcl.args
	t.Cleanup(func() { tcl.args = saved; tcl.flags.allowDangerous, tcl.flags.yes = false, false })
	setCallerEnv(t, "CLAUDECODE", "1")
	var texts []string
	savedAsk := askOnScreen
	askOnScreen = func(_ *call, text string) (bool, bool) { texts = append(texts, text); return false, true }
	t.Cleanup(func() { askOnScreen = savedAsk; resetApproval() })

	st := &store.State{Hosts: map[string]*store.Host{"web": {Name: "web", Address: "10.0.0.1", Protected: true}}}
	hosts := []*store.Host{st.Hosts["web"]}
	tcl.flags.allowDangerous, tcl.flags.yes = true, true
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
		tcl.args = []string{"komando", "exec", "web", "--allow-dangerous", "--", c.cmd}
		err := guard(tcl, st, hosts, c.cmd, true)
		if err == nil {
			t.Errorf("%s: the person said no, but it passed", c.name)
		}
		if (len(texts) == 1) != (c.shown != "") {
			t.Errorf("%s: %d windows", c.name, len(texts))
			continue
		}
		if c.shown == "" {
			e := toErr(err)
			approvalHint(tcl, e)
			if tcl.sess.Window().Why != "unshowable" || !strings.Contains(e.Hint, "did not ask the user") {
				t.Errorf("%s: why %q, hint %q", c.name, tcl.sess.Window().Why, e.Hint)
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
	tcl.flags.allowDangerous = false
	tcl.args = []string{"komando", "fs", "replace", "web", "/etc/app.yml", "--old", "a: 1", "--new", "a:\n  b: 1\n  c: 2", "--yes"}
	if guard(tcl, st, hosts, "", true) == nil {
		t.Error("fs replace: the person said no, but it passed")
	}
	if len(texts) != 1 || !strings.Contains(texts[0], `--new $'a:\n  b: 1\n  c: 2' --yes`) {
		t.Errorf("fs replace window: %q", texts)
	}

}

// A guard check that stalls or crashes is refused within the budget, in
// every harness's format, before the harness's own hook time limit.
func TestGuardStalledCheckIsRefused(t *testing.T) {
	stop := make(chan struct{})
	oldDecide, oldBudget := guardDecide, guardBudget
	t.Cleanup(func() { close(stop); guardDecide, guardBudget = oldDecide, oldBudget })
	guardBudget = 50 * time.Millisecond
	for name, check := range map[string]func(*call, string) guardDecision{
		"stalled": func(*call, string) guardDecision { <-stop; return allow() },
		"crashed": func(*call, string) guardDecision { panic("check failed") },
	} {
		guardDecide = check
		for _, agent := range []string{"", "claude", "codex", "cursor", "gemini"} {
			done := make(chan []byte, 1)
			go func() { done <- guardHook(nil, agent) }()
			select {
			case b := <-done:
				if !strings.Contains(string(b), "deny") || !strings.Contains(string(b), "so the call is refused") {
					t.Errorf("%s check, --for %q: want a denial, got %q", name, agent, b)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("%s check, --for %q: the guard did not answer in 2s", name, agent)
			}
		}
	}
}

// guardInput runs the guard on in as the harness agent would, and returns
// its answer.
func guardInput(t *testing.T, agent, in string) string {
	t.Helper()
	setHome(t, t.TempDir())
	saved := tcl.stdin
	t.Cleanup(func() { tcl.stdin = saved })
	tcl.stdin = strings.NewReader(in)
	return string(guardHook(tcl, agent))
}

// A tool call larger than the guard reads whole is refused in every
// harness's format, here a 5 MiB write to komando's own folder.
func TestGuardRefusesOversizedCall(t *testing.T) {
	content := strings.Repeat("x", 5<<20)
	write := `"tool_input":{"file_path":"~/.komando/x","content":"` + content + `"}`
	for _, c := range []struct{ agent, in string }{
		{"", `{"tool_name":"Write",` + write + `,"cwd":"/p"}`},
		{"codex", `{"hook_event_name":"PreToolUse","tool_name":"Write",` + write + `}`},
		{"cursor", `{"hook_event_name":"preToolUse","tool_name":"Write",` + write + `,"cwd":"/p"}`},
		{"gemini", `{"hook_event_name":"BeforeTool","tool_name":"write_file",` + write + `}`},
	} {
		if got := guardInput(t, c.agent, c.in); !strings.Contains(got, "deny") || !strings.Contains(got, "too large for komando's guard to check") {
			t.Errorf("%q: want a denial for a call over 4 MiB, got %.200q", c.agent, got)
		}
	}
}

// A call of exactly 4 MiB is read whole and judged by what it does (a
// write to komando's folder is denied by the path check); one byte more is
// refused by its size.
func TestGuardInputSizeBoundary(t *testing.T) {
	call := func(size int) string {
		head, tail := `{"tool_name":"Write","tool_input":{"file_path":"~/.komando/x","content":"`, `"},"cwd":"/p"}`
		return head + strings.Repeat("x", size-len(head)-len(tail)) + tail
	}
	whole := call(guardInputMax)
	if len(whole) != guardInputMax {
		t.Fatalf("the input is %d bytes, want %d", len(whole), guardInputMax)
	}
	if got := guardInput(t, "", whole); !strings.Contains(got, "deny") || strings.Contains(got, "too large") {
		t.Errorf("exactly 4 MiB: want a denial by the path check, got %.200q", got)
	}
	if got := guardInput(t, "", call(guardInputMax+1)); !strings.Contains(got, "too large for komando's guard to check") {
		t.Errorf("4 MiB and one byte: want a denial by size, got %.200q", got)
	}
}

// fakeKomando writes a stand-in for the komando program that runs body.
func fakeKomando(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// runHookLine runs a guard hook line the way a harness does: through sh,
// with the tool call on stdin.
func runHookLine(t *testing.T, line, in string) (stdout string, code int) {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", line)
	cmd.Stdin = strings.NewReader(in)
	b, err := cmd.Output()
	if ee, ok := err.(*exec.ExitError); ok {
		return string(b), ee.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b), 0
}

// The guard hook line answers for every harness: the guard's own answer
// when it ran to the end, and the harness's deny, with exit 0, when the
// program is missing, fails or dies halfway.
func TestGuardHookLineRefusesWhenTheGuardFails(t *testing.T) {
	unixOnly(t, "the hook line runs through /bin/sh")
	dir := t.TempDir()
	call := `{"tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/p"}`
	progs := map[string]string{
		"missing":       filepath.Join(dir, "gone", "komando"),
		"exits 1":       fakeKomando(t, dir, "fails", "exit 1"),
		"dies halfway":  fakeKomando(t, dir, "half", `printf '{"hookSpecificOutput":'; exit 3`),
		"not a program": filepath.Join(dir, "plain"),
	}
	_ = os.WriteFile(progs["not a program"], []byte("x"), 0o644)
	for _, h := range []string{"claude", "codex", "cursor", "gemini"} {
		want := strings.TrimSpace(string(guardAnswer(h, deny(guardDidNotRun))))
		for name, prog := range progs {
			if got, code := runHookLine(t, guardHookLine(prog, h), call); got != want || code != 0 {
				t.Errorf("%s, %s: want the deny %q and exit 0, got %q, exit %d", h, name, want, got, code)
			}
		}
		// the guard's own answer passes through, and it reads the call on stdin
		if got, code := runHookLine(t, guardHookLine(fakeKomando(t, dir, "echo-"+h, "cat"), h), call); got != call || code != 0 {
			t.Errorf("%s: the guard's answer: want %q, got %q, exit %d", h, call, got, code)
		}
		if got, code := runHookLine(t, guardHookLine(fakeKomando(t, dir, "allow-"+h, "exit 0"), h), call); got != "" || code != 0 {
			t.Errorf("%s: an allowed call prints nothing: got %q, exit %d", h, got, code)
		}
	}
}

// guide install writes the hook line for every harness, replaces an old
// line, and the readers find both forms; doctor flags the old form and a
// missing program.
func TestGuardHookInstallAndReaders(t *testing.T) {
	unixOnly(t, "program checks read Unix modes")
	dir := t.TempDir()
	prog := fakeKomando(t, dir, "komando", "exit 0")
	settings := filepath.Join(dir, "settings.json")
	old := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"` + prog + ` guide guard"}]}]}}`
	if err := os.WriteFile(settings, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if found, problem := claudeGuard(settings); !found || !strings.Contains(problem, "old hook line") {
		t.Errorf("doctor on the old line: found %v, problem %q", found, problem)
	}
	if _, err := installGuardHook(settings, prog, false); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(settings)
	var v any
	_ = json.Unmarshal(b, &v)
	if got := guardHookCommands(v); len(got) != 1 || got[0] != guardHookLine(prog, "claude") {
		t.Errorf("after install: want one wrapper line, got %q", got)
	}
	if found, problem := claudeGuard(settings); !found || problem != "" {
		t.Errorf("doctor on the wrapper: found %v, problem %q", found, problem)
	}
	for _, h := range agentHooks {
		path := filepath.Join(dir, h.name+".json")
		if _, err := installAgentHook(path, h.add, guardHookLine(prog, h.name), false); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(path)
		var v any
		_ = json.Unmarshal(b, &v)
		for _, c := range guardHookCommands(v) {
			if p, wrapped := hookLineProgram(c); p != prog || !wrapped {
				t.Errorf("%s: the line %q names %q (wrapped %v)", h.name, c, p, wrapped)
			}
		}
	}
	for _, line := range []string{prog + " guide guard", prog + " guide guard --for codex", guardHookLine(prog, "claude"), guardHookLine(prog, "cursor")} {
		entry := map[string]any{"hooks": []any{map[string]any{"command": line}}}
		if !isGuardEntry(entry) || len(withoutGuard([]any{entry, map[string]any{"command": line}})) != 0 {
			t.Errorf("the readers miss %q", line)
		}
	}
	if err := os.Remove(prog); err != nil {
		t.Fatal(err)
	}
	if _, problem := claudeGuard(settings); !strings.Contains(problem, "does not exist") || !strings.Contains(problem, "every tool call is refused") {
		t.Errorf("doctor with the program gone: %q", problem)
	}
}

// The guard keeps an agent from changing what runs it: the agents' hook
// settings and folders and the komando program. Reading them stays open.
func TestGuardRefusesChangesToItself(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	self, _ := os.Executable()
	refused := []struct {
		tool string
		in   map[string]any
	}{
		{"Bash", map[string]any{"command": `rm "$(command -v komando)"`}},
		{"Bash", map[string]any{"command": "rm -f " + self}},
		{"Bash", map[string]any{"command": "mv ~/.claude/settings.json /tmp/x"}},
		{"Bash", map[string]any{"command": "echo '{}' > ~/.cursor/hooks.json"}},
		{"Bash", map[string]any{"command": "rm -rf ~/.claude"}},
		{"Bash", map[string]any{"command": "sed -i s/guard/x/ ~/.codex/hooks.json"}},
		{"Write", map[string]any{"file_path": home + "/.gemini/settings.json"}},
		{"Edit", map[string]any{"file_path": home + "/.claude/settings.local.json"}},
		{"Bash", map[string]any{"command": "cp /tmp/x ~/bin/komando"}},
		{"Bash", map[string]any{"command": "ln -s /tmp/x ~/bin/Komando"}},
		{"Bash", map[string]any{"command": "mv /tmp/x " + home + "/bin/komando"}},
		{"Write", map[string]any{"file_path": home + "/bin/komando"}},
		{"Bash", map[string]any{"command": "cp /tmp/x ~/bin/KOMANDO.EXE"}},
		{"Write", map[string]any{"file_path": home + "/bin/komando.exe"}},
	}
	for _, c := range refused {
		if d := checkTool(tcl, c.tool, c.in, home, home); !d.Deny {
			t.Errorf("%s %v: want a refusal", c.tool, c.in)
		}
	}
	allowed := []struct {
		tool string
		in   map[string]any
	}{
		{"Bash", map[string]any{"command": "cat ~/.claude/settings.json"}},
		{"Read", map[string]any{"file_path": home + "/.claude/settings.json"}},
		{"Write", map[string]any{"file_path": home + "/.claude/projects/p/memory/note.md"}},
		{"Bash", map[string]any{"command": "rm -rf ~/.claude/projects/old"}},
		{"Bash", map[string]any{"command": "command -v komando"}},
	}
	for _, c := range allowed {
		if d := checkTool(tcl, c.tool, c.in, home, home); d.Deny {
			t.Errorf("%s %v: want it allowed, got %q", c.tool, c.in, d.Reason)
		}
	}
}

// A line whose program is not only a reader may not name a hook file or a
// program named komando anywhere: in code given to an interpreter, or in a
// variable it uses later.
func TestGuardRefusesGuardFilesAnywhereOnTheLine(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	refused := []string{
		`python3 -c "open('` + home + `/.claude/settings.json','w').write('{}')"`,
		`node -e "require('fs').writeFileSync(process.env.HOME+'/.gemini/settings.json','{}')"`,
		`ruby -e 'File.write(Dir.home + "/.cursor/hooks.json", "{}")'`,
		`perl -e 'unlink "$ENV{HOME}/.codex/hooks.json"'`,
		`perl -e 'unlink glob("~/.codex/config.toml")'`,
		`f=~/.claude/settings.json; rm "$f"`,
		`f=$HOME/.claude/settings.local.json && : > "$f"`,
		`d=~/.claude; mv "$d" /tmp/old`,
		`python3 -c "import os,shutil; os.remove(shutil.which('komando'))"`,
		`python3 -c "open('/usr/local/bin/komando','w')"`,
		`p=~/bin/komando; cp /bin/true "$p"`,
	}
	for _, line := range refused {
		if d := checkTool(tcl, "Bash", map[string]any{"command": line}, home, home); !d.Deny {
			t.Errorf("%s: want a refusal", line)
		}
	}
	allowed := []string{
		"cat ~/.claude/settings.json | jq .hooks",
		"grep -n guard ~/.claude/settings.json ~/.codex/hooks.json",
		"cp notes.md ~/.claude/skills/notes/",
		"python3 report.py --out /tmp/report.txt",
		"node build.js",
	}
	for _, line := range allowed {
		if d := checkTool(tcl, "Bash", map[string]any{"command": line}, home, home); d.Deny {
			t.Errorf("%s: want it allowed, got %q", line, d.Reason)
		}
	}
}

// A refusal names the way out: a program the agent builds gets another
// name; a hook file is the user's.
func TestGuardSelfRefusalNamesTheWayOut(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, c := range []struct {
		tool, key, value, want string
	}{
		{"Bash", "command", "go build -o ~/bin/komando ./cmd/komando", "go build -o komando-dev"},
		{"Write", "file_path", home + "/bin/komando", "go build -o komando-dev"},
		{"Bash", "command", `python3 -c "import shutil; print(shutil.which('komando'))"`, "go build -o komando-dev"},
		{"Bash", "command", "p=~/bin/komando; cp /bin/true \"$p\"", "go build -o komando-dev"},
		{"Bash", "command", "rm ~/.claude/settings.json", "ask the user to do it"},
		{"Bash", "command", "f=~/.codex/hooks.json; rm \"$f\"", "ask the user to do it"},
	} {
		d := checkTool(tcl, c.tool, map[string]any{c.key: c.value}, home, home)
		if !d.Deny || !strings.Contains(d.Reason, c.want) {
			t.Errorf("%s %q: %v %q, want a refusal naming %q", c.tool, c.value, d.Deny, d.Reason, c.want)
		}
	}
}

// An existing folder named komando outside PATH may be named (go build
// ./cmd/komando in the repo); a link to a folder, or a folder in a PATH
// folder, may not: either can be swapped for a program by the same line.
func TestGuardKomandoFolderException(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	repo := filepath.Join(home, "src", "komando")
	bin := filepath.Join(home, "bin")
	for _, d := range []string{filepath.Join(repo, "cmd", "komando"), filepath.Join(bin, "komando"), filepath.Join(home, "dirs", "real")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(home, "links")
	if err := os.MkdirAll(link, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "dirs", "real"), filepath.Join(link, "komando")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, line := range []string{"go build ./cmd/komando", "go build -o /tmp/k ./cmd/komando", "ls cmd/komando"} {
		if d := checkTool(tcl, "Bash", map[string]any{"command": line}, home, repo); d.Deny {
			t.Errorf("in the repo, %s: want it allowed, got %q", line, d.Reason)
		}
	}
	for _, line := range []string{
		"rm -r ~/bin/komando; cp /bin/true ~/bin/komando",
		"ln -sfn /bin/true " + filepath.Join(link, "komando"),
		"rm " + filepath.Join(link, "komando") + " && cp /bin/true " + filepath.Join(link, "komando"),
	} {
		if d := checkTool(tcl, "Bash", map[string]any{"command": line}, home, repo); !d.Deny {
			t.Errorf("%s: want a refusal", line)
		}
	}
	if d := checkTool(tcl, "Write", map[string]any{"file_path": filepath.Join(link, "komando")}, home, home); !d.Deny {
		t.Error("a Write to a link named komando: want a refusal")
	}
	file := filepath.Join(home, "tools", "komando")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if d := checkTool(tcl, "Bash", map[string]any{"command": "chmod 755 " + file}, home, home); !d.Deny {
		t.Error("chmod of an existing file named komando: want a refusal")
	}
}

// With no full path for komando, guide install writes no hook (a bare name
// is found through PATH), and doctor flags a hook that names komando bare.
func TestGuardHookNeedsAFullPath(t *testing.T) {
	was := selfProgram
	selfProgram = func() (string, error) { return "", errors.New("unknown") }
	t.Cleanup(func() { selfProgram = was })
	t.Setenv("PATH", t.TempDir())
	if _, _, err := hookProgram(false); toErr(err).Code != "GUARD_PROGRAM_UNKNOWN" {
		t.Errorf("home install without a full path: %v, want GUARD_PROGRAM_UNKNOWN", err)
	}
	if _, _, err := hookProgram(true); toErr(err).Code != "GUARD_PROGRAM_UNKNOWN" {
		t.Errorf("project install without a full path: %v, want GUARD_PROGRAM_UNKNOWN", err)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := runRoot(t, "guide", "install"); toErr(err).Code != "GUARD_PROGRAM_UNKNOWN" {
		t.Errorf("guide install without a full path: %v, want GUARD_PROGRAM_UNKNOWN", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); err == nil {
		t.Error("guide install wrote a hook without a full path")
	}
	for _, h := range []string{"claude", "codex"} {
		if p := guardHookProblem(guardHookLine("komando", h)); !strings.Contains(p, "not a full path") {
			t.Errorf("%s: a hook naming komando bare: %q, want it flagged", h, p)
		}
	}
}

// On Windows (no /bin/sh) the hook keeps the line of 0.17.1, doctor does not
// call it old, and says what it cannot do.
func TestGuardHookOnWindows(t *testing.T) {
	unixOnly(t, "program checks read Unix modes")
	prog := fakeKomando(t, t.TempDir(), "komando", "exit 0")
	was := hookOS
	hookOS = "windows"
	t.Cleanup(func() { hookOS = was })
	if got, want := guardHookLine(prog, "claude"), shellQuote(prog)+" guide guard"; got != want {
		t.Errorf("claude: %q, want %q", got, want)
	}
	if got, want := guardHookLine(prog, "codex"), shellQuote(prog)+" guide guard --for codex"; got != want {
		t.Errorf("codex: %q, want %q", got, want)
	}
	if p := guardHookProblem(guardHookLine(prog, "claude")); p != "" {
		t.Errorf("on Windows the line is not a problem: %q", p)
	}
	var lines []string
	agentGuardChecks([]string{"/x/.claude/skills/komando/SKILL.md"}, func(name string, ok bool, detail string, _ ...string) {
		lines = append(lines, name+": "+detail)
	})
	if !slices.ContainsFunc(lines, func(l string) bool {
		return strings.HasPrefix(l, "agent_guard_windows: on Windows the hook lets a call through when komando is missing")
	}) {
		t.Errorf("doctor on Windows: %q", lines)
	}
	hookOS = "linux"
	if p := guardHookProblem(shellQuote(prog) + " guide guard"); !strings.Contains(p, "old hook line") {
		t.Errorf("elsewhere the old line is flagged: %q", p)
	}
}

// The real komando, built here, answers through the installed hook line of
// each harness: an allowed call, a refused one, and no program at all.
func TestGuardHookLineWithTheRealProgram(t *testing.T) {
	unixOnly(t, "the hook line runs through /bin/sh")
	if testing.Short() {
		t.Skip("builds komando")
	}
	dir, home := t.TempDir(), t.TempDir()
	prog := filepath.Join(dir, "komando")
	build := exec.Command("go", "build", "-o", prog, "../../cmd/komando")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	calls := map[string]func(cmd string) string{
		"claude": func(c string) string { return `{"tool_name":"Bash","tool_input":{"command":` + strconv.Quote(c) + `}}` },
		"codex":  func(c string) string { return `{"tool_name":"Bash","tool_input":{"command":` + strconv.Quote(c) + `}}` },
		"gemini": func(c string) string {
			return `{"tool_name":"run_shell_command","tool_input":{"command":` + strconv.Quote(c) + `}}`
		},
		"cursor": func(c string) string {
			return `{"hook_event_name":"beforeShellExecution","command":` + strconv.Quote(c) + `}`
		},
	}
	denyWord := map[string]string{"claude": `"permissionDecision":"deny"`, "codex": `"permissionDecision":"deny"`, "gemini": `"decision":"deny"`, "cursor": `"permission":"deny"`}
	allowOut := map[string]string{"claude": "", "codex": "", "gemini": "", "cursor": `{"permission":"allow"}`}
	run := func(line, in string) (string, int) {
		cmd := exec.Command("/bin/sh", "-c", line)
		cmd.Stdin = strings.NewReader(in)
		cmd.Env = append(os.Environ(), "HOME="+home)
		b, err := cmd.Output()
		if ee, ok := err.(*exec.ExitError); ok {
			return string(b), ee.ExitCode()
		}
		if err != nil {
			t.Fatal(err)
		}
		return string(b), 0
	}
	for h, call := range calls {
		line := guardHookLine(prog, h)
		if got, code := run(line, call("ls")); strings.TrimSpace(got) != allowOut[h] || code != 0 {
			t.Errorf("%s, allowed call: %q, exit %d", h, got, code)
		}
		if got, code := run(line, call("cat ~/.komando/x")); !strings.Contains(got, denyWord[h]) || code != 0 {
			t.Errorf("%s, a read of ~/.komando: %q, exit %d; want the deny", h, got, code)
		}
	}
	if err := os.Remove(prog); err != nil {
		t.Fatal(err)
	}
	for h, call := range calls {
		want := strings.TrimSpace(string(guardAnswer(h, deny(guardDidNotRun))))
		if got, code := run(guardHookLine(prog, h), call("ls")); got != want || code != 0 {
			t.Errorf("%s, no program: %q, exit %d; want %q", h, got, code, want)
		}
	}
}
