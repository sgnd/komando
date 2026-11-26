package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// Every refusal the guard makes for a real attack, one line each, with
// the words of its own reason: a change that drops one fails here by name.
// The refusals of a crashed, stalled or oversized check and of a hook line
// whose program fails are pinned in TestGuardStalledCheckIsRefused,
// TestGuardRefusesOversizedCall and TestGuardHookLineRefusesWhenTheGuardFails.
func TestGuardRealAttackRefusals(t *testing.T) {
	home, _ := guardLineHome(t)
	for _, c := range guardAttacks(home) {
		d := checkTool(tcl, c.tool, c.in, home, home)
		if !d.Deny || !strings.Contains(d.Reason, c.reason) {
			t.Errorf("%s: want a refusal with %q, got deny=%v %q", c.name, c.reason, d.Deny, d.Reason)
		}
	}
}

// guardAttack is a real attack tool call and the words of the refusal the
// guard answers it with.
type guardAttack struct {
	name, tool string
	in         map[string]any
	reason     string
}

// guardAttacks are one tool call per refusal site, for the home that
// guardLineHome makes.
func guardAttacks(home string) []guardAttack {
	src := filepath.Join(home, "src")
	bash := func(line string) map[string]any { return map[string]any{"command": line} }
	return []guardAttack{
		{"read a private key", "Read", map[string]any{"file_path": "~/.ssh/id_ed25519"}, "is a private key. komando keeps it away"},
		{"write a hook file", "Write", map[string]any{"file_path": "~/.claude/settings.json"}, "hook settings, which run komando's guard; an AI agent does not change it"},
		{"write the komando program", "Edit", map[string]any{"file_path": "~/bin/komando"}, "a program named komando"},
		{"search a private key", "Grep", map[string]any{"path": "~/.ssh/id_ed25519"}, "is a private key; ask the user"},
		{"glob for secret files", "Glob", map[string]any{"glob": "**/.env"}, "matches files that hold secrets"},
		{"search the home folder", "Grep", map[string]any{"path": home}, "a search of it reads them"},
		{"search glob into komando's data", "Grep", map[string]any{"path": src, "glob": "../.komando/*"}, "leave it out of the search"},
		{"redirect into a hook file", "Bash", bash("echo x > ~/.claude/settings.json"), "hook settings, which run komando's guard; an AI agent does not change it"},
		{"delete a hook file", "Bash", bash("rm ~/.claude/settings.json"), "hook settings, which run komando's guard; an AI agent does not change it"},
		{"replace the komando program", "Bash", bash("cp /bin/true ~/bin/komando"), "a program named komando"},
		{"build over the komando program", "Bash", bash("go build -o ~/bin/komando ./cmd/komando"), "a program named komando"},
		{"read the vault passphrase", "Bash", bash("echo $KOMANDO_VAULT_PASS"), "KOMANDO_VAULT_PASS opens komando's vault"},
		{"change komando found by name", "Bash", bash(`rm "$(command -v komando)"`), "the line changes the komando program the guard hook runs"},
		{"read a process environment", "Bash", bash("cat /proc/1/environ"), "process environments hold secrets"},
		{"hook file in interpreter code", "Bash", bash(`python3 -c "open('` + home + `/.claude/settings.json','w')"`), "the line names"},
		{"komando path through a variable", "Bash", bash(`p=~/newbin/komando; cp /bin/true "$p"`), "the line names ~/newbin/komando and runs cp"},
		{"komando found by interpreter code", "Bash", bash(`python3 -c "import shutil; open(shutil.which('komando'),'w')"`), "the line names komando and runs python3"},
		{"komando named to interpreter code", "Bash", bash(`K=komando python3 -c "import os,shutil; open(shutil.which(os.environ['K']),'w')"`), "the line names komando and runs python3"},
		{"komando output piped into interpreter code", "Bash", bash(`komando doctor | python3 -c "import sys; open(sys.stdin.read().split()[0],'w')"`), "the line names komando and runs python3"},
		{"cd into komando's data", "Bash", bash("cd ~/.komando && ls"), "komando's own data"},
		{"ssh past komando", "Bash", bash("ssh web1 uptime"), "use komando for servers"},
		{"rsync to a server", "Bash", bash("rsync -a /tmp/x web1:/tmp/"), "use `komando sync` or `komando cp`"},
		{"dump the environment", "Bash", bash("env"), "listing every environment variable"},
		{"read the keychain", "Bash", bash("security find-generic-password -w -s x"), "reading passwords from the keychain"},
		{"git -C komando's data", "Bash", bash("git -C ~/.komando status"), "komando's own data"},
		{"tar --directory into komando's data", "Bash", bash("tar --directory=~/.komando -cf /tmp/x ."), "komando's own data"},
		{"read komando's data", "Bash", bash("cat ~/.komando/vault.json"), "komando's own data"},
		{"recursive read of the home folder", "Bash", bash("grep -r password ~"), "and grep reads all of it"},
		{"env -i in front of komando", "Bash", bash("env -i komando list"), "clears the variables komando knows an AI agent by"},
		{"env - in front of komando", "Bash", bash("env - komando list"), "clears the variables komando knows an AI agent by"},
		{"env --ignore-environment", "Bash", bash("env --ignore-environment komando list"), "clears the variables komando knows an AI agent by"},
		{"exec -c komando", "Bash", bash("exec -c komando list"), "clears the variables komando knows an AI agent by"},
		{"sudo komando", "Bash", bash("sudo komando list"), "starts komando with a clean environment"},
		{"HOME in front of komando", "Bash", bash("HOME=/tmp/x komando list"), "in front of komando would move its data folder"},
		{"move komando's data folder", "Bash", bash("export KOMANDO_HOME=/tmp/x"), "moves komando's data folder"},
		{"clear the agent variable", "Bash", bash("unset CLAUDECODE"), "tells komando that an AI agent is running it"},
	}
}

// The guard answers a hook call without opening the store or the vault:
// it needs neither, and opening them made every tool call of every
// session decrypt the vault.
func TestGuardOpensNoStore(t *testing.T) {
	keys, values, source := 0, 0, store.KeySource
	t.Cleanup(func() { store.KeySource = source; tcl.out.SetSecrets(nil) })
	setup := func(t *testing.T) {
		store.KeySource = source
		if err := vault.Set(store.Save(), "web-pw", "a-value-long-enough"); err != nil {
			t.Fatal(err)
		}
		store.Close()
		store.KeySource = func(meta map[string]string, create bool) ([]byte, map[string]string, error) {
			keys++
			return source(meta, create)
		}
		// the vault values output is checked against (HoldsVaultValue)
		tcl.out.SetSecrets(func() map[string]string { values++; return vaultValues() })
	}
	for h, in := range map[string]string{
		"claude": `{"tool_name":"Bash","tool_input":{"command":"cat ~/.ssh/id_ed25519"},"cwd":"/p"}`,
		"codex":  `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat ~/.ssh/id_ed25519"}}`,
		"cursor": `{"hook_event_name":"beforeShellExecution","command":"cat ~/.ssh/id_ed25519","cwd":"/p"}`,
		"gemini": `{"hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"cat ~/.ssh/id_ed25519"}}`,
	} {
		keys, values = 0, 0
		stdout, _, code := goldenRunIn(t, true, []string{"guide", "guard", "--for", h}, setup, in)
		if keys != 0 || values != 0 {
			t.Errorf("--for %s: the guard asked for the store's key %d times and read the vault's values %d times", h, keys, values)
		}
		if code != 0 || !strings.Contains(stdout, "is a private key") {
			t.Errorf("--for %s: want the private key refused, exit 0; got exit %d, %q", h, code, stdout)
		}
	}
}

// Only the words a hook line runs the guard with take the short way.
func TestGuardHookArgs(t *testing.T) {
	for _, c := range []struct {
		args  string
		agent string
		ok    bool
	}{
		{"guide guard", "", true},
		{"guide guard --for codex", "codex", true},
		{"guide guard --for=gemini", "gemini", true},
		{"guide guard --help", "", false},
		{"guide guard --for", "", false},
		{"guide guard --for codex -o json", "", false},
		{"-o json guide guard", "", false},
		{"guide install", "", false},
		{"guide", "", false},
	} {
		agent, ok := guardHookArgs(strings.Fields(c.args))
		if agent != c.agent || ok != c.ok {
			t.Errorf("%q: want %q %v, got %q %v", c.args, c.agent, c.ok, agent, ok)
		}
	}
}

// The hook's own lines (guide guard, --for H, --for=H) take the short way
// to the guard; every other form runs as a command. Both answer every
// call of the corpus with the same bytes.
func TestGuardHookAnswersAsTheCommand(t *testing.T) {
	if raceOn {
		t.Skip("runs the guard many times")
	}
	home, _ := guardLineHome(t)
	var calls []string
	for _, c := range guardAttacks(home) {
		b, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": c.tool, "tool_input": c.in, "cwd": "/p"})
		if err != nil {
			t.Fatal(err)
		}
		calls = append(calls, string(b))
	}
	calls = append(calls, `not json`, `{"tool_name":"Bash","tool_input":{"command":"go test ./..."},"cwd":"/p"}`,
		`{"hook_event_name":"beforeShellExecution","command":"cat .env","cwd":"/p"}`,
		`{"hook_event_name":"BeforeTool","tool_name":"read_file","tool_input":{"file_path":"~/.ssh/id_ed25519"}}`)
	denied := 0
	for _, h := range []string{"claude", "codex", "cursor", "gemini"} {
		for _, in := range calls {
			short, _, code := goldenRunIn(t, true, []string{"guide", "guard", "--for=" + h}, nil, in)
			long, _, longCode := goldenRunIn(t, true, []string{"-o", "json", "guide", "guard", "--for", h}, nil, in)
			if short != long || code != longCode {
				t.Errorf("--for %s, %.80s: the hook's line answers %q (exit %d), the command %q (exit %d)", h, in, short, code, long, longCode)
			}
			if strings.Contains(short, "deny") {
				denied++
			}
		}
	}
	if denied < 50 {
		t.Errorf("only %d of the corpus's calls were refused; the corpus lost its attacks", denied)
	}
}

// guardSecretTargets are files the secret-path rule guards, one per kind:
// komando's data (also through $HOME and ${KOMANDO_HOME}), a
// private key, a credential store and a file named as one that holds
// secrets.
func guardSecretTargets() []string {
	return []string{
		"~/.komando/vault.json",
		`"$HOME/.komando/state.json"`,
		"${KOMANDO_HOME}/audit.log",
		"~/.ssh/id_ed25519",
		"~/.aws/credentials",
		"/tmp/site/.pgpass",
		"/tmp/site/.env",
	}
}

// The file a plain > or >> redirect writes is checked as a secret path
// for every program, as the >& and &> forms are: also for the programs
// whose own arguments only name files (echo, printf, touch, mkdir, ls,
// test).
func TestGuardRedirectTargetIsCheckedAsSecretPath(t *testing.T) {
	home, _ := guardLineHome(t)
	for _, prog := range []string{"echo x", "printf x", "touch a", "mkdir -p a", "ls", "test -n x", "[ -n x ]", "date"} {
		t.Run(strings.Fields(prog)[0], func(t *testing.T) {
			var lines []string
			for _, op := range []string{">", ">>", " >", "1>", ">&", "&>", ">|", ">>|", ">!", ">>!"} {
				for _, target := range guardSecretTargets() {
					lines = append(lines, prog+" "+op+" "+target, prog+" "+op+target)
				}
			}
			checkLines(t, home, home, lines, true)
		})
	}
}

// The same check holds where the redirect stands in a longer line: after
// a pipe or ;, inside $(...) and backquotes, in the script of bash -c, with
// no space around the operator, and with the operator before the program.
func TestGuardRedirectTargetInLongerLines(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		"cat /tmp/a | echo x > ~/.komando/vault.json",
		"true; printf x >> ~/.komando/vault.json",
		"x=$(echo y > ~/.komando/vault.json)",
		"x=`echo y > ~/.komando/vault.json`",
		`bash -c 'echo y > ~/.komando/vault.json'`,
		"echo x>~/.komando/vault.json",
		"echo x>>~/.ssh/id_ed25519",
		"> ~/.komando/vault.json echo x",
		"echo x > /tmp/ok > ~/.komando/vault.json",
		"cd ~/.ssh/.. && echo x > .komando/vault.json",
		"echo X=1 > .env",
	}, true)
}

// A redirect that writes elsewhere stays allowed, and so do the words
// these programs only name: a file name in quoted text or in an argument
// is no redirect.
func TestGuardRedirectTargetHarmlessStaysAllowed(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		"echo x > notes.txt",
		"printf 'a\\n' >> /tmp/out.log",
		"ls -la > /tmp/listing",
		"echo x 2>/dev/null",
		"mkdir -p build > /dev/null",
		`echo "write the key to ~/.ssh/id_ed25519 > later" > /tmp/note`,
		"echo 'a > ~/.komando/vault.json'",
		"echo ~/.komando/vault.json",
		"ls ~/.komando",
		"test -f ~/.ssh/id_ed25519",
		"echo .pgpass >> .gitignore",
		"echo X=1 > .env.example",
		"printf 'X=1\\n' >> /tmp/site/.env.sample",
	}, false)
}

// The shell, not the program, writes a redirect's file: the check holds
// for komando's own line, and for a redirect where the program reads a
// value or a pattern (find -name, grep's pattern), and for <>.
func TestGuardRedirectTargetWhereTheProgramSkipsWords(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		"komando list > ~/.komando/vault.json",
		"komando list -o json >> ~/.ssh/id_ed25519",
		"find . -name > ~/.komando/vault.json x",
		"grep > ~/.komando/vault.json foo /tmp/a",
		"echo x <> ~/.komando/vault.json",
		"komando list > ~/.claude/settings.json",
		"komando guide >> ~/bin/komando",
		"echo x >! ~/.claude/settings.json",
		"echo x >>!~/.claude/settings.local.json",
		"date >! ~/bin/komando",
		"bash -c 'echo x >! ~/.komando/state.json'",
		"date >! .env",
	}, true)
	checkLines(t, home, home, []string{
		"komando list -o json > /tmp/hosts.json",
		"find . -name '*.go' > /tmp/files",
	}, false)
}

// The other ways a line writes a file are checked as secret paths too:
// tee, cp and mv to it, and a redirect after a here-document or a
// here-string.
func TestGuardSecretPathWrittenOtherWays(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		"echo x | tee ~/.komando/vault.json",
		"echo x | tee -a ~/.ssh/id_ed25519",
		"cp /tmp/x ~/.komando/vault.json",
		"mv /tmp/x ~/.aws/credentials",
		"cat <<EOF > ~/.komando/vault.json\nx\nEOF",
		"cat <<'EOF' >> ~/.komando/vault.json\nx\nEOF",
		"cat > ~/.komando/vault.json <<'EOF'\nx\nEOF",
		"cat <<< x > ~/.komando/vault.json",
		"echo <<< x > ~/.ssh/id_ed25519",
	}, true)
}

// dollarQuoted writes the first dot of target, without its double quotes,
// in each form bash and zsh decode: $'\x2e', $'\056', $'.', $'.'
// and $".".
func dollarQuoted(target string) []string {
	t := strings.Trim(target, `"`)
	var out []string
	for _, q := range []string{`$'\x2e'`, `$'\056'`, `$'.'`, `$'.'`, `$"."`} {
		out = append(out, strings.Replace(t, ".", q, 1))
	}
	return out
}

// A word in $'...' or $"..." quotes is checked as the shell reads it: in
// a redirect, as an argument that writes and as one that reads.
func TestGuardDollarQuotedPathIsDecoded(t *testing.T) {
	home, _ := guardLineHome(t)
	var lines []string
	for _, target := range guardSecretTargets() {
		for _, w := range dollarQuoted(target) {
			lines = append(lines, "echo x > "+w, "cp /tmp/a "+w, "cat "+w)
		}
	}
	lines = append(lines, `echo x > ~/$'.cl\x61ude'/settings.json`, `cp /tmp/a ~/$'.claude'/settings.json`)
	checkLines(t, home, home, lines, true)
	checkLines(t, home, home, []string{
		`echo $'a\tb' > /tmp/out`,
		`printf $'x\n' >> notes.txt`,
		`echo "$'.komando'" > /tmp/out`,
		`echo '$'"'"'x'"'" > /tmp/out`,
	}, false)
}

// A path held in a variable set earlier on the line is checked as the
// path itself: written, copied or read through the variable. A redirect
// whose file the guard cannot know (a variable never set on the line or in
// the environment, or a command's output) is refused.
func TestGuardPathInAVariable(t *testing.T) {
	home, _ := guardLineHome(t)
	t.Setenv("C533_KNOWN_DIR", "/tmp")
	checkLines(t, home, home, []string{
		`f=~/.komando/vault.json; cp /tmp/a $f`,
		`f=~/.komando/vault.json; cat $f`,
		`f=~/.komando/vault.json; echo x > "$f"`,
		`f=~/.komando/vault.json && echo x >> "${f}"`,
		`export f=~/.ssh/id_ed25519; cat "$f"`,
		`d=~/.komando; echo x > "$d/vault.json"`,
		`d=~/.kom; echo x > "${d}ando/vault.json"`,
		`for d in /tmp ~/.kom; do echo x > "${d}ando/vault.json"; done`,
		`f=$(cat /tmp/name); echo x > "$f"`,
		`echo x > "$C533_NEVER_SET"`,
		"echo x > `cat /tmp/name`",
		`echo x > $(cat /tmp/name)`,
		`while read f; do echo x > "$f"; done < /tmp/list`,
	}, true)
	checkLines(t, home, home, []string{
		`out=/tmp/x.log; echo x > "$out"`,
		`for f in a.go b.go; do gofmt "$f" > "$f.tmp"; done`,
		`tmp=$(mktemp); echo x > "$tmp"`,
		`echo x > "$C533_KNOWN_DIR/out"`,
		`f=notes.txt; cat "$f"`,
		`f=notes.txt; echo x > $f 2>&1`,
		`echo x > "$HOME/notes.txt"`,
		`echo x > "$(mktemp)"`,
		`echo x > /tmp/log.$$`,
		`echo x > "$PWD/out.txt"`,
	}, false)
}

// A shell nested deeper than the guard reads is refused, not let through.
func TestGuardNestingPastTheLimitIsRefused(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		`bash -c "bash -c 'bash -c \"bash -c \\\"echo x > ~/.komando/vault.json\\\"\"'"`,
		`sh -c 'sh -c "sh -c \"sh -c \\\"cat ~/.ssh/id_ed25519\\\"\""'`,
		`eval 'eval "eval \"eval true\""'`,
		`env -S 'env -S "env -S \"env -S \\\"true\\\"\""' true`,
	}, true)
	checkLines(t, home, home, []string{
		`bash -c "bash -c 'echo ok > /tmp/out'"`,
	}, false)
}

// Ordinary output handling stays allowed.
func TestGuardOrdinaryRedirectsStayAllowed(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		"echo x > /dev/null",
		"ls > /dev/null 2>&1",
		"go vet ./... 2>&1",
		"echo done >&2",
		"go build ./... &> build.log",
		"make 2>&1 | tee build.log",
		"echo x >> logs/build.log",
		"echo X=1 > .env.example",
		"go test ./... >| /tmp/out",
	}, false)
}
