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

// A search program's word that names a key file, or looks like one, is
// checked as a file in every form, its pattern too: a search that names
// one is refused, as before.
func TestGuardSearchWordsNamingKeysStayRefused(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		"grep -v scrypt.Key internal/vault/storekey.go",
		"rg -n vault.Key internal",
		"grep -n -A 3 tls.key README.md",
		"grep --color=auto -n scrypt.Key internal/vault/storekey.go",
		"grep -f ~/.komando/vault.key notes.txt",
		"grep -e x ~/.ssh/id_ed25519",
		"grep x ~/.ssh/id_*",
		"grep -- x ~/.ssh/id_ed25519",
		"grep foo server.key",
		"grep ~/.ssh/id_* notes.txt",
		"grep -rf ~/.komando/vault.key .",
		"grep ~/.komando/vault.key -e .",
		"grep ~/.ssh/id_ed25519 -e .",
		"grep -m1 ~/.komando/vault.key -f /dev/null",
		"grep --regex=. ~/.komando/vault.key",
		"grep --fil=~/.komando/vault.key x",
		"grep --context=1 ~/.komando/vault.key",
		"GREP_OPTIONS=-f grep ~/.komando/vault.key notes.txt",
		"env GREP_OPTIONS=-f grep ~/.komando/vault.key notes.txt",
		"export GREP_OPTIONS=-f; grep ~/.komando/vault.key notes.txt",
		"xargs grep ~/.komando/vault.key < notes.txt",
		"parallel grep ~/.komando/vault.key ::: notes.txt",
		"find . -exec grep ~/.komando/vault.key {} +",
		"X=-e.; grep ~/.komando/vault.key $X",
		"grep ~/.komando/vault.key $X",
		`grep ~/.komando/vault.key "$@"`,
		"grep ~/.komando/vault.key *",
		"touch ./-e.; grep ~/.komando/vault.key *",
		"grep ~/.komando/vault.key ./-e.",
		"grep ~/.komando/vault.key {-e,.}",
		`grep ~/.komando/vault.key $'\x2de' .`,
		"grep ~/.komando/vault.key $'-e' .",
		`grep ~/.komando/vault.key \-e .`,
		"grep ~/.komando/vault.key '-e' .",
		"grep ~/.komando/vault.key ~-e",
		`export GREP_OPT""IONS='-e .'; grep ~/.komando/vault.key`,
		`export GREP_OPT\IONS='-e .'; grep ~/.komando/vault.key`,
		"declare -x GREP_OPT''IONS=-e.; grep ~/.komando/vault.key",
		`grep(){ cat "$@"; }; grep ~/.komando/vault.key x`,
		"grep () { cat $1; }\ngrep ~/.komando/vault.key",
		"function grep { cat $1; }; grep ~/.komando/vault.key",
		"shopt -s expand_aliases\nalias grep=cat\ngrep ~/.komando/vault.key",
		"alias grep=cat; grep ~/.komando/vault.key",
		"enable -n grep; grep ~/.komando/vault.key",
		"hash -p /bin/cat grep; grep ~/.komando/vault.key",
		"PATH=/tmp/x:$PATH; grep ~/.komando/vault.key",
		"ln -s /bin/cat ./grep; ./grep ~/.komando/vault.key",
		"/tmp/grep ~/.komando/vault.key",
		"./grep ~/.komando/vault.key",
		`\grep ~/.komando/vault.key`,
		"egrep ~/.komando/vault.key",
		"rg ~/.komando/vault.key",
		"grep -- ~/.komando/vault.key -e .",
		"IFS=,; grep ~/.komando/vault.key,-e,.",
		`set -- -e .; grep ~/.komando/vault.key "$@"`,
		"grep --color=auto ~/.komando/vault.key",
	}, true)
}

// C520: an Orca worktree for komando names the repo komando, a word that
// names Orca's own record, not a file. Orca with an output or path flag is
// still checked.
func TestGuardOrcaWorktreeNamedKomando(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		"orca worktree create --repo komando --name komando-c519-guard-hook-weight",
		"orca worktree create --repo=komando --name komando-c519 --json",
		"orca worktree create --name komando-c519 --base origin/main",
	}, false)
	checkLines(t, home, home, []string{
		"orca worktree create --repo komando --path komando",
		"orca worktree create --repo komando -o komando",
		"orca worktree create --repo komando; cp /bin/true komando",
	}, true)
}

// C520: 2>&1 and >&2 copy one output to another: they write no file, so a
// line naming the komando repo stays a reader's line. >&FILE writes FILE.
func TestGuardOutputCopyIsNoRedirect(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		"gh issue view 665 -R sgnd/komando --json title,body 2>&1 | head -60",
		"gh pr list -R sgnd/komando --state open >&2",
		"gh issue view 665 -R sgnd/komando 2>&-; echo done",
	}, false)
	checkLines(t, home, home, []string{
		"echo x >&~/.claude/settings.json",
		"echo x >& ~/.claude/settings.json",
		"echo x >&~/.komando/vault.json",
		"echo x &>~/.komando/vault.json",
		"ls >&~/.ssh/id_ed25519",
		"cat ~/.ssh/id_ed25519 >&2",
		`echo \>& cp /bin/true ~/bin/komando`,
		"gh pr list -R sgnd/komando >&komando",
		"gh release download v1 -R sgnd/komando -O ~/newbin/komando 2>&1",
	}, true)
}

// C520: on a plain line, a command that runs komando or reads its program
// names komando only for itself: python3 and sleep beside it get nothing
// from it. A reader whose output goes on (a pipe, a file, a command
// substitution), cd, a variable and a heredoc still count.
func TestGuardKomandoRunNextToAnotherCommand(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		"python3 -c 'print(1)'; komando version",
		"komando version && sleep 2 && komando list",
		"sleep 5; ~/bin/komando version",
		"stat ~/bin/komando; sleep 1",
		"python3 -c 'print(1)' && ls -la ~/bin/komando",
		"ls -la /usr/local/bin/komando; python3 --version",
		"which komando; sleep 1",
		"cat ~/.claude/settings.json; python3 -c 'print(1)'",
		"komando version 2>&1; python3 -c 'print(1)'",
	}, false)
	checkLines(t, home, home, []string{
		"echo ~/bin/komando | xargs rm",
		"ls ~/bin/komando > /tmp/t; xargs rm < /tmp/t",
		"ls ~/bin/komando |& xargs rm",
		`cp /bin/true "$(ls ~/bin/komando)"`,
		"cd ~/.claude && python3 -c \"open('settings.json','w')\"",
		"K=~/bin/komando ls; python3 -c 'print(1)'",
		"export K=~/bin/komando; python3 -c 'import os; open(os.environ[\"K\"],\"w\")'",
		"python3 - <<EOF\nopen(\"\"\"\n" + home + "/bin/komando\n\"\"\".strip(),\"w\")\nEOF",
		"python3 - <<< ~/bin/komando",
		`ls ~/bin/komando; cp /bin/true "$_"`,
		`printf -v p %s ~/bin/komando; cp /bin/true "$p"`,
		`read p <<< ~/bin/komando; cp /bin/true "$p"`,
		`printf -v p %s ~/.claude/settings.json; python3 -c 'import sys;open(sys.argv[1],"w")' "$p"`,
		"for f in a; do ls ~/bin/komando; done | xargs rm",
		"(ls ~/bin/komando; echo) | xargs rm",
		"{ ls ~/bin/komando; } | xargs rm",
		"exec > /tmp/t; ls ~/bin/komando; xargs rm < /tmp/t",
	}, true)
}

// C520: the guard reads a line as each command sees it only when every
// command on it is plain literal text. Each case is a kind of line it
// reads whole instead, so a command that changes the program still sees
// the name another command gives. The first line of each case is refused
// by that check alone; the rest are the review's lines of that kind.
func TestGuardNarrowsOnlyPlainLines(t *testing.T) {
	home, _ := guardLineHome(t)
	bin := filepath.Join(home, "bin", "komando")
	cases := []struct {
		name  string
		lines []string
	}{
		{"a dollar sign", []string{
			`ls ~/bin/komando; cp /bin/true "$_"`,
			`ls ~/bin/komando; read -r p < /tmp/f; cp /bin/true "$p"`,
			`x=_; ls ~/bin/komando; cp /bin/true "${!x}"`,
			`x=_; ls ~/bin/komando; python3 -c 'import sys;open(sys.argv[1],"w")' "${!x}"`,
			`x=_; cat ~/.claude/settings.json; python3 -c 'import sys;open(sys.argv[1],"w")' "${!x}"`,
			"ls ~/bin/komando\ncp /bin/true \"${!x}\"",
			`declare -n r=_; ls ~/bin/komando; cp /bin/true "$r"`,
		}},
		{"a backtick", []string{
			"python3 -c 'import sys;open(sys.argv[1],\"w\")' `which komando`",
		}},
		{"a parenthesis outside quotes", []string{
			"xargs rm < <(ls ~/bin/komando)",
			"(ls ~/bin/komando; echo) | xargs rm",
		}},
		{"a heredoc", []string{
			"xargs rm <<EOF\n" + bin + "\nEOF",
		}},
		{"a redirect to a file", []string{
			"ls ~/bin/komando > /tmp/t; xargs rm < /tmp/t",
		}},
		{"a group or compound command", []string{
			"{ ls ~/bin/komando; } | xargs rm",
			"for f in a; do ls ~/bin/komando; done | xargs rm",
		}},
		{"a background job", []string{
			"ls " + bin + " & jobs | xargs rm",
			"ls ~/bin/komando & python3 -",
		}},
		{"an exclamation mark", []string{
			"ls ~/bin/komando\ncp /bin/true !!:1",
			"set -o history; ls ~/bin/komando; cp /bin/true !$",
			"ls ~/bin/komando; history -p '!!' | xargs rm",
		}},
		{"BASH_COMMAND", []string{
			"ls ~/bin/komando; BASH_COMMAND=1 python3 -",
			`ls ~/bin/komando; cp /bin/true "$BASH_COMMAND"`,
			`trap 'eval cp /bin/true ${BASH_COMMAND#ls }' DEBUG; ls ~/bin/komando`,
			`trap 'eval cp /bin/true ${BASH_COMMAND#* }' DEBUG; komando version ~/bin/komando`,
		}},
		{"code run at run time", []string{
			`ls ~/bin/komando; eval 'cp /bin/true "$'_'"'`,
			`ls ~/bin/komando; eval cp /bin/true '"$'_'"'`,
		}},
		{"a change of folder", []string{
			"cd ~/.claude; python3 -c \"open('settings.json','w')\"",
			"builtin cd ~/.claude; python3 -c \"open('settings.json','w')\"",
			"command cd ~/.claude; python3 -c \"open('settings.json','w')\"",
			"time cd ~/.claude; python3 -c \"open('settings.json','w')\"",
			"env cd ~/.claude; python3 -c \"open('settings.json','w')\"",
			"builtin cd ~/bin && python3 -c \"open('komando','w')\"",
			"builtin pushd ~/.claude; python3 -c \"open('settings.json','w')\"",
			"builtin cd ~/.komando; python3 -c \"print(open('vault.key').read())\"",
			"command cd ~/.komando; python3 -c \"print(open('vault.key').read())\"",
		}},
		{"a program word redefined", []string{
			"hash -p /bin/rm ls; ls ~/bin/komando",
		}},
		{"a variable a reader sets", []string{
			"printf -v p %s ~/bin/komando; cp /bin/true ~p",
		}},
		{"output that goes on through a pipe", []string{
			"echo ~/bin/komando | xargs rm",
			"ls ~/bin/komando |& xargs rm",
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { checkLines(t, home, home, c.lines, true) })
	}
	// every word that runs code, reads the line back or changes the shell
	// keeps the line whole, wherever it stands
	for _, w := range []string{"eval", "trap", "source", ".", "bash", "sh", "zsh", "exec", "command", "builtin",
		"declare", "local", "typeset", "export", "readonly", "alias", "unalias", "hash", "enable", "disable",
		"autoload", "functions", "zmodload", "set", "setopt", "shopt", "emulate", "history", "fc", "r",
		"cd", "pushd", "popd", "chdir"} {
		t.Run("the word "+w, func(t *testing.T) {
			checkLines(t, home, home, []string{"ls ~/bin/komando; " + w + " x; python3 y.py"}, true)
		})
	}
	checkLines(t, home, home, []string{"command -v komando; python3 -c 'print(1)'"}, true)
}

// C520: the lines of the independent reviews that change the program, a
// guard file or a key file, or read a key file, stay refused.
func TestGuardReviewLinesStayRefused(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		"rg ~/.komando/vault.key -e .",
		"grep --regexp=. ~/.komando/vault.key",
		"grep -r . ~/.komando",
		"grep -r ~/.komando .",
		"grep -A ~/.komando/vault.key x",
		"grep -y ~/.komando/vault.key x",
		"grep -P ~/.komando/vault.key x",
		"rg -d 1 ~/.komando/vault.key",
		"rg --pre=cat x ~/.komando/vault.key",
		"rg --pre cat ~/.komando/vault.key .",
		"rg --pre=/bin/cp ~/.komando/vault.key .",
		`komando version; python3 -c "open('/x/.komando/vault.json','w')"`,
		"komando version; sleep 1; cp /bin/true ~/bin/komando",
		`komando version; python3 -c 'import os;os.remove(os.path.expanduser("~/bin/komando"))'`,
		`command -v komando; rm "$(command -v komando)"`,
		"type -p komando; rm -f ~/bin/komando",
		"ls ~/bin/komando; history | tail -1 | python3 -",
		"ls ~/bin/komando; fc -ln -1 | xargs rm",
		"ls ~/bin/komando; fc -s ls=rm",
		"cat ~/.claude/settings.json; sed -i '' s/a/b/ $(!!)",
		"komando version; perl -pi -e s/a/b/ ~/.claude/settings.json",
		"jq . ~/.claude/settings.json; jq . notes > ~/.claude/settings.json",
		"echo ~/bin/komando >&2; cp /bin/true ~/bin/komando",
		"orca worktree create --repo komando --json -o x",
		"orca run --repo komando -- rm ~/bin/komando",
		"orca exec --repo komando rm ~/bin/komando",
		"orca --repo komando terminal send 'rm ~/bin/komando'",
		"gh pr list 2>&1 >~/.claude/settings.json",
		"echo x 1>&2 > ~/bin/komando",
		"echo x >&2>~/bin/komando",
		"ls ~/bin/komando 2>&1 | cat; python3 -c 'print(1)'",
		`grep ~/.komando/vault.key "$@"`,
		`grep ~/.komando/vault.key ''-e .`,
		`grep ~/.komando/vault.key ""-e .`,
		`v=GREP_OPTIONS; export "${v}=-e."; grep ~/.komando/vault.key`,
		"cp /bin/cat /tmp/grep; /tmp/grep ~/.komando/vault.key",
		"grep -i ~/.komando/vault.key -ie.",
		"IFS=e; grep ~/.komando/vault.key -",
		`read p <<< ~/bin/komando; cp /bin/true "$p"`,
		`ls ~/bin/komando; read p < /tmp/f; cp /bin/true "$p"`,
		"command grep ~/.komando/vault.key -e .",
		"busybox grep ~/.komando/vault.key -e .",
		"grep --include=* ~/.komando/vault.key -r",
		"grep -e. --colour=x ~/.komando/vault.key",
	}, true)
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
	t.Setenv("GUARD_TEST_KNOWN_DIR", "/tmp")
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
		`echo x > "$GUARD_TEST_NEVER_SET"`,
		"echo x > `cat /tmp/name`",
		`echo x > $(cat /tmp/name)`,
		`while read f; do echo x > "$f"; done < /tmp/list`,
	}, true)
	checkLines(t, home, home, []string{
		`out=/tmp/x.log; echo x > "$out"`,
		`for f in a.go b.go; do gofmt "$f" > "$f.tmp"; done`,
		`tmp=$(mktemp); echo x > "$tmp"`,
		`echo x > "$GUARD_TEST_KNOWN_DIR/out"`,
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
