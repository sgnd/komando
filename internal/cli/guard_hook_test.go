package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// guardLineHome is a home with a settings file and a program named komando
// in ~/bin, as an agent's machine has them, and a checkout whose folders
// are named komando, outside PATH.
func guardLineHome(t *testing.T) (home, repo string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	repo = filepath.Join(home, "src", "komando")
	for _, d := range []string{filepath.Join(home, ".claude"), filepath.Join(home, "bin"), filepath.Join(repo, "cmd", "komando")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(home, ".claude", "settings.json"), filepath.Join(home, "bin", "komando")} {
		if err := os.WriteFile(f, []byte("x\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return home, repo
}

func checkLines(t *testing.T, home, cwd string, lines []string, wantDeny bool) {
	t.Helper()
	for _, line := range lines {
		d := checkTool(tcl, "Bash", map[string]any{"command": line}, home, cwd)
		switch {
		case wantDeny && !d.Deny:
			t.Errorf("%s: want a refusal", line)
		case !wantDeny && d.Deny:
			t.Errorf("%s: want it allowed, got %q", line, d.Reason)
		}
	}
}

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

// C520: a line that runs komando, or reads its program, next to another
// command names komando only for that command: python3 and sleep beside it
// get nothing from it. A reader whose output goes on (a pipe, a file, a
// command substitution), cd, a variable and a heredoc still count.
func TestGuardKomandoRunNextToAnotherCommand(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		"python3 -c 'print(1)'; komando version",
		"komando version && sleep 2 && komando list",
		"sleep 5; ~/bin/komando version",
		"stat ~/bin/komando; sleep 1",
		"python3 -c 'print(1)' && ls -la ~/bin/komando",
		"command -v komando; python3 -c 'print(1)'",
		"cat ~/.claude/settings.json; python3 -c 'print(1)'",
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

// Programs that only read may name a guard file or the komando program:
// an agent looks at them all the time. rtk only filters what the program
// after it prints.
func TestGuardReadersMayNameGuardFiles(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		"grep -n guard ~/.claude/settings.json | cut -c1-200",
		"cut -d: -f1 ~/.claude/settings.json",
		"sort ~/.claude/settings.json | uniq -c",
		"uniq ~/.claude/settings.json",
		"wc -l ~/.claude/settings.json",
		"head -5 ~/.claude/settings.json | tail -1",
		"stat -f %z ~/bin/komando",
		"file ~/bin/komando",
		"go version -m ~/bin/komando",
		"awk '{print $1}' ~/.claude/settings.json",
		"awk -F: 'NR<5 {print NR\": \"$0}' ~/.claude/settings.json",
		"sed -n 1,20p ~/.claude/settings.json",
		"sed -n '/hooks/p' ~/.claude/settings.json",
		"sed 's/a/b/g' ~/.claude/settings.json",
		"rtk grep -c hooks ~/.claude/settings.json",
		"rtk cat ~/.claude/settings.json",
	}, false)
}

// The same readers in a form that writes are refused: an output file, an
// in-place edit, a write or a command inside the program, a redirect, or
// rtk in front of a program that writes.
func TestGuardReadersThatWriteAreRefused(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		"sort -o ~/.claude/settings.json /tmp/x",
		"sort --output=" + home + "/.claude/settings.json /tmp/x",
		"sort /tmp/x -o ~/bin/komando",
		"uniq /tmp/x ~/.claude/settings.json",
		"awk -i inplace '{print}' ~/.claude/settings.json",
		"awk '{print > \"/tmp/x\"}' ~/.claude/settings.json",
		"awk '{system(\"rm \" FILENAME)}' ~/.claude/settings.json",
		"awk '{print | \"sh\"}' ~/.claude/settings.json",
		"sed -i '' s/a/b/ ~/.claude/settings.json",
		"sed -i.bak s/a/b/ ~/.claude/settings.json",
		"sed --in-place s/a/b/ ~/.claude/settings.json",
		"sed -n 'w /tmp/x' ~/.claude/settings.json",
		"sed 's/a/b/w /tmp/x' ~/.claude/settings.json",
		"sed '1e rm -f x' ~/.claude/settings.json",
		"go build -o ~/bin/komando ./cmd/komando",
		"go version -m /tmp/x > ~/bin/komando",
		"cut -c1-5 /tmp/x > ~/.claude/settings.json",
		"head -1 /tmp/x >> ~/bin/komando",
		"rtk sed -i s/a/b/ ~/.claude/settings.json",
		"sed --in s/a/b/ ~/.claude/settings.json",
		"sed --exp='w /tmp/x' ~/.claude/settings.json",
		"sort --compress-program=sh ~/.claude/settings.json",
		"awk '@load \"inplace\"; {print}' ~/.claude/settings.json",
		"rtk cp /bin/true ~/bin/komando",
	}, true)
}

// A word ending in /komando that is no file is not a program: a repo slug
// after -R or --repo, a URL, a loop over repo slugs, and a real folder
// named komando may be named, by gh, git and the readers. Other programs
// still may not: curl -O names its file after the URL.
func TestGuardKomandoWordsThatAreNoProgram(t *testing.T) {
	home, repo := guardLineHome(t)
	checkLines(t, home, home, []string{
		"gh pr view 1 -R sgnd/komando",
		"gh pr list --repo sgnd/komando --json number",
		"gh pr list --repo=sgnd/komando",
		"gh issue view 561 -R sgnd/komando -q .title --json title",
		`for r in sgnd/komando efolusi/sso; do gh pr list -R "$r"; done`,
		"git ls-remote https://github.com/sgnd/komando",
		"git -C " + filepath.ToSlash(repo) + " status",
		"git -C " + filepath.ToSlash(repo) + " log --oneline -3",
	}, false)
}

// The refusals of F1 and F2 stay: creating, linking or moving a file named
// komando anywhere, writing it through a redirect, an output flag, a
// variable or an interpreter's code, and changing the existing program.
func TestGuardKomandoProgramStaysProtected(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		"cp /bin/true ~/newbin/komando",
		"ln -s /bin/true ~/newbin/komando",
		"mv /tmp/x ~/newbin/komando",
		"install /bin/true ~/newbin/komando",
		"tee ~/newbin/komando < /tmp/x",
		"echo x > ~/newbin/komando",
		"p=~/newbin/komando; cp /bin/true \"$p\"",
		`for f in ~/newbin/komando; do cp /bin/true "$f"; done`,
		`python3 -c "open('` + home + `/newbin/komando','w')"`,
		"gh release download v0.17.2 -R sgnd/komando -O ~/newbin/komando",
		"gh release download v0.17.2 --repo sgnd/komando --output ~/newbin/komando",
		"git archive -o ~/newbin/komando HEAD",
		"git show HEAD:x > ~/newbin/komando",
		"curl -o ~/newbin/komando https://example.com/k",
		"curl -sO https://github.com/sgnd/komando",
		"chmod +x ~/bin/komando",
		"rm ~/bin/komando",
		"gh pr view 1 -R sgnd/komando; cp /bin/true ~/newbin/komando",
		"git checkout HEAD -- ~/newbin/komando",
		"git -C ~/newbin restore ~/newbin/komando",
		"git mv tools/k ~/newbin/komando",
		"git config --file ~/newbin/komando a.b c",
		"gh pr checkout 1 -R sgnd/komando",
		"gh repo fork sgnd/komando --clone",
		"gh run download 1 -R sgnd/komando -D ~/newbin/komando",
	}, true)
}

// A sed script glued to its option, alone or in a cluster, is a script as
// getopt reads it, and is checked: a write in it is refused. So is an
// option the reader does not know, a script or program file, and sort's
// temporary folder.
func TestGuardReaderOptionsAsGetoptReadsThem(t *testing.T) {
	home, _ := guardLineHome(t)
	hook := filepath.ToSlash(filepath.Join(home, ".claude", "settings.json"))
	codex := "./.codex/hooks.json" // no i, I or f in it, as in Audit's case
	checkLines(t, home, home, []string{
		"sed -n -es/^/x/w" + codex + " p",
		"sed -nes/^/x/w" + codex + " p",
		"sed --expression=s/^/x/w" + codex + " p",
		"sed --expr=s/^/x/w" + codex + " p",
		"sed -n --e s/^/x/w" + codex + " p",
		"sed -n -es/^/x/w" + hook + " p",
		"sed -n -l 5 -ew/tmp/x " + hook,
		"sed -nf /tmp/script " + hook,
		"sed -n --fi=/tmp/script " + hook,
		"sed -nX p " + hook,
		// the hook file is only read here: the parser alone must find the write
		"sed -n -ew/tmp/x p " + hook,
		"sed -new/tmp/x p " + hook,
		"sed --expression=w/tmp/x p " + hook,
		"sed --expression w/tmp/x p " + hook,
		"sed -n -f p " + hook,
		"sed -n --fi=/tmp/s p " + hook,
		"awk -f /tmp/prog " + hook,
		"awk -vx=1 -fprog " + hook,
		"sort -T ~/.claude /tmp/x",
		"sort -T /tmp/t " + hook,
		"sort --temp=/tmp " + hook,
		"sort -uo " + hook + " /tmp/x",
		"uniq --skip-fields 1 /tmp/x " + hook,
	}, true)
	checkLines(t, home, home, []string{
		"sed -n p " + hook,
		"sed -ne 1,5p " + hook,
		"sed -n -e 1p -e 2p " + hook,
		"sed --quiet --expression=1p " + hook,
		"sed -nE '/hooks/p' " + hook,
		"sort -k2 -t: " + hook,
		"uniq -c " + hook,
		"awk -F: -v n=2 '{print $n}' " + hook,
	}, false)
}

// A program that writes in another form is checked against the whole
// line even in its read form: a hook file named in its script or a flag,
// not as a file it reads, is refused.
func TestGuardReaderScriptNamingAHookFile(t *testing.T) {
	home, _ := guardLineHome(t)
	hook := filepath.ToSlash(filepath.Join(home, ".claude", "settings.json"))
	checkLines(t, home, home, []string{
		"sed -n 's|x|" + hook + "|p' /tmp/x",
		"awk '{print \"" + hook + "\"}' /tmp/x",
		"f=" + hook + "; sed -n p /tmp/x",
		"git fetch https://github.com/sgnd/komando",
	}, true)
}
