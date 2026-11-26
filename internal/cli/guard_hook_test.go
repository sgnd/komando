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
