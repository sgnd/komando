package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// completionScript is what `komando completion SHELL` prints.
func completionScript(t *testing.T, shell string, flags ...string) string {
	t.Helper()
	return captureOutput(t, func() error { // cobra's own scripts go to os.Stdout
		root := newRoot()
		root.SetArgs(append([]string{"completion", shell}, flags...))
		root.SilenceErrors, root.SilenceUsage = true, true
		return root.Execute()
	})
}

// The line the README and install.sh give for zsh works in a zsh whose
// ~/.zshrc never ran compinit (a new Mac): the script turns it on itself,
// while "#compdef komando" stays the first line for the fpath way.
func TestZshCompletionWorksWithoutCompinit(t *testing.T) {
	unixOnly(t, "loads the script in zsh")
	for _, flags := range [][]string{nil, {"--no-descriptions"}} {
		lines := strings.SplitN(completionScript(t, "zsh", flags...), "\n", 4)
		if len(lines) < 4 || lines[0] != "#compdef komando" || lines[1]+"\n" != zshInit || lines[2] != "compdef _komando komando" {
			t.Fatalf("%v: script starts %q", flags, lines[:min(3, len(lines))])
		}
	}
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("no zsh here")
	}
	f := filepath.Join(t.TempDir(), "komando.zsh")
	if err := os.WriteFile(f, []byte(completionScript(t, "zsh")), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(zsh, "-f", "-c", `source "$1" && whence -w _komando`, "zsh", f)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "ZDOTDIR="+t.TempDir())
	got, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(got)) != "_komando: function" {
		t.Fatalf("zsh -f: %v, %s", err, got)
	}
}

// The bash line is eval "$(komando completion bash)": it works in bash 3.2
// (macOS), where source <(...) reads nothing.
func TestBashCompletionLoadsWithEval(t *testing.T) {
	unixOnly(t, "loads the script in bash")
	if !strings.Contains(completionHelp["bash"], `eval "$(komando completion bash)"`) {
		t.Fatal("bash help does not give the eval line")
	}
	var shells []string
	for _, b := range []string{"bash", "/bin/bash"} { // /bin/bash is 3.2 on macOS
		if p, err := exec.LookPath(b); err == nil && !slices.Contains(shells, p) {
			shells = append(shells, p)
		}
	}
	if len(shells) == 0 {
		t.Skip("no bash here")
	}
	f := filepath.Join(t.TempDir(), "komando.bash")
	if err := os.WriteFile(f, []byte(completionScript(t, "bash")), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, bash := range shells {
		got, err := exec.Command(bash, "--norc", "-c", `eval "$(cat "$1")" && complete -p komando`, "bash", f).CombinedOutput()
		if err != nil || !strings.Contains(string(got), "-F __start_komando komando") {
			t.Errorf("%s: %v, %s", bash, err, got)
		}
	}
}

// Each shell's help is komando's: the line to add, not cobra's package
// and Homebrew paths.
func TestCompletionHelpIsKomandos(t *testing.T) {
	root := newRoot()
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		c, _, err := root.Find([]string{"completion", shell})
		if err != nil || c.Long != completionHelp[shell] || strings.Contains(c.Long, "brew") {
			t.Errorf("%s: %v, %q", shell, err, c.Long)
		}
	}
}

// A CONN is completed with the conns its command works with: `cache info`
// offers caches, `db query` databases; groups, all and kind: stay.
func TestConnCompletionByFamily(t *testing.T) {
	invHome(t)
	for _, args := range [][]string{
		{"conn", "add", "app-db", "postgres://app@10.0.0.5/app"},
		{"conn", "add", "app-cache", "rediss://default@10.0.0.7:6379/0"},
		{"group", "add", "prod", "app-db"},
	} {
		if _, e := invRun(t, args...); e != nil {
			t.Fatalf("%v: %v", args, e)
		}
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"cache", "info", ""}, "@prod all app-cache kind:"},
		{[]string{"db", "query", ""}, "@prod all app-db kind:"},
		{[]string{"db", "schema", ""}, "@prod all app-db kind:"},
		{[]string{"test", ""}, "@prod all app-cache app-db kind:"},
	} {
		got := captureOutput(t, func() error {
			root := newRoot()
			root.SetArgs(append([]string{"__complete"}, c.args...))
			return root.Execute()
		})
		var names []string
		for _, l := range strings.Split(got, "\n") {
			if l != "" && !strings.HasPrefix(l, ":") && !strings.HasPrefix(l, "Completion ended") {
				names = append(names, l)
			}
		}
		if strings.Join(names, " ") != c.want {
			t.Errorf("%v: %q, want %q", c.args, strings.Join(names, " "), c.want)
		}
	}
}
