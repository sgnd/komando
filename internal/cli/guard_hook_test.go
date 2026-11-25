package cli

import (
	"os"
	"path/filepath"
	"testing"
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
