package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// cp, mv and rsync write DEST/NAME, or a folder's contents into DEST; ln
// makes a path that leads where its target does. A destination that is or
// holds komando's data, a key folder or a guard file is refused.
func TestGuardCopyIntoAProtectedFolderIsRefused(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		`cp -r /tmp/x/.ssh ~/`,
		`cp -a /tmp/x/.ssh ~`,
		`cp -r /tmp/x/. ~/`,
		`rsync -a /tmp/x/ ~/`,
		`mv /tmp/x/.komando ~/`,
		`cp -r /tmp/x/* ~/`,
		`cp -R /tmp/x/.claude ~`,
		`ditto /tmp/x ~`,
		`ditto /tmp/x ~/`,
		`cp -at ~ /tmp/x/.ssh`,
		`cp -r -t ~ /tmp/x/.ssh`,
		`cp /tmp/x/settings.json ~/.claude/`,
		`ln -s ~ /tmp/h`,
		`ln -s / /tmp/root`,
		`ln -s .. /tmp/up`,
		`cd /tmp && ln -s ~/. h`,
		`cp -r /tmp/x/.ssh ~/ 2>/dev/null`,
		`cp -r /tmp/x/.claude ~ </dev/null`,
		`mv /tmp/x/.komando ~/ >/tmp/log 2>&1`,
	}, true)
}

// rm -r, mv and chmod, chown or chgrp -R reach everything under a folder:
// one that is or holds komando's data, a key folder, a credential store or
// a guard file is refused, as find -delete's start is.
func TestGuardTreeChangeOfAProtectedFolderIsRefused(t *testing.T) {
	home, repo := guardLineHome(t)
	for _, d := range []string{filepath.Join(home, "Library", "Keychains"), filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	checkLines(t, home, home, []string{
		`rm -rf ~`,
		`rm -rf ~/.ss[h]`,
		`rm -rf ~/.ss?`,
		`mv ~/.s*h /tmp/k`,
		`rm -rf "$HOME"`,
		`rm -rf ~/`,
		`rm -fr ~`,
		`rm -Rf ~`,
		`rm --recursive --force ~`,
		`rm --rec -f ~/.ssh`,
		`rm -rf -- ~`,
		`rm -r ~/.ssh`,
		`rm -rf ~/.aws`,
		`rm -rf ~/*`,
		`rm -rf ~/{src,.ssh}`,
		`rm -r /`,
		`mv ~ /tmp/h`,
		`mv ~/.ssh /tmp/k`,
		`mv ~/.. /tmp/u`,
		`mv -t /tmp ~/.ssh`,
		`mv --t /tmp/k ~`,
		`mv --targ=/tmp/k ~/.ssh`,
		`chmod -R 777 ~`,
		`chmod --rec 777 ~/.ssh`,
		`chown -R nobody ~`,
		`chown --recur nobody ~`,
		`chgrp -R staff ~/.ssh`,
		`find ~/.ssh -delete`,
		`trash ~/.ssh`,
		`trash -v ~`,
		`R=rm; $R -rf ~/.ssh`,
		`M=mv; "$M" ~/.ssh /tmp/k`,
		`read p < /tmp/n; $p ~/.ssh /tmp/k`,
		"alias m2=mv\nm2 ~/.ssh /tmp/k",
		`mv {~/.ssh,/tmp/k}`,
		`mv /tmp/x {~/.ssh,/tmp/k}`,
		`mv {~,/tmp/h}`,
		`rm {-rf,~}`,
		`rm {-rf,~/.ssh}`,
		`f=-rf; rm $f ~/.ssh`,
		`o='-rf ~/.ssh'; rm $o`,
		`r=-R; chmod $r 777 ~/.ssh`,
	}, true)
	checkLines(t, home, filepath.Join(home, "Documents"), []string{`rm -rf ..`}, true)
	checkLines(t, home, repo, []string{
		`rm -rf ./build`,
		`rm -rf node_modules`,
		`rm -rf build dist`,
		`mv build /tmp/out`,
		`mv --target ~ build`,
		`R=rm; $R -rf ./build`,
		`M=mv; "$M" build /tmp/out`,
		`rm -rf {build,dist}`,
		`mv {build,/tmp/out}`,
		`f=-rf; rm $f ./build`,
		`mv build {/tmp/a,/tmp/b}`,
		`mv a.txt b.txt`,
		`chmod -R u+w .`,
		`chown -R me build`,
		`rm -f ~/notes.txt`,
		`mv ~/notes.txt /tmp/`,
		`rm -rf /tmp/x`,
	}, false)
	agentRepo(t, repo)
	checkLines(t, home, repo, []string{
		`true && S=/tmp/x && rm -rf $S`,
		`rm -rf ""`,
		`true && S=/tmp/x && mv a.txt $S/`,
		`true && S=/tmp/x && mv a.txt "$S/"`,
	}, false)
}

// treeRefusal is the folder rule's own reason (checkTreeChange).
const treeRefusal = "and everything under it"

// checkRefusedBy is checkLines for lines the guard must refuse with a
// reason that holds why: a pin that another check refuses first does not
// pin the check it names.
func checkRefusedBy(t *testing.T, home, cwd string, lines []string, why string) {
	t.Helper()
	for _, line := range lines {
		d := checkTool(tcl, "Bash", map[string]any{"command": line}, home, cwd)
		if !d.Deny || !strings.Contains(d.Reason, why) {
			t.Errorf("%s: want a refusal with %q, got deny=%v %q", line, why, d.Deny, d.Reason)
		}
	}
}

// Past 64 choices among a line's values the folder rule reads one list of
// every value, where each word that is not an option is an operand: a -S
// from one value cannot hide the folder after it.
func TestGuardFolderRulePastTheChoicesReadsEveryOperand(t *testing.T) {
	home, repo := guardLineHome(t)
	checkRefusedBy(t, home, home, []string{
		`C=-f; B=-f; true || C=-v; true || B=-S; mv $C $C $C $C $C $C $B ~/.ssh /tmp/k`,
	}, treeRefusal)
	checkLines(t, home, repo, []string{
		`C=-f; true || C=-v; mv $C $C $C $C $C $C $C build /tmp/out`,
	}, false)
}

// A program word whose value is empty or holds a separator runs the words
// of its value and of the line after it: the guard reads it as a program
// it cannot name, with the value's own words among its operands.
func TestGuardProgramValueWithASeparatorIsAnyProgram(t *testing.T) {
	home, repo := guardLineHome(t)
	checkRefusedBy(t, home, home, []string{
		`R=; $R rm -rf ~`,
		`R="rm -rf"; eval $R ~`,
		`R="rm -rf"; $R ~`,
		`R="rm -rf $HOME/.ssh"; $R`,
		`IFS=,; R="rm,-rf"; $R ~`,
	}, treeRefusal)
	checkLines(t, home, repo, []string{
		`R=rm; $R -rf ./build`,
		`R="rm -rf"; $R ./build`,
		`G="go test"; $G ./...`,
	}, false)
}

// The folder rule splits a value where the shell may: at the line's own
// IFS, never at \v, \f, \r or a non-breaking space; and a quoted value
// stays one word.
func TestGuardFolderRuleSplitsValuesAsTheShellDoes(t *testing.T) {
	home, repo := guardLineHome(t)
	checkRefusedBy(t, home, home, []string{
		`S=$'x\v-S'; mkdir -p /tmp/k; mv "$S" ~/.ssh /tmp/k`,
		"S='x -S'; mkdir -p /tmp/k; mv \"$S\" ~/.ssh /tmp/k",
		`IFS=,; o="$HOME/.ssh,/tmp/k"; mv $o`,
		`IFS=,; o="-rf,$HOME"; rm $o`,
		`mkdir -p "$HOME/x y"; d="$HOME/x y/.."; rm -rf "$d"`,
	}, treeRefusal)
	checkLines(t, home, repo, []string{
		`S='a b'; mv "$S" /tmp/out`,
		`IFS=,; o="build,/tmp/out"; mv $o`,
	}, false)
}

// The folder rule checks each word once, however many argument lists and
// program values a line gives: a crafted line ends well inside the guard's
// time budget.
func TestGuardFolderRuleChecksEachWordOnce(t *testing.T) {
	home, repo := guardLineHome(t)
	names := make([]string, 64)
	for i := range names {
		names[i] = fmt.Sprint(i + 1)
	}
	list := "{" + strings.Join(names, ",") + "}"
	line := "A=a; true || A=b; P=rm; true || P=trash; $P -rf $A $A $A $A $A $A /tmp/x/" + list + " /tmp/y/" + list
	start := time.Now()
	checkLines(t, home, repo, []string{line}, false)
	if el := time.Since(start); el > time.Second {
		t.Errorf("the check took %v, want under 1s", el)
	}
}

// The agent's own settings folders are the home folder's and those of the
// project in use (the working folder the agent runs in, and the folders
// above it): removing, moving or changing a folder that holds one is
// refused. Another clone or worktree that holds its own is ordinary work.
func TestGuardFolderRuleGuardsTheProjectInUse(t *testing.T) {
	home, repo := guardLineHome(t)
	agentRepo(t, repo)
	other := filepath.Join(home, "src", "other")
	agentRepo(t, other)
	wt := filepath.Join(repo, ".claude", "worktrees", "wt-x")
	agentRepo(t, wt)
	checkLines(t, home, repo, []string{
		`rm -rf ../other`,
		`mv ../other /tmp/o`,
		`chmod -R u+w ../other`,
		`rm -rf ` + wt,
		`git -C ../other pull`,
		`rm -rf ./build`,
		`mv build /tmp/out`,
		`chmod -R u+w build`,
	}, false)
	checkRefusedBy(t, home, repo, []string{
		`rm -rf .`,
		`rm -rf ..`,
		`cd /tmp && rm -rf ` + repo,
		`chmod -R u+w .`,
		`mv ` + repo + ` /tmp/r`,
	}, treeRefusal)
	checkRefusedBy(t, home, wt, []string{
		`rm -rf ` + repo,
		`rm -rf .`,
	}, treeRefusal)
	checkLines(t, home, wt, []string{`rm -rf ` + other}, false)
}

// Copies and links in project and temporary folders stay allowed.
func TestGuardOrdinaryCopiesStayAllowed(t *testing.T) {
	home, repo := guardLineHome(t)
	checkLines(t, home, repo, []string{
		`cp -r src/ /tmp/copy`,
		`cp notes.txt ~/`,
		`cp -r build /tmp/out/`,
		`mv build/out.bin /tmp/`,
		`rsync -a src/ /tmp/mirror/`,
		`ln -sf ../shared/config.yml config.yml`,
		`ln -s /tmp/build out`,
		`install -m 755 build/tool /tmp/bin/`,
	}, false)
}

// Programs that write some of their arguments, or names they read from an
// archive or a repository into a folder: compressors, editors, split, zip,
// plutil, xattr, perl and ruby -i, sqlite3's database, ditto, and tar,
// unzip, cpio and git into their folder.
func TestGuardOtherWritersAreChecked(t *testing.T) {
	home, _ := guardLineHome(t)
	var lines []string
	for _, cmd := range []string{
		`ditto /tmp/a "$f"`, `gzip "$f"`, `gunzip "$f"`, `xz -d "$f"`, `ed "$f" < /tmp/script`, `split -l 10 /tmp/a "$f"`,
		`zip "$f" /tmp/a`, `plutil -convert xml1 "$f"`, `xattr -w k v "$f"`, `perl -pi -e 's/a/b/' "$f"`,
		`ruby -i -pe 'gsub(/a/, "b")' "$f"`, `sqlite3 "$f" 'create table t(x)'`, `tar -xf /tmp/a.tar -C "$f"`,
		`tar --extract --file /tmp/a.tar --directory="$f"`, `tar -czf "$f" src`, `unzip /tmp/a.zip -d "$f"`,
		`cpio -i -D "$f" < /tmp/a.cpio`, `git -C "$f" checkout -- .`, `git clone https://example.com/r.git "$f"`,
	} {
		lines = append(lines, "read f < /tmp/n; "+cmd)
	}
	lines = append(lines,
		`ditto /tmp/x ~/`,
		`cd ~ && tar xzf /tmp/a.tgz`,
		`unzip /tmp/a.zip -d ~`,
		`tar -xf /tmp/a.tar -C ~/.ssh`,
		`git -C ~/.claude checkout -- .`,
	)
	checkLines(t, home, home, lines, true)
}

// Their everyday forms in project and temporary folders stay allowed.
func TestGuardOtherWritersInAProjectStayAllowed(t *testing.T) {
	home, repo := guardLineHome(t)
	checkLines(t, home, repo, []string{
		`tar -xzf /tmp/a.tgz -C /tmp/out`,
		`tar -czf /tmp/a.tgz src`,
		`tar xf /tmp/a.tar`,
		`tar -tzf /tmp/a.tgz`,
		`unzip -o /tmp/a.zip -d /tmp/out`,
		`unzip -l /tmp/a.zip`,
		`gzip -k notes.txt`,
		`perl -pi -e 's/a/b/' notes.txt`,
		`read x < /tmp/n; perl -Mstrict -e 'print 1' "$x"`,
		`sqlite3 /tmp/db.sqlite 'select 1'`,
		`read d < /tmp/n; git -C "$d" status`,
		`git clone https://example.com/r.git /tmp/r`,
		`ditto src /tmp/copy`,
		`zip -r /tmp/a.zip src`,
		`split -l 100 big.txt /tmp/part-`,
	}, false)
}

// git writes the files of a folder only in the commands that change its
// worktree (checkout, merge, pull, stash pop, reset --hard, an alias it
// does not know). The rest write inside .git or nowhere, also in a
// repository that holds an agent's settings folder; worktree add, move and
// remove write their path, read from the -C folder.
func TestGuardGitWritesOnlyInsideDotGitStayAllowed(t *testing.T) {
	home, repo := guardLineHome(t)
	agentRepo(t, repo)
	var lines []string
	for _, cmd := range []string{
		`fetch origin`, `worktree list`, `worktree prune`, `push origin main`, `commit -m x`, `add a.txt`,
		`stash list`, `reset -q HEAD~1`, `bundle list-heads /tmp/a.bundle`, `worktree add /tmp/wt-x -b x`,
		`worktree remove /tmp/wt-x`, `archive -o /tmp/a.tar HEAD`, `config user.name x`, `branch -D old`,
		`-c color.ui=never log --oneline -3`, `worktree add ../wt-y`,
	} {
		lines = append(lines, "git -C "+repo+" "+cmd)
	}
	lines = append(lines, `for w in /tmp/a /tmp/b; do git -C $w pull --ff-only; done`)
	checkLines(t, home, home, lines, false)
}

func TestGuardGitWritesTheWorktreeIsChecked(t *testing.T) {
	home, repo := guardLineHome(t)
	agentRepo(t, repo)
	var lines []string
	for _, cmd := range []string{`checkout -- .`, `stash pop`, `stash`, `reset --hard`, `pull`, `co main`, `merge x`} {
		lines = append(lines, "git -C "+repo+" "+cmd)
	}
	lines = append(lines,
		`git -C /tmp/r worktree add ~/.ssh/x`,
		`git -C ~/.kom* checkout -- .`,
		`for w in /tmp/a ~/.ssh; do git -C $w checkout -- .; done`,
		`git worktree add ~/.komando/x`,
		`git -C ~ worktree add .komando/x`,
		`git -C /tmp/r worktree move /tmp/r/wt ~/.ssh/wt`,
		`git -C /tmp/r config --file ~/.claude/settings.json a.b c`,
		`git -C /tmp/r config --file=`+repo+`/.claude/settings.json a.b c`,
		`git -C /tmp/r bundle create ~/.claude/settings.json HEAD`,
		`x=$(cat /tmp/n); git -C /tmp/r worktree add "$x"`,
		`x=$(cat /tmp/n); git -C /tmp/r worktree move /tmp/r/wt "$x"`,
		`x=$(cat /tmp/n); git -C /tmp/r config --file "$x" a.b c`,
		`x=$(cat /tmp/n); git -C /tmp/r bundle create "$x" HEAD`,
	)
	checkLines(t, home, repo, lines, true)
	// from a folder that holds no guard file, only the -C folder can refuse;
	// a clone that is not the project in use holds no agent's own folder
	plain := t.TempDir()
	checkLines(t, home, plain, []string{`git -C ~ checkout -- .`}, true)
	checkLines(t, home, plain, []string{`git -C ` + repo + ` pull`}, false)
}

// A worktree Claude Code keeps in REPO/.claude/worktrees/NAME is a project
// folder of its own: its files are ordinary files, and only its own agent
// folder and what holds it are guarded.
func TestGuardWorktreeInAnAgentFolderIsAProject(t *testing.T) {
	home, repo := guardLineHome(t)
	agentRepo(t, repo)
	wt := filepath.Join(repo, ".claude", "worktrees", "wt-x")
	agentRepo(t, wt)
	checkLines(t, home, wt, []string{
		`mv /tmp/gi .gitignore`,
		`cp /tmp/a internal/x.go`,
		`ln -s ../../../.venv .venv`,
		`find build -name '*.o' -delete`,
		`cp -r /tmp/src/. internal/`,
		`ln -sfn ` + filepath.Join(repo, ".claude", "skills", "x") + ` /tmp/skill`,
	}, false)
	checkLines(t, home, wt, []string{
		`mv /tmp/a .claude/settings.json`,
		`cp -r /tmp/x/. .`,
		`rm -rf .claude`,
		`cp -r /tmp/x/. ` + filepath.Join(repo, ".claude", "worktrees"),
		`ln -s ` + filepath.Join(repo, ".claude", "worktrees") + ` /tmp/l`,
		`ln -s ` + wt + ` /tmp/l`,
	}, true)
}

// agentRepo makes dir a project folder that holds Claude Code's settings.
func agentRepo(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".claude", "settings.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
