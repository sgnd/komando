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
		`rm -rf ~/.config`,
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
		// cp copies its operands, it does not remove or move them
		`true || W=/tmp/w; for f in 1 2 3 4 5 6 7 8 9; do cp "$W/$f" "$f"; done`,
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
		// a literal or a quoted value is one program name, blanks and all
		`"/tmp/a b/rm" -rf ~`,
		`R="/tmp/a b/rm"; "$R" -rf ~`,
		// empty values are gone, and a value after them is still a value
		`E=; $E $E rm -rf ~`,
		`E=; $E $E $E rm -rf ~`,
	}, treeRefusal)
	// a field of a value not quoted is a glob
	checkRefusedBy(t, home, home, []string{`R="rm -rf $HOME/.cla?de"; $R`}, "is an AI agent's settings folder")
	// a $ in a value is text: touch makes a file named $x
	t.Setenv("GUARD_TEST_CMD", "touch $x")
	checkLines(t, home, repo, []string{
		`read x < /tmp/n; $GUARD_TEST_CMD`,
		`R=rm; $R -rf ./build`,
		`R="rm -rf"; $R ./build`,
		`G="go test"; $G ./...`,
		// a quoted value is one program name, blanks and all
		`B="/Applications/My App.app/Contents/MacOS/My App"; read h < /tmp/n; "$B" --size=$h`,
		// and its words are no options of it: -o here makes less write nothing
		`L="less -o"; read h < /tmp/n; "$L" $h`,
		// a value that may be empty leaves the next word as the program
		`true && S=/tmp/x/run.sh; $S --size=4`,
		`E=; $E $E ls`,
		// a program written on the line is its name, an escaped ` in it too
		"cat >f <<EOF\n(2) \\`service.ts\\` ~128-149: price check\nEOF",
	}, false)
}

// A wrapper held in a value (nohup, env, xargs) runs the program after it,
// which the guard checks as it checks that program written on the line.
func TestGuardWrapperInAValueIsUnwrapped(t *testing.T) {
	home, repo := guardLineHome(t)
	var lines []string
	for _, w := range []string{"nohup", "env", "command", "nice", "exec", "time", "sudo", `"nohup nice"`} {
		lines = append(lines, "W="+w+"; $W rm -rf ~")
	}
	checkRefusedBy(t, home, home, append(lines, `W=nohup; read p < /tmp/n; $W $p ~/.ssh /tmp/k`, `env rm -rf ~`), treeRefusal)
	checkRefusedBy(t, home, home, []string{`X=xargs; echo ~ | $X rm -rf`}, "xargs gives rm names")
	checkRefusedBy(t, home, home, []string{`W=nohup; $W tar -xf /tmp/a.tar -C ~`, `env tar -xf /tmp/a.tar -C ~`}, "tar writes names it reads from elsewhere")
	// sed reads $s as its script, rm as a file to remove
	checkRefusedBy(t, home, repo, []string{`P=sed; true || P=rm; read s < /tmp/n; $P -i -e $s notes.txt`}, "names files this line writes with a value")
	checkLines(t, home, repo, []string{
		`W=nohup; $W rm -rf ./build`,
		`W=nohup; $W go test ./...`,
		`env go test ./...`,
		`W=nice; $W -n 5 make build`,
		`X=xargs; echo a | $X wc -l`,
	}, false)
}

// A script runner or a reader held in a value is read as that program written
// on the line: eval's and a shell's -c script, find's -delete, grep -r. Each
// word with a blank given to a program the guard cannot name is read as a
// shell line too, since that program may be eval.
func TestGuardRunnerInAValueReadsItsScript(t *testing.T) {
	home, repo := guardLineHome(t)
	checkRefusedBy(t, home, home, []string{
		`E=eval; $E 'rm -rf ~'`,
		`S=bash; $S -c 'rm -rf ~'`,
		`W=nohup; $W bash -c 'rm -rf ~'`,
		`W=nohup; S=bash; $W $S -c 'rm -rf ~'`,
		`read X < /tmp/n; $X 'rm -rf ~'`,
	}, treeRefusal)
	checkRefusedBy(t, home, home, []string{`F=find; $F ~ -name settings.json -delete`}, "find -delete removes files under")
	checkRefusedBy(t, home, home, []string{`G=grep; $G -r x ~`}, "and grep reads all of it")
	checkLines(t, home, repo, []string{
		`W=nohup; $W go test ./...`,
		`S=bash; $S -c 'go test ./...'`,
		`G=grep; $G -r x ./src`,
		`read X < /tmp/n; $X "fix the build"`,
	}, false)
}

// A wrapper option the guard does not know is read both with and without a
// value, a cluster's last letter may take the next word, and env -C and
// sudo -D run the program in that folder (a lost one when it is not known).
func TestGuardWrapperOptionsWithAValue(t *testing.T) {
	home, repo := guardLineHome(t)
	checkRefusedBy(t, home, home, []string{
		`nice --adjustment 5 rm -rf ~`,
		`sudo --user root rm -rf ~`,
		`sudo -Eu root rm -rf ~`,
		`sudo --us root rm -rf ~`,
		`nice --foo 5 rm -rf ~`,
	}, treeRefusal)
	checkRefusedBy(t, home, repo, []string{
		`env -C ~ rm -rf .ssh`,
		`env --chdir ~ rm -rf .ssh`,
		`env --chdir=$HOME rm -rf .ssh`,
		`env -C$HOME rm -rf .ssh`,
		`sudo -D ~ rm -rf .ssh`,
		`sudo --chdir ~ rm -rf .ssh`,
	}, treeRefusal)
	checkLines(t, home, repo, []string{`env --ch ~ rm -rf .ssh`, `read d < /tmp/n; env -C "$d" rm -rf .ssh`}, true)
	checkLines(t, home, repo, []string{
		`nice --adjustment 5 make build`,
		`nice --foo go test ./...`,
		`env -C ./sub go test ./...`,
		`env -C ~ ls`,
		`timeout --foreground 30 go test ./...`,
		`sudo --user root ls`,
		`sudo -E go test ./...`,
		`env -C ~ true; rm -rf ./build`,
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
	}, treeRefusal)
	// from a project folder, where no field of it names a protected folder
	checkRefusedBy(t, home, repo, []string{`mkdir -p "$HOME/x y"; d="$HOME/x y/.."; rm -rf "$d"`}, treeRefusal)
	checkLines(t, home, repo, []string{
		`S='a b'; mv "$S" /tmp/out`,
		`IFS=,; o="build,/tmp/out"; mv $o`,
	}, false)
}

// The folder rule checks each word once, however many argument lists and
// program values a line gives: a line of 64 lists and 8 program values
// takes about as long as one of a single list or of a single program, and
// well under a second. The words name no path, so the other checks pass
// over them.
func TestGuardFolderRuleChecksEachWordOnce(t *testing.T) {
	home, repo := guardLineHome(t)
	var words string
	for i := range 32 {
		words += fmt.Sprintf(" f%d", i)
	}
	took := func(line string) time.Duration {
		best := time.Hour
		for range 3 {
			start := time.Now()
			checkLines(t, home, repo, []string{line}, false)
			if best = min(best, time.Since(start)); best > time.Second {
				break
			}
		}
		return best
	}
	// P=rm and A=a surely run; the values after || may be added
	values := "P=rm; A=a; true || A=b; "
	for _, p := range []string{"trash", "mv", "chmod", "chown", "chgrp", "/bin/rm", "/bin/chmod"} {
		values += "true || P=" + p + "; "
	}
	one := took(values + "$P -Rf a b a b a b" + words)
	many := took(values + "$P -Rf $A $A $A $A $A $A" + words)
	single := took("P=rm; A=a; true || A=b; $P -Rf $A $A $A $A $A $A" + words)
	t.Logf("64 lists %v, one list %v, one program %v", many, one, single)
	if many > time.Second || many > 8*one || many > 4*single {
		t.Errorf("64 lists took %v, one list %v, one program %v: want under 1s, under 8 times one list and under 4 times one program", many, one, single)
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
		`eval true; rm -rf ../other`,
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
	// from a folder of the project that holds no agent folder itself
	sub := filepath.Join(repo, "internal")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	checkRefusedBy(t, home, sub, []string{`rm -rf ` + repo, `rm -rf ..`}, treeRefusal)
	checkLines(t, home, wt, []string{`rm -rf ` + other}, false)
}

// A folder the line names with a part the guard cannot know before it
// runs: checkWritten refuses one that ends in that part, and the folder
// rule one whose fixed rest after it can end the path of a folder that is
// or holds a protected path (the home folder, the folders above it, the
// project in use and the folders above it). Another fixed rest stays
// allowed.
func TestGuardFolderRuleReadsTheRestOfAnUnknownWord(t *testing.T) {
	home, repo := guardLineHome(t)
	agentRepo(t, repo)
	checkRefusedBy(t, home, repo, []string{
		`read d < /tmp/n; rm -rf "$d"`,
		`read d < /tmp/n; mv "$d/.." /tmp/k`,
		`read d < /tmp/n; chmod -R 777 $d`,
	}, "cannot read before the line runs")
	up := filepath.Base(filepath.Dir(home))
	checkRefusedBy(t, home, repo, []string{
		`read d < /tmp/n; rm -rf "$d/` + up + `"`,
		`read d < /tmp/n; rm -rf "$d/` + filepath.Base(home) + `"`,
		`read d < /tmp/n; mv "$d/src" /tmp/k`,
		`read d < /tmp/n; rm -rf "$d/x/../` + up + `"`,
		`cd "$(cat /tmp/n)" && rm -rf ` + up,
		`cd "$(cat /tmp/n)" && chmod -R 777 src`,
		`read d < /tmp/n; rm -rf "$d/` + up[:1] + `${d}` + up[1:] + `"`,
		// a brace list gives each of its names, after the part or around it
		`read d < /tmp/n; rm -rf "$d"/{` + filepath.Base(home) + `,x}`,
		`cd "$(cat /tmp/n)" && rm -rf {` + filepath.Base(home) + `,x}`,
		`read d < /tmp/n; rm -rf {"$d",x}/` + filepath.Base(home),
		`read d < /tmp/n; mv "$d"/{` + up + `,x} /tmp/k`,
	}, treeRefusal)
	checkLines(t, home, repo, []string{
		`read d < /tmp/n; rm -rf "$d"/{build,dist}`,
		`cd "$(cat /tmp/n)" && rm -rf {build,dist}`,
		`read d < /tmp/n; rm -rf "$d/{` + filepath.Base(home) + `,x}"`, // quoted: no list
		`read d < /tmp/n; rm -rf "$d/build"`,
		`read d < /tmp/n; mv "$d/out.txt" /tmp/`,
		`cd "$(cat /tmp/n)" && rm -rf build`,
		`x=$(git rev-parse --show-toplevel); rm -rf "$x/dist"`,
	}, false)
}

// A pin of the folder rule is refused by the folder rule: ~/.config holds
// a credential store and ~/Library the keychains, and neither is one
// (~/.aws is, and the older read check refuses it first).
func TestGuardFolderRuleRefusesForItsOwnReason(t *testing.T) {
	home, _ := guardLineHome(t)
	checkRefusedBy(t, home, home, []string{
		`rm -rf ~`,
		`rm -rf ~/.ssh`,
		`rm -rf ~/.config`,
		`mv ~/Library /tmp/l`,
		`chmod -R 777 ~`,
	}, treeRefusal)
	checkRefusedBy(t, home, home, []string{`rm -rf ~/.aws`}, "is a credential store")
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
