package cli

import (
	"fmt"
	"strings"
	"testing"
)

// A glob that names a written file is checked against the guard files: the
// files it matches now, and an agent folder, a hook file or a program named
// komando it could match by name. A brace list is each of its names.
func TestGuardGlobNamingAGuardFileIsRefused(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		`echo x > ~/.claude/setting?.json`,
		`echo x >> ~/.cl*de/settings.json`,
		`cp /tmp/a ~/.claude/settings.js[o]n`,
		`cp /bin/true ~/bin/koman?o`,
		`cp /bin/true ~/bin/koman[d]o`,
		`echo x > ~/bin/{komando,other}`,
		`touch ~/.c?aude`,
		`rm -rf ~/.claude*`,
		`python3 build.py ~/bin/koman?o`,
	}, true)
}

// A glob that matches no guard file stays allowed; * and ? do not match a
// leading dot, so a bare * does not name an agent folder.
func TestGuardOrdinaryGlobWritesStayAllowed(t *testing.T) {
	home, repo := guardLineHome(t)
	checkLines(t, home, repo, []string{
		`rm -f *.o`,
		`chmod +x scripts/*.sh`,
		`cp src/*.go /tmp/copy/`,
		`touch a{1,2}.txt`,
		`rm -f build/*`,
		`echo x > /tmp/out-?.log`,
	}, false)
}

// A glob qualifier or a ( ) group in a word is a glob form the guard does
// not read: zsh's *(D) also matches hidden files, *(e:...:) runs code, and
// a(b|c) is a choice. So is a glob on a line that changes how globs match.
func TestGuardGlobFormsTheGuardDoesNotReadAreRefused(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		`cd ~; rm -rf *(D)`,
		`ls *(e:'echo x > ~/.komando/state.json':)`,
		`echo x > ~/.koman(d|x)o/state.json`,
		`cp /tmp/a ~/.ssh/id_*(N)`,
		`echo "$(rm -rf ~/*(D))"`,
		`shopt -s extglob; rm -rf ~/!(x)`,
		`shopt -s dotglob; cd ~; chmod -R 777 *`,
		`setopt GLOB_DOTS; rm -rf ~/*`,
		`GLOBIGNORE=x; rm -rf ~/*`,
		`cat ~/.ss[!x]/id_ed25519`,
		`cat ~/.ss[[:alpha:]]/id_ed25519`,
		`cat ~/.ss[[.h.]]/id_ed25519`,
		`cat ~/.koman[!x]o/vault.json`,
		`echo x > ~/.claud[!x]/settings.json`,
		`rm -rf ~/.ss[!x]`,
		`rm -rf ~/.ss[h-]`,
		`rm -rf ~/.ss[-h]`,
		`cp /bin/true ~/bin/koman[[=d=]]o`,
	}, true)
	checkLines(t, home, home, []string{
		`f() { echo hi; }; f > /tmp/out`,
		`arr=(a b); echo "${arr[@]}" > /tmp/out`,
		`echo $((2*(3+4))) > /tmp/n`,
		`(( n = 2*(1+1) )); echo $n`,
		`echo "*(D)" > /tmp/out`,
		`(cd /tmp && ls)`,
		"cat > /tmp/main.go <<EOF\nfunc main() { fmt.Println(x) }\nEOF",
		"git commit -m \"$(cat <<'EOF'\nFix the parser (part 1) of 2\nEOF\n)\"",
		`set -euo pipefail; ls *.go`,
		`grep -E '[!a-z]' notes.txt`,
		`[ ! -f build/out ] && make`,
		`[[ -n "$x" ]] && echo ok`,
		`rm -f build/[a-z]*.o`,
		`ls src/[^.]*`,
		`git commit -m "Guard reads [!x] and [[:alpha:]] in globs"`,
	}, false)
}

// A command output in a heredoc whose word is not quoted runs, so its glob
// forms are checked as on the line; the rest of the body is text.
func TestGuardGlobFormsInAHeredocCommandAreRefused(t *testing.T) {
	home, repo := guardLineHome(t)
	checkLines(t, home, home, []string{
		"cat <<EOF\n$(cat ~/.ss[!x]/*)\nEOF",
		"cat <<EOF\n$(mv ~/.ss[!x] /tmp/k)\nEOF",
		"cat <<EOF\n'$(cat ~/.ss[!x]/*)'\nEOF",
		"cat <<EOF\n`cat ~/.ss[!x]/*`\nEOF",
		"cat <<EOF\n$(echo x > ~/.koman(d|x)o/state.json)\nEOF",
	}, true)
	checkLines(t, home, repo, []string{
		"cat >f <<EOF\n[!NOTE]\nEOF",
		"cat >f <<EOF\n$(date)\n[!NOTE] see *(D)\nEOF",
		"cat >f <<'EOF'\n$(cat x[!y])\nEOF",
		"cat >f <<EOF\n\\$(cat x[!y])\nEOF",
	}, false)
}

// A brace list gives the guard at most 64 names: a word with more is
// refused wherever it is checked, so no name past the limit goes unread. A
// { that starts no list leaves the lists after it to be read.
func TestGuardBraceListPastTheLimitIsRefused(t *testing.T) {
	home, repo := guardLineHome(t)
	many := func(last string) string { // 64 names, then last
		var b strings.Builder
		for i := 1; i <= 64; i++ {
			fmt.Fprintf(&b, "%d,", i)
		}
		return "{" + b.String() + last + "}"
	}
	checkLines(t, home, home, []string{
		"rm -rf " + many("~"),
		"mv " + many("~/.ssh") + " /tmp/k",
		"rm -rf " + strings.Repeat("{,}", 11) + "~/.ssh",
		"cat " + many("~/.komando/state.json"),
		"echo x > " + many("~/.claude/settings.json"),
		"unset " + many("CLAUDECODE"),
		"mv {x{/../.ssh,} /tmp/k",
	}, true)
	checkRefusedBy(t, home, repo, []string{"touch " + many("65") + ".txt"}, "more than 64 names")
	checkLines(t, home, repo, []string{
		"rm -rf {build,dist}",
		"touch " + strings.Repeat("{a,b}", 6) + ".txt",
		"touch {x}{a,b}.txt",
	}, false)
}

// A << inside ${...}, $[...] or $'...' starts no here-document, in bash or
// zsh: the lines after it run and are checked. A here-document inside a
// command output inside ${...} is one, and its body stays text.
func TestGuardHeredocMarkInAnExpansionIsNoHeredoc(t *testing.T) {
	home, repo := guardLineHome(t)
	checkRefusedBy(t, home, home, []string{
		"echo ${v/<<'Z'/x}\nrm -rf ~/.ssh",
		"echo $[1<<'Z']\nrm -rf ~/.ssh",
		"echo $'a\\'<<Z'\nrm -rf ~/.ssh",
		"echo \"${v:-\"<<Z\"}\"\nrm -rf ~/.ssh",
		"echo \"${v} <<'Z'\"\nrm -rf ~/.ssh",
		"echo ${v/)/<<'Z'}\nrm -rf ~/.ssh",
		"echo ${v/\\}/<<'Z'}\nrm -rf ~/.ssh",
		"echo ${v:-{a}<<'Z'}\nrm -rf ~/.ssh", // zsh reads {a} inside
	}, treeRefusal)
	checkRefusedBy(t, home, home, []string{"echo ${v/<<Z/x}\nrm -rf ~/.ss[!x]"}, "has a [ ] list")
	checkLines(t, home, repo, []string{
		"echo ${v:-$(cat <<'EOF'\nrm -rf ~/.ssh\nEOF\n)}",
		"echo \"${v}\"; cat >f <<'EOF'\nrm -rf ~/.ssh\nEOF",
		"echo ${#v} ${v%%/*}\ncat >f <<'EOF'\nrm -rf ~/.ssh\nEOF",
		"echo $[2*3]; cat >f <<'EOF'\nrm -rf ~/.ssh\nEOF",
		"echo $'a\\'b'; cat >f <<'EOF'\nrm -rf ~/.ssh\nEOF",
	}, false)
}
