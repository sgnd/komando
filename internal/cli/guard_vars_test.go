package cli

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// A value the guard checks is known only when every part of it is literal
// or comes from a rule that proves it. A redirect target or an argument of
// a program that writes files with any other part is refused; known values
// stay allowed. Each test below pins one source of unknown parts.

// The output of a command is known only for mktemp and date run as one
// simple command: in a list or a pipeline, with a redirect or a comment, or
// on a line that can make the name run another program, the output is the
// output of something else.
func TestGuardCommandOutputIsKnownOnlyWhenProved(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		`echo x > "$(mktemp >/dev/null; echo ~/.komando/state.json; true)"`,
		`echo x > "$(mktemp && cat /tmp/n)"`,
		`echo x > "$(mktemp | cat /tmp/n -)"`,
		`echo x > "$(mktemp </tmp/n)"`,
		"echo x > `mktemp; cat /tmp/n`",
		`f=$(mktemp; cat /tmp/n); echo x > "$f"`,
		`f=$(mktemp && cat /tmp/n); cp /tmp/a "$f"`,
		`f=$(mktemp | cat /tmp/n -); echo x > $f`,
		"f=`mktemp; cat /tmp/n`; echo x > $f",
		"echo x > \"$(mktemp -p /nonexistent #)\ncat /tmp/n)\"",
		`mktemp() { cat /tmp/n; }; echo x > "$(mktemp)"`,
		`alias date='cat /tmp/n'; echo x > "$(date +%F)"`,
		`PATH=/tmp/bin:$PATH; echo x > "$(mktemp)"`,
		`TMPDIR=~/.komando; echo x > "$(mktemp)"`,
		`echo x > "$(date)"`,
		`echo x > "$(date +%N)"`,
		`echo x > "$(echo ~/.koman?o/state.json)"`,
		`echo x > ~/"$(printf '\x2ekomando')"/state.json`,
		`f=$(date +%F)$(cat /tmp/n); echo x > "$f"`,
	}, true)
	checkLines(t, home, home, []string{
		`tmp=$(mktemp); echo x > "$tmp"`,
		`echo x > "$(mktemp)"`,
		`cmd > "$(mktemp)"`,
		`d=$(mktemp -d); echo x > "$d/out"`,
		`LOG=$(mktemp); go test ./... > "$LOG" 2>&1`,
		`echo x > "$(date +%F).log"`,
		`echo x > "build-$(date +%s).log"`,
		`echo x > /tmp/log.$(date -u +%Y%m%dT%H%M%S)`,
		`f=$(date '+%F %T'); echo x > "/tmp/$f.log"`,
	}, false)
}

// The proof of mktemp and date is lost only where the line can change what
// the name runs or where mktemp writes: alias, function, eval, source or .
// as a command, and PATH, path or TMPDIR set or unset. The same words as
// text, a path or a value read ($TMPDIR, find ., source-parser.ts, f())
// keep it.
func TestGuardProofIsLostOnlyByARealRedefinition(t *testing.T) {
	home, _ := guardLineHome(t)
	for _, pre := range []string{
		`PATH=/tmp/bin:$PATH`, `export TMPDIR=~/.komando`, `path+=(/tmp/bin)`, `typeset -U path`, `unset TMPDIR`,
		`. /tmp/env.sh`, `source /tmp/env.sh`, `mktemp() { cat /tmp/n; }`, `function mktemp { cat /tmp/n; }`,
		`if true; then alias mktemp=x; fi`, `command eval "$(cat /tmp/n)"`, `true && hash -p /tmp/x mktemp`,
	} {
		checkLines(t, home, home, []string{pre + `; f=$(mktemp); echo x > "$f"`}, true)
	}
	for _, pre := range []string{
		`D=$TMPDIR/x`, `find . -name '*.go' | head`, `curl -o /tmp/sp.ts https://x/src/source-parser.ts`,
		`echo "$PATH"`, `grep -n 'func f()' main.go`, `go test ./... -run 'TestAlias'`, `echo hash enable`,
		"git commit -m 'Keep `~/.komando`. Then run (see docs). Done'",
	} {
		checkLines(t, home, home, []string{pre + `; f=$(mktemp); echo x > "$f"`}, false)
	}
}

// ${NAME:?} and ${NAME?} give NAME's value, or stop the line before the
// command runs.
func TestGuardErrorFormGivesTheValue(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		`L=/tmp/locks; G=; until mkdir "${L:?}/gate-1" 2>/dev/null && G=gate-1; do sleep 1; done; rmdir "${L:?}/${G:?}"`,
		`D=/tmp/out; rm -rf "${D?no folder}"`,
	}, false)
	checkLines(t, home, home, []string{
		`L=~/.komando; rm -rf "${L:?}/keys"`,
		`read L < /tmp/n; echo x > "${L:?}"`,
	}, true)
}

// A command's output inside a word leaves the whole word unknown: the
// guard does not check the word with the output left out.
func TestGuardCommandOutputInsideAWordIsUnknown(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		`echo x > ~/.$(rev <<< odnamok)/state.json`,
		`echo x > "$HOME/.$(rev <<< odnamok)/state.json"`,
		"echo x > ~/.`rev <<< odnamok`/state.json",
		`echo x > ~/.koma$(cat /tmp/n)`,
		`cp /tmp/a ~/.$(rev <<< odnamok)/state.json`,
		`mv /tmp/a "$HOME/.$(cat /tmp/n)/state.json"`,
		`bash -c "echo x > $(cat /tmp/n)"`,
	}, true)
}

// A variable keeps every value it may have: an assignment that may not run
// (after && or ||, in a subshell, in a pipeline, in a loop) adds a value
// and replaces none.
func TestGuardVariableKeepsEveryValueItMayHave(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		`f=~/.komando/state.json; false && f=/tmp/x; echo x > $f`,
		`f=~/.komando/state.json; true || f=/tmp/x; echo x > $f`,
		`f=~/.komando/state.json; (f=/tmp/x); echo x > $f`,
		`f=~/.komando/state.json; echo | f=/tmp/x; echo x > $f`,
		`f=~/.komando/state.json; { f=/tmp/x; } | cat; echo x > $f`,
		`f=~/.komando/state.json; (f=/tmp/x); cp /tmp/a "$f"`,
		`f=~/.komando/state.json; for f in /tmp/x; do :; done; echo x > $f`,
		`false && d=/tmp; cp /tmp/a ~/.koma${d}ndo/state.json`,
		`a=( $(cat /tmp/n) ); echo x > $a`,
		`f="a $HOME/.komando/state.json"; cp /tmp/x $f`,
		`IFS=,; f=/tmp/a,$HOME/.komando/state.json; rm $f`,
	}, true)
	checkLines(t, home, home, []string{
		`out=/tmp/x.log; [ -n "$CI" ] && out=/tmp/ci.log; echo x > "$out"`,
		`f=a.txt; f=b.txt; cp a "$f"`,
		`tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT; echo x > "$tmp"`,
	}, false)
}

// After a name reference, eval, source or a trap that may run at any time,
// no variable is known: each can set any of them.
func TestGuardVariableSetOutOfSightIsUnknown(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		`d=.komando; f=$HOME/$d/state.json; declare -n r=f; echo x > $r`,
		`f=/tmp/x; declare -n r=f; r=~/.komando/state.json; echo x > "$f"`,
		`f=/tmp/x; typeset -n r=f; r=~/.komando/state.json; cp /tmp/a "$f"`,
		`f=/tmp/x; local -n r=f; r=$HOME/.komando/state.json; echo x > "$f"`,
		`declare -n r=_; ls ~/bin/komando; cp /bin/true "$r"`,
		`f=/tmp/x; eval "f=$(cat /tmp/n)"; echo x > "$f"`,
		`f=/tmp/x; source /tmp/vars.sh; cp /tmp/a "$f"`,
		`f=/tmp/x; . /tmp/vars.sh; cp /tmp/a "$f"`,
		`trap 'f=$(cat /tmp/n)' DEBUG; f=/tmp/x; echo x > "$f"`,
		`trap 'eval cp /bin/true ${BASH_COMMAND#ls }' DEBUG; ls ~/bin/komando`,
		`f=/tmp/x; print -v f "$(cat /tmp/n)"; cp /tmp/a "$f"`,
	}, true)
}

// A program that writes the files its arguments name is refused an
// argument whose value the guard cannot read, one pin per program; so is a
// program whose own name the guard cannot read, and xargs feeding names to
// a writing program.
func TestGuardWritingProgramWithUnknownArgumentIsRefused(t *testing.T) {
	home, _ := guardLineHome(t)
	var lines []string
	for _, cmd := range []string{
		`cp /tmp/a "$f"`, `mv /tmp/a "$f"`, `ln -sf /tmp/a "$f"`, `install -m 600 /tmp/a "$f"`,
		`tee "$f" < /tmp/a`, `tee -a "$f" < /tmp/a`, `dd if=/tmp/a of="$f"`, `truncate -s 0 "$f"`,
		`sed -i s/a/b/ "$f"`, `chmod 777 "$f"`, `chown me "$f"`, `chgrp staff "$f"`, `rm -f "$f"`,
		`rmdir "$f"`, `unlink "$f"`, `shred "$f"`, `touch "$f"`, `mkdir -p "$f"`, `sort -o "$f" /tmp/a`,
		`less -o "$f" /tmp/a`,
	} {
		lines = append(lines, "read f < /tmp/n; "+cmd)
	}
	lines = append(lines,
		`printf -v f %s/.komando/state.json "$HOME"; cp /tmp/a "$f"`,
		`d=.komando; f=$HOME/$d/state.json; n=f; cp /tmp/a ${!n}`,
		`f=$HOME/.kXmando/state.json; cp /tmp/a ${f/X/o}`,
		`f=$HOME/.kXmando/state.json; tee ${f/X/o} < /tmp/a`,
		`f=$HOME/.kXmando/state.json; dd if=/tmp/a of=${f/X/o}`,
		`cp /tmp/a ${X:-$HOME/.komando/state.json}`,
		`set -- ~/.komando/state.json; cp /tmp/a $1`,
		`x=_; ls ~/bin/komando; cp /bin/true "${!x}"`,
		`ls ~/bin/komando; cp /bin/true "$_"`,
		`ls ~/bin/komando; cp /bin/true "$BASH_COMMAND"`,
		`ls ~/bin/komando; read -r p < /tmp/f; cp /bin/true "$p"`,
		`read p < f; cp /bin/true "$p"`,
		`p=/tmp/x; read p < /tmp/f; cp /bin/true "$p"`,
		`cmd=cp; read f < /tmp/n; $cmd /tmp/a "$f"`,
		`read f < /tmp/n; $(cat /tmp/prog) /tmp/a "$f"`,
		`printf '%s\n' ~/.komando/state.json | xargs rm -f`,
		`echo ~/.komando/state.json | xargs -I{} cp /tmp/a {}`,
	)
	checkLines(t, home, home, lines, true)
}

// A writing program's argument is read as the program reads it: a path
// after = or after a short option, $HOME in the middle of a word, and the
// files touch and mkdir make.
func TestGuardWritingProgramArgumentIsReadAsTheProgramReadsIt(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		`dd if=/tmp/a of=$HOME/.komando/state.json`,
		`dd if=/tmp/a of=~/.komando/state.json`,
		`cp --target-directory=$HOME/.komando /tmp/a`,
		`cp -t$HOME/.komando /tmp/a`,
		`cp /tmp/a /$HOME/.komando/state.json`,
		`touch ~/.komando/state.json`,
		`mkdir -p ~/.komando/keys2`,
		`touch "$HOME/.ssh/id_ed25519"`,
		`d=.komando; touch ~/$d/audit.log`,
	}, true)
	t.Setenv("GUARD_TEST_DIR", "/tmp/guard-test")
	checkLines(t, home, home, []string{
		`for f in a.go b.go; do cp "$f" "$f.bak"; done`,
		`tmp=$(mktemp -d); cp a.txt "$tmp/"; rm -rf "$tmp"`,
		`rm -rf "$GUARD_TEST_DIR/out"`,
		`sed -i 's/a/b/' notes.txt`,
		`chmod +x build/run.sh`,
		`touch a.txt`,
		`mkdir -p build/out`,
		`mkdir -p ~/.ssh`,
		`git ls-files | xargs gofmt -l`,
		`dd if=/dev/zero of=/tmp/blob bs=1k count=1`,
		`cp -r src/ /tmp/copy`,
	}, false)
}

// After a cd the guard cannot follow (cd -, a folder it cannot read, popd,
// eval or source), a relative name a command writes is read as a fixed name
// in an unknown folder: refused when it is a protected name, the folder
// itself, a glob or unknown; reads and full paths stay allowed.
func TestGuardWriteAfterAnUnknownFolderChangeIsRefused(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		`cd -; echo x > state.json`,
		`cd "$OLDPWD" && cp /tmp/a state.json`,
		`cd "$(cat /tmp/d)" && echo x > vault.json`,
		`cd - && rm -rf keys`,
		`read d < /tmp/d; cd "$d"; touch state.json`,
		`pushd /tmp; popd; echo x > state.json`,
		`eval "cd $(cat /tmp/d)"; echo x > state.json`,
		`CDPATH=~; cd .komando; echo x > state.json`,
		`cd - && echo x > settings.json`,
		`cd - && rm -rf .`,
		`cd - && rm -f *`,
		`read n < /tmp/n; cd -; echo x > "$n"`,
		`cd -; cp /tmp/a .ssh/rc`,
	}, true)
	checkLines(t, home, home, []string{
		`cd - && cat state.json`,
		`cd -; echo x > /tmp/out.txt`,
		`cd /tmp && echo x > out.txt`,
		`cd "$(mktemp -d)" && echo x > out.txt`,
		`cd -; ls > /dev/null 2>&1`,
		`cd src && echo x > out.txt`,
		`cd -; echo x > out.txt`,
		`read d < /tmp/d; cd "$d" && rm -rf build/out`,
	}, false)
}

// A part the guard cannot know may hold / and .., so it can lead out of
// any folder before it. A written name whose last part is unknown is a
// wholly unknown target and refused, in /tmp too; a last part with a fixed
// ending after the unknown part is allowed when no protected name has that
// ending. Anything else stays refused.
func TestGuardUnknownLastNameIsRefusedUnlessItsEndingIsSafe(t *testing.T) {
	home, repo := guardLineHome(t)
	checkLines(t, home, repo, []string{
		`echo x > "/tmp/out-$(cat /tmp/n).log"`,
		`echo x > "build/$(git rev-parse --short HEAD).txt"`,
		`read n < /tmp/n; cp a.txt "$PWD/build/$n.bak"`,
	}, false)
	checkLines(t, home, repo, []string{
		`read n < /tmp/n; echo x > "/tmp/$n"`,
		`read n < /tmp/n; cp a.txt "$PWD/build/$n"`,
		`read n < /tmp/n; echo x > "$HOME/$n"`,
		`echo x > ~/.claude/$(cat /tmp/n)`,
		`read n < /tmp/n; echo x > ~/.komando/"$n"`,
		`read n < /tmp/n; cd ~ && echo x > "log-$n"`,
		`read n < /tmp/n; echo x > "/tmp/$n/settings.json"`,
		`read n < /tmp/n; echo x > "/tmp/$n.json"`,
		`read n < /tmp/n; echo x > "/tmp/x-$n.key"`,
		`read n < /tmp/n; echo x > "/tmp/$n-$n"`,
	}, true)
}

func TestGuardFixedNameAfterAnUnknownFolderIsAllowed(t *testing.T) {
	home, repo := guardLineHome(t)
	checkLines(t, home, repo, []string{
		`read d < /tmp/d; echo x > "$d/out.txt"`,
		`cp a.txt "$(git rev-parse --show-toplevel)/build/a.txt"`,
		`echo x > "$(pwd)/notes.txt"`,
		`read d < /tmp/d; ln -sf /tmp/a "$d/link"`,
		`read d < /tmp/d; cp -r /tmp/src "$d/x"`,
	}, false)
	var lines []string
	for _, name := range []string{"settings.json", "settings.local.json", "hooks.json", "state.json", "vault.key",
		"store.db", ".env", "komando", "id_ed25519", ".ssh/rc", ".claude", ".komando/x", "", ".", "..", "*", "*.json", "{a,komando}"} {
		lines = append(lines, `read d < /tmp/d; echo x > "$d"/`+name)
	}
	lines = append(lines,
		`read d < /tmp/d; cp /tmp/settings.json "$d/x"`,
		`read d < /tmp/d; cp -r /tmp/src/. "$d/x"`,
		`read d < /tmp/d; rsync -a /tmp/src/ "$d/x"`,
		`read d < /tmp/d; cp /tmp/a $d/out.txt`,
		`read d < /tmp/d; cp --target-directory="$d" /tmp/a`,
		`read d < /tmp/d; cp -t"$d" /tmp/a`,
		`read f < /tmp/f; dd if=/tmp/a of="$f"`,
		`read d < /tmp/d; tar -xf /tmp/a.tar -C "$d/x"`,
	)
	checkLines(t, home, repo, lines, true)
}

// The shell's own numbers are known: [0-9]* stands for each value, so they
// do not hide a secret folder either.
func TestGuardShellNumbersAreKnown(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		`echo x > /tmp/log.$RANDOM`,
		`echo x > "/tmp/run-$SECONDS.log"`,
		`echo x > "/tmp/t-$EPOCHSECONDS.log"`,
		`echo x > /tmp/log.$$`,
	}, false)
	checkLines(t, home, home, []string{
		`echo x > ~/.komando/log.$RANDOM`,
		`echo x > "$HOME/.komando/$(date +%s)"`,
	}, true)
}

// Lines that write komando's data, a key, the program or an agent's
// settings through the forms above, one or more at a time.
func TestGuardWritesThroughTheseFormsAreRefused(t *testing.T) {
	home, _ := guardLineHome(t)
	if err := os.MkdirAll(filepath.Join(home, ".komando"), 0o700); err != nil {
		t.Fatal(err)
	}
	checkLines(t, home, home, []string{
		`d=.komando; f=$HOME/$d/state.json; bash -c 'declare -n r=f; echo x > $r'`,
		`d=.komando; f=$HOME/$d/state.json; n=f; echo x > ${!n}`,
		`echo x > ${X:-~/.komando/state.json}`,
		`f=$HOME/.kXmando/state.json; echo x > ${f/X/o}`,
		`d=.komando; a=(/tmp/x ~/$d/state.json); cp /tmp/a ${a[1]}`,
		`d=.komando; set -- ~/$d/state.json; cp /tmp/a $1`,
		`read f < /tmp/name; tee $f < /tmp/a`,
		`d=.komando; for f in ~/$d/state.json; do cp /tmp/a $f; done`,
		`echo x > $(mktemp -p ~/.komando)`,
		`echo x > $(mktemp -u ~/.komando/state.json)`,
		`d=.komando; f=$(mktemp); mv $f ~/$d/state.json`,
		`x=_; ls ~/bin/komando; python3 -c 'import sys;open(sys.argv[1],"w")' "${!x}"`,
		`ls ~/bin/komando; eval 'cp /bin/true "$'_'"'`,
		`trap 'eval cp /bin/true ${BASH_COMMAND#* }' DEBUG; komando version ~/bin/komando`,
		`printf -v p %s ~/bin/komando; cp /bin/true "$p"`,
		`printf -v p %s ~/.claude/settings.json; python3 -c 'import sys;open(sys.argv[1],"w")' "$p"`,
		`read p < /tmp/f; ls ~/.ssh/id_ed25519; cp /tmp/a "$p"`,
	}, true)
}

// A command output assigned to a variable is one word, in quotes or not:
// the value mktemp or date gives is known there too.
func TestGuardAssignedCommandOutputStaysKnown(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		`tmp="$(mktemp)"; echo x > "$tmp"`,
		`d="$(mktemp -d)"; cp a.txt "$d/a.txt"`,
		`stamp=$(date '+%F %T'); echo x > "/tmp/run $stamp.log"`,
		`stamp=$(date '+%F rm -rf /'); echo "$stamp"`,
	}, false)
	checkLines(t, home, home, []string{
		`tmp="$(mktemp; cat /tmp/n)"; echo x > "$tmp"`,
		`tmp="$(cat /tmp/n)"; cp /tmp/a "$tmp"`,
	}, true)
}

// zsh gives $=NAME, $~NAME, $^NAME, $NAME[...] and $NAME:MOD a value other
// than the variable's own: such a word is unknown. A $ the shell leaves as
// it is (s/a$/b/) stays plain text.
func TestGuardZshValueFormsAreUnknown(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		`f=~/.komando.x; echo x > $f:r/state.json`,
		`f=$HOME/.kXmando/state.json; echo x > $f:s/X/o/`,
		`f=XX$HOME/.komando/state.json; cp /tmp/a $f[3,-1]`,
		`f=~/.komando/state.json; echo x > $~f`,
		`f=~/.komando/state.json; cp /tmp/a $=f`,
		`f=~/.komando/state.json; tee $^f < /tmp/a`,
	}, true)
	checkLines(t, home, home, []string{
		`sed -i 's/a$/b/' notes.txt`,
		`sed -i 's/ *$//' notes.txt`,
		`echo x > "$HOME/out.txt"`,
	}, false)
}

// ${NAME:=VALUE}, ${NAME=VALUE} and zsh's ${NAME::=VALUE} set NAME where
// they stand: the value joins the ones NAME may have.
func TestGuardAssignmentInsideAWordIsFollowed(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		`f=; : ${f:=$HOME/.komando/state.json}; cp /tmp/a "$f"`,
		`f=/tmp/x; : ${f::=$HOME/.komando/state.json}; echo x > $f`,
		`f=/tmp/x; echo ${f=~/.komando/state.json} > /dev/null; echo x > "$f"`,
		`f=/tmp/x; : ${(A)f::=/tmp/y}; echo x > $f`,
	}, true)
	checkLines(t, home, home, []string{
		`: "${OUT:=/tmp/out.txt}"; echo x > "$OUT"`,
	}, false)
}

// A file named with ~- or ~+ (the folders before and now), ~N (the folder
// stack), ~NAME other than the user's own (a zsh named folder, another
// user) or zsh's =NAME (a program in PATH) is unknown.
func TestGuardTildeAndEqualsNamesAreUnknown(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		`cd /tmp; echo x > ~-/state.json`,
		`cp /tmp/a ~+/state.json`,
		`echo x > ~1/state.json`,
		`k=$HOME/.komando; echo x > ~k/state.json`,
		`hash -d k=$HOME/.komando; cp /tmp/a ~k/state.json`,
		`cp /bin/true =komando`,
		`echo x > =komando`,
	}, true)
	checkLines(t, home, home, []string{
		`echo x > ~/notes.txt`,
		`cp a.txt ~/backup.txt`,
		`chmod u=rw,go= notes.txt`,
	}, false)
}

// The file an output option names (-o, --output, -out, wget's -O) is a
// file the program writes, whatever the program is.
func TestGuardOutputOptionNamesAWrittenFile(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		`read f < /tmp/n; curl -o "$f" https://example.com/x`,
		`read f < /tmp/n; go build -o "$f" ./cmd/x`,
		`read f < /tmp/n; wget -O "$f" https://example.com/x`,
		`curl --output=$(cat /tmp/n) https://example.com/x`,
		`openssl rand -out ~/.komando/state.json 16`,
		`go build -o ~/bin/koman?o ./cmd/komando`,
	}, true)
	checkLines(t, home, home, []string{
		`go build -o /tmp/kmd ./cmd/tool`,
		`curl -o /tmp/x.tgz https://example.com/x.tgz`,
		`out=$(mktemp); curl -o "$out" https://example.com/x`,
		`ps -o pid,comm`,
		`komando list -o json`,
	}, false)
}

// After an alias the guard reads (alias, or the word alias in an eval's
// text), the program a command name runs on a later line is not known: its
// arguments are checked as files it writes. The shell reads a line whole
// before it runs it, so on the same line an alias does not count yet. The
// alias's own text is checked as a shell line.
func TestGuardAliasedCommandIsCheckedAsAWriter(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		"alias c='cp /tmp/a'\nread f < /tmp/n; c \"$f\"",
		"eval 'alias c=cp'\nread f < /tmp/n; c /tmp/a \"$f\"",
		"eval alias c=cp\nread f < /tmp/n; c /tmp/a \"$f\"",
		"eval 'x=1; alias c=cp'\nread f < /tmp/n; c /tmp/a \"$f\"",
		`alias w='echo x > ~/.komando/state.json'`,
	}, true)
	// Code the guard does not read (a sourced file, eval "$x") is outside it
	// and can change files itself: the commands after it keep their own check.
	checkLines(t, home, home, []string{
		`alias ll='ls -l'; ll > /tmp/out`,
		`alias ll='ls -l'; read d < /tmp/n; ls "$d"`,
		`source ./env.sh; echo "$NAME" > /tmp/out`,
		"source ./aliases.sh\ncat \"$X\"",
		"eval \"$(cat /tmp/n)\"\n[ -n \"$err\" ] && echo \"$err\"",
		". ./env.sh\necho $OUT",
	}, false)
}

// mktemp and date are proven only when their name runs /usr/bin/mktemp or
// /bin/date: a program of that name earlier in PATH, or one the line
// writes, gives an unknown value.
func TestGuardProofOfMktempAndDateNeedsTheSystemProgram(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		`cp /tmp/evil ~/bin/mktemp; f=$(mktemp); echo x > "$f"`,
		`cp /tmp/evil ./date && PATH=.:$PATH; echo x > "$(date +%s)"`,
		`install -m 755 /tmp/evil /usr/local/bin/mktemp; cp /tmp/a "$(mktemp)"`,
	}, true)
	bin := filepath.Join(home, "bin")
	if err := os.WriteFile(filepath.Join(bin, "mktemp"), []byte("#!/bin/sh\necho x\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	checkLines(t, home, home, []string{
		`f=$(mktemp); echo x > "$f"`,
		`echo x > "$(mktemp)"`,
	}, true)
}

// Only one path proves each program: /usr/bin/mktemp and /bin/date, links
// followed (on Linux /bin is often a link to /usr/bin). A second path is a
// second program to trust.
func TestGuardMktempAndDateAreProvedAtOnePathEach(t *testing.T) {
	want := map[string][]string{"mktemp": {"/usr/bin/mktemp"}, "date": {"/bin/date"}}
	if len(trustedPrograms) != len(want) {
		t.Fatalf("trustedPrograms has %d programs, want %d", len(trustedPrograms), len(want))
	}
	for name, paths := range want {
		if got := trustedPrograms[name]; !slices.Equal(got, paths) {
			t.Errorf("trustedPrograms[%q] = %q, want %q", name, got, paths)
		}
	}
}

// Text in single quotes is literal: $0 and $1 in an awk program or a sed
// script are no shell values. A sed script or an awk program is code, not a
// file name: a value in it names no written file (code is row C534's), and
// sed without -i only reads its files. A file sed -i edits stays checked.
func TestGuardScriptTextNamesNoWrittenFile(t *testing.T) {
	home, repo := guardLineHome(t)
	checkLines(t, home, repo, []string{
		`awk 'NR>=24 && NR<=29 {print index($0,"->")}' notes.md`,
		`awk '/^<<<<<<<|^=======|^>>>>>>>/{print NR": "$0}' notes.md`,
		`awk '{print $1 > "/tmp/out.txt"}' notes.md`,
		`sed -i 's/x$/y/' notes.md`,
		`sed -i 's/a/$b/' notes.md`,
		`sed -i.bak 's/^$1$/x/' notes.md`,
		`echo x > '$HOME-notes.txt'`,
		`read x < /tmp/n; echo x > '/tmp/$x'`,
		`a=$(grep -n x notes.md | cut -d: -f1); sed -n "${a},$((a+5))p" notes.md`,
		`f=$(grep -rln x .); sed -n "$(grep -n y $f | cut -d: -f1),+45p" $f`,
		`read n < /tmp/n; sed -i '' "s/a/$n/" notes.md`,
		`read n < /tmp/n; sed -i -e "s/a/$n/" notes.md`,
		`read n < /tmp/n; awk -v n="$n" '{print > "/tmp/out.txt"}' notes.md`,
		`sed -n '$p' ~/.claude/settings.json`,
	}, false)
	checkLines(t, home, repo, []string{
		`read f < /tmp/n; awk '{print $1}' notes.md > "$f"`,
		`read f < /tmp/n; sed -i 's/x$/y/' "$f"`,
		`read f < /tmp/n; echo x > "$f"'.txt'"$f"`,
		`read f < /tmp/n; sed -i '' "s/a/b/" "$f"`,
		`read f < /tmp/n; sed -i -e "s/a/$f/" $f`,
		`read f < /tmp/n; sed -i "s/a/$f/" notes.md $f`,
	}, true)
}
