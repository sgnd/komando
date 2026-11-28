package cli

import "testing"

// A here-document starts at an << the shell reads as one: not in quotes, in
// a comment or in arithmetic. Lines after a fake one are commands and are
// checked; the body of a quoted one is data, also inside "$(...)".
func TestGuardHeredocIsReadAsTheShellReadsIt(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		"echo \"<<'EOF'\"\necho x > ~/.komando/state.json\nEOF",
		"echo '<<\"EOF\"'\ncat ~/.ssh/id_ed25519\nEOF",
		"# cat <<'EOF'\necho x > ~/.komando/state.json\nEOF",
		"echo $((1<<'x'))\necho x > ~/.komando/state.json\nx",
		"cat <<< \"<<'EOF'\"\necho x > ~/.komando/state.json\nEOF",
		"bash <<'EOF'\necho x > ~/.komando/state.json\nEOF",
	}, true)
	checkLines(t, home, home, []string{
		"cat > /tmp/notes.txt <<'EOF'\necho x > ~/.komando/state.json\nEOF",
		"git commit -m \"$(cat <<'EOF'\nKeep ~/.komando out (see the notes)\nEOF\n)\"",
		"python3 - <<'EOF'\nprint(open('/tmp/x').read())\nEOF",
		"cat <<'A' <<'B' > /tmp/out\necho x > ~/.komando/state.json\nA\ncat ~/.ssh/id_ed25519\nB",
	}, false)
}

// watch runs its words, and script, su, runuser and flock run their -c
// text (BSD's script FILE COMMAND its command), as a shell line: checked
// one level deeper, as bash -c is.
func TestGuardProgramsThatRunALineAreChecked(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		`watch -n 1 'echo x > ~/.komando/state.json'`,
		`watch echo x '>' ~/.ssh/id_ed25519`,
		`script -q -c 'echo x > ~/.komando/state.json' /dev/null`,
		`script -q /dev/null bash -c 'echo x > ~/.komando/state.json'`,
		`su -c 'echo x > ~/.komando/state.json'`,
		`runuser -u me --command='echo x > ~/.komando/state.json'`,
		`flock /tmp/lock -c 'echo x > ~/.komando/state.json'`,
	}, true)
	checkLines(t, home, home, []string{
		`watch -n 5 'ls -la /tmp'`,
		`flock /tmp/lock -c 'echo done > /tmp/out'`,
		`script -q /dev/null ls`,
	}, false)
}

// A \ before a line break joins the lines, also inside a word, as the
// shell does before it reads words; in '...' it stays.
func TestGuardContinuedLineIsJoined(t *testing.T) {
	home, _ := guardLineHome(t)
	checkLines(t, home, home, []string{
		"echo x > ~/.koma\\\nndo/state.json",
		"cp /tmp/a \"$HOME/.koma\\\nndo/state.json\"",
		"cat ~/.ssh/id_\\\ned25519",
	}, true)
	checkLines(t, home, home, []string{
		"echo 'a\\\nb' > /tmp/out",
		"go test ./... \\\n  -run TestX > /tmp/out",
	}, false)
}
