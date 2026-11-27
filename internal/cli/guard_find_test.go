package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// find's -delete, its -exec family and its -fprint family change files.
// {} is a file under the start folders: unknown when a start folder holds
// komando's data, a key, an agent folder or the program the guard hook
// runs, or when find follows links. The command of -exec is checked as a
// shell line; -execdir runs it in the found file's folder.
func TestGuardFindThatChangesFilesIsChecked(t *testing.T) {
	home, _ := guardLineHome(t)
	t.Setenv("PATH", filepath.Join(home, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	checkLines(t, home, home, []string{
		`find ~ -name state.json -delete`,
		`find ~/.komando -name '*.json' -delete`,
		`find . -name settings.json -delete`,
		`find -L /tmp -name x -delete`,
		`find /tmp -follow -name x -delete`,
		`find ~/bin -name 'koma*' -exec cp /bin/true {} \;`,
		`find ~/.claude -name '*.json' -exec rm {} +`,
		`find /tmp -maxdepth 0 -exec sh -c 'echo x > ~/.komando/state.json' \;`,
		`read f < /tmp/n; find /tmp -name x -exec cp /tmp/a "$f" \;`,
		`find ~/Documents -execdir cp /tmp/a ../.komando/state.json \;`,
		`read f < /tmp/n; find /tmp -fprint "$f"`,
		`find "$(cat /tmp/d)" -name x -delete`,
	}, true)
}

// find in a project folder stays allowed, also when it deletes or runs a
// command on what it finds.
func TestGuardFindInAProjectStaysAllowed(t *testing.T) {
	home, repo := guardLineHome(t)
	checkLines(t, home, repo, []string{
		`find . -name '*.o' -delete`,
		`find . -name '*.o' -exec rm {} +`,
		`find /tmp/build -type f -exec chmod 644 {} \;`,
		`find . -name '*.go' -exec gofmt -l {} +`,
		`find . -type f -name '*.tmp' -execdir rm {} \;`,
		`find . -name '*.go' -exec grep -l foo {} +`,
		`find . -name '*.go' > /tmp/files`,
	}, false)
}
