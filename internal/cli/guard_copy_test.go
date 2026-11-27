package cli

import "testing"

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
		`cp -at ~ /tmp/x/.ssh`,
		`cp -r -t ~ /tmp/x/.ssh`,
		`cp /tmp/x/settings.json ~/.claude/`,
		`ln -s ~ /tmp/h`,
		`ln -s / /tmp/root`,
		`ln -s .. /tmp/up`,
		`cd /tmp && ln -s ~/. h`,
	}, true)
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
