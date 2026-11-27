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
