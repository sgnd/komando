package cli

import (
	"crypto/rand"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// A conn URL's ?ca=secret:NAME (a private CA, driver/ca.go) holds for the
// dump tools too: pg_dump, pg_restore and mysqldump check the database's
// certificate against that CA, as komando's own connections do. libpq
// refuses an option it does not know, so ca= leaves the URL the tool gets;
// the certificate itself goes to the tool in a file:
//
//   - On a server, the CA follows the password line on the tool script's
//     stdin. The script writes it into a new folder only the login user
//     can open, and a watcher removes the folder once the tool has ended
//     (the script itself ends in exec, so signals reach the tool).
//   - pg_dump and pg_restore read it as sslrootcert= with
//     sslmode=verify-full: the certificate must be signed by that CA and
//     name the server, the same full check komando makes.
//   - mysqldump reads it as --ssl-ca, with tls=true when the URL has no tls=
//     (ca= alone turns TLS on for komando's connections as well).

// toolCABase is the folder on the server that holds the CA's own folder.
var toolCABase = "/tmp"

// toolCA is the conn's CA certificate, readied for one tool run.
type toolCA struct {
	dir   string // the private folder that holds ca.crt
	pem   string // the certificates, as clean PEM (no blank lines)
	local bool   // the folder is on this computer: komando writes and removes it
}

func (ca *toolCA) file() string { return filepath.ToSlash(filepath.Join(ca.dir, "ca.crt")) }

// onServer is what the tool script needs for the CA: the folder to make
// and the stdin lines that fill it, the last one empty. "" without a CA,
// or when the tool runs here.
func (ca *toolCA) onServer() (dir, lines string) {
	if ca == nil || ca.local {
		return "", ""
	}
	return ca.dir, ca.pem + "\n"
}

// remove deletes the folder when it is on this computer (a server's
// folder goes with its watcher).
func (ca *toolCA) remove() {
	if ca != nil && ca.local {
		os.RemoveAll(ca.dir)
	}
}

// toolWithCA readies the conn's ?ca= for running argv on h (nil: here): it
// points the tool at the CA's file and, for mysqldump, asks it for a
// checked TLS connection. Without a ca= nothing changes and the CA is nil.
func toolWithCA(c *store.Conn, h *store.Host, tool dumpTool, argv []string) (dumpTool, []string, *toolCA, error) {
	t, err := driver.Parse(c.URL)
	// tool.dump is nil for the `--version` probe, which connects nowhere
	if err != nil || t.CA == "" || tool.dump == nil || len(argv) == 0 {
		return tool, argv, nil, nil
	}
	certs, err := t.CAPEM()
	if err != nil {
		return tool, nil, nil, err
	}
	ca := &toolCA{pem: certs, dir: toolCABase + "/komando-ca-" + strings.ToLower(rand.Text())}
	if h == nil {
		if ca.dir, err = os.MkdirTemp("", "komando-ca-*"); err != nil {
			return tool, nil, nil, out.Errf(out.ExitError, "FILE_ERROR", "check that the temporary folder is writable", "%v", err)
		}
		ca.local = true
		if err := os.WriteFile(ca.file(), []byte(certs), 0o600); err != nil {
			ca.remove()
			return tool, nil, nil, out.Errf(out.ExitError, "FILE_ERROR", "check that the temporary folder is writable", "%v", err)
		}
	}
	argv = slices.Clone(argv)
	switch t.Kind.Name {
	case "postgres":
		if i := slices.Index(argv, "--dbname"); i >= 0 && i+1 < len(argv) {
			argv[i+1] = libpqCAURL(argv[i+1], ca.file())
		}
	case "mysql":
		argv = slices.Insert(argv, 1, "--ssl-ca="+ca.file())
		if tool.tls == "" {
			tool.tls = "true"
		}
	}
	return tool, argv, ca, nil
}

// libpqCAURL is the conn URL raw for libpq: without komando's own ca=,
// checking the server's certificate fully against the CA in file. Its
// other options stay as written; re-encoding them would turn %20 into +,
// which libpq does not read as a space.
func libpqCAURL(raw, file string) string {
	base, query, _ := strings.Cut(raw, "?")
	var keep []string
	for _, kv := range strings.Split(query, "&") {
		k, _, _ := strings.Cut(kv, "=")
		if name, err := url.QueryUnescape(k); kv == "" || err == nil && (name == "ca" || name == "sslmode" || name == "sslrootcert") {
			continue
		}
		keep = append(keep, kv)
	}
	path := strings.NewReplacer("%2F", "/", "+", "%20").Replace(url.QueryEscape(file))
	return base + "?" + strings.Join(append(keep, "sslmode=verify-full", "sslrootcert="+path), "&")
}

// toolScript is the shell script that runs argv on a server. The first
// stdin line is the password; it goes into the tool's environment only, so
// it is never on a command line (`ps`). With caDir, the lines after it, up
// to an empty one, are the conn's CA certificate (toolWithCA). low adds
// nice and, where the server has it, ionice's idle class, so a dump does
// not slow the server down.
func toolScript(argv []string, passwordEnv, caDir string, low bool) string {
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = sshx.Q(a)
	}
	var b strings.Builder
	fmt.Fprintf(&b, `command -v %s >/dev/null 2>&1 || { echo "komando: %s is not installed" >&2; exit 127; }
IFS= read -r KOMANDO_PW; %s=$KOMANDO_PW; export %s; unset KOMANDO_PW
`, sshx.Q(argv[0]), argv[0], passwordEnv, passwordEnv)
	if caDir != "" {
		// mkdir refuses a path that exists, so nobody else's file or link
		// is trusted; the watcher outlives the shell, whose pid becomes
		// the tool's at exec
		fmt.Fprintf(&b, `KOMANDO_CA=%s
mkdir -m 700 "$KOMANDO_CA" || { echo "komando: cannot make $KOMANDO_CA for the database's CA certificate" >&2; exit 1; }
(trap '' HUP INT TERM; while kill -0 $$ 2>/dev/null; do sleep 1; done; rm -f "$KOMANDO_CA/ca.crt"; rmdir "$KOMANDO_CA") </dev/null >/dev/null 2>&1 &
while IFS= read -r KOMANDO_L && [ -n "$KOMANDO_L" ]; do printf '%%s\n' "$KOMANDO_L"; done >"$KOMANDO_CA/ca.crt"
`, sshx.Q(caDir))
	}
	fmt.Fprintf(&b, "set -- %s\n", strings.Join(quoted, " "))
	if low {
		b.WriteString(`if command -v nice >/dev/null 2>&1; then set -- nice -n 10 "$@"; fi
if command -v ionice >/dev/null 2>&1 && ionice -c3 true >/dev/null 2>&1; then set -- ionice -c3 "$@"; fi
`)
	}
	b.WriteString(`exec "$@"`)
	return b.String()
}
