package cli

import (
	"bytes"
	"context"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// The dump tools connect to the database themselves, from the server they
// run on, so the conn URL's TLS settings go to them in each client's own
// terms (docs/features/databases.md):
//
//   - mysqldump: tls= becomes its --ssl-mode (MySQL) or --ssl flags
//     (MariaDB), see mysqlTLSFlags.
//   - pg_dump and pg_restore (libpq) read the URL itself. With sslmode
//     verify-full or verify-ca, libpq checks the server's certificate
//     against ~/.postgresql/root.crt on that server, where komando checks it
//     against the system's CAs. libpq 16 and newer do the same with
//     sslrootcert=system, so komando adds that when the URL names no CA of
//     its own. An older libpq needs the CA in that file.

// toolTLSArgs passes the conn URL's TLS settings on to the tool's command
// line argv, asking the tool for its version where that matters.
func toolTLSArgs(cl *call, ctx context.Context, st *store.State, c *store.Conn, h *store.Host, tool dumpTool, argv []string) ([]string, error) {
	version := func() (string, error) {
		var b bytes.Buffer
		err := runTool(cl, ctx, st, c, h, dumpTool{passwordEnv: tool.passwordEnv, pkg: tool.pkg}, []string{argv[0], "--version"}, nil, &b, false)
		return b.String(), err
	}
	switch {
	case tool.tls != "": // the URL asks for TLS: pass it on in this client's own flags
		v, err := version()
		if err != nil {
			return nil, err
		}
		flags := mysqlTLSFlags(tool.tls, v)
		if flags == nil {
			return nil, out.Usage("tls=%s in the conn URL cannot be passed to %s; use true, skip-verify, preferred or false", tool.tls, argv[0])
		}
		return append(append([]string{argv[0]}, flags...), argv[1:]...), nil
	case tool.libpq:
		i := slices.Index(argv, "--dbname")
		if i < 0 || i+1 >= len(argv) || !libpqNeedsRoots(argv[i+1]) {
			return argv, nil
		}
		v, err := version()
		if err != nil {
			return nil, err
		}
		if libpqMajor(v) < 16 {
			return argv, nil // its CA comes from ~/.postgresql/root.crt (rootCertHint)
		}
		argv = slices.Clone(argv)
		argv[i+1] += map[bool]string{true: "&", false: "?"}[strings.Contains(argv[i+1], "?")] + "sslrootcert=system"
	}
	return argv, nil
}

// libpqNeedsRoots: libpq checks the server's certificate for the conn URL
// raw, and the URL names no CA (sslrootcert=, or komando's own ca=).
func libpqNeedsRoots(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	q := u.Query()
	m := q.Get("sslmode")
	return (m == "verify-full" || m == "verify-ca") && !q.Has("sslrootcert") && !q.Has("ca")
}

// pgToolVersion reads "pg_dump (PostgreSQL) 16.4 (Ubuntu ...)".
var pgToolVersion = regexp.MustCompile(`\(PostgreSQL\) ([0-9]+)`)

// libpqMajor is the major version in a PostgreSQL tool's --version line,
// the libpq it comes with; 0 when it cannot be read.
func libpqMajor(version string) int {
	m := pgToolVersion.FindStringSubmatch(version)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// rootCertHint explains libpq's "root certificate file ... does not exist":
// the tool checks the server's certificate, but has no CA to check it
// against where it runs. "" for other failures.
func rootCertHint(stderr, tool, where string) string {
	if !strings.Contains(stderr, "root certificate file") {
		return ""
	}
	return tool + " on " + where + " checks the database's certificate (sslmode=verify-full), but has no CA to check it against: install postgresql-client 16 or newer there " +
		"(komando then passes sslrootcert=system, the system's CAs), or put the CA certificate in ~/.postgresql/root.crt of the user komando logs in as on " + where +
		"; or reach the database --via that server and connect without TLS through it"
}

// mysqlTLSFlags maps the URL's tls= setting to the client's flags. MySQL
// and MariaDB clients spell them differently; version is `--version` output.
func mysqlTLSFlags(tls, version string) []string {
	if tls == "" {
		return nil
	}
	if strings.Contains(version, "MariaDB") {
		return map[string][]string{
			"true":        {"--ssl", "--ssl-verify-server-cert"},
			"skip-verify": {"--ssl", "--skip-ssl-verify-server-cert"},
			"preferred":   {"--ssl"},
			"false":       {"--skip-ssl"},
		}[tls]
	}
	return map[string][]string{
		"true":        {"--ssl-mode=VERIFY_IDENTITY"},
		"skip-verify": {"--ssl-mode=REQUIRED"},
		"preferred":   {"--ssl-mode=PREFERRED"},
		"false":       {"--ssl-mode=DISABLED"},
	}[tls]
}
