package cli

import (
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/sgnd/komando/internal/dbx"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// Where a conn's login goes. A URL says more than its address: Postgres
// takes host=, port=, hostaddr= and service= from its settings, Redis
// sentinels=, MongoDB more seed hosts, RabbitMQ management=, and many
// kinds a CA, a TLS mode or a client certificate. So the place a conn's
// password goes is every address its driver logs in at, read as the
// driver reads the URL (connPlaces), plus every setting of the URL except
// the few that move nothing (connURLSettings). Any other change of the URL
// is a new place: an AI agent's gets SECRET_DESTINATION for a conn with a
// stored password, and it fails closed for a setting komando does not
// know.

// connSafeSettings are URL settings that change neither where a login goes
// nor how the server is checked.
var connSafeSettings = map[string]bool{
	"application_name": true, "connect_timeout": true, "timeout": true, "dial_timeout": true,
	"read_timeout": true, "write_timeout": true, "statement_timeout": true, "lock_timeout": true,
}

// connURLSettings are the URL's settings that are part of where the login
// goes, as sorted key=value pairs.
func connURLSettings(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	var set []string
	for k, vs := range u.Query() {
		if connSafeSettings[strings.ToLower(k)] {
			continue
		}
		for _, v := range vs {
			set = append(set, k+"="+v)
		}
	}
	sort.Strings(set)
	return set
}

// connPlaces are the addresses c's driver logs in at: the URL's hosts
// (every one it lists), Kafka and NATS brokers, Redis sentinels, the
// RabbitMQ management API, ?resolve=, and for Postgres every host pgx
// reads from the URL (fallbacks included). The user is not a place: the
// login goes to the same servers.
func connPlaces(c *store.Conn) []string {
	t, err := driver.Parse(c.URL)
	if err != nil {
		return []string{c.URL}
	}
	if t.Kind.File {
		return []string{t.Path}
	}
	places := []string{t.Address}
	if u, err := url.Parse(c.URL); err == nil {
		for _, h := range strings.Split(u.Host, ",") { // mongodb://a,b/ and the like
			if h = strings.TrimSpace(h); h != "" && !slices.Contains(places, h) && !slices.ContainsFunc(places, func(p string) bool { return sameHost(p, h) }) {
				places = append(places, h)
			}
		}
	}
	places = append(places, t.Brokers...)
	places = append(places, t.Sentinels...)
	if t.Management != "" {
		places = append(places, t.Management+" (management API)")
	}
	if t.Resolve != "" && t.Resolve != t.Address {
		places = append(places, t.Resolve+" (resolve)")
	}
	if t.Kind.Name == "postgres" {
		places = append(places, dbx.PostgresTargets(c.URL)...)
	}
	var out []string
	for _, p := range places {
		if p != "" && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// sameHost: a is b with the kind's default port added.
func sameHost(a, b string) bool {
	ha, _, err := net.SplitHostPort(a)
	return err == nil && ha == b
}

// guardConnFile refuses a file conn (SQLite) that is komando's own data,
// its links included: the store holds the inventory and the sealed
// secrets, and only komando's commands read it. For an AI agent it also
// refuses a database where its logins live (dbFileOffLimits): a SQLite
// conn reads, copies and deletes rows, so it is a way to read those files.
// It runs at add and edit, and again whenever the conn is opened.
func guardConnFile(cl *call, c *store.Conn) error {
	t, err := driver.Parse(c.URL)
	if err != nil || !t.Kind.File {
		return nil
	}
	return guardDBFile(cl, dbx.SQLitePath(t), "a database for a conn")
}

// guardDBFile is guardConnFile for a database file path p on this
// computer (a conn's, or a db dump's --to); what says what p would be.
func guardDBFile(cl *call, p, what string) error {
	if localSecret(cl, p) == komandoData {
		return out.Errf(out.ExitPolicy, "SENSITIVE_FILE",
			"use a database of your own; komando's data is read only through komando's commands (`komando list`, `komando secret list`)",
			"%s is %s, not %s", p, komandoData, what).NoFlag()
	}
	if !cl.isAgent() {
		return nil
	}
	if why := dbFileOffLimits(cl, p); why != "" {
		return out.Errf(out.ExitPolicy, "SENSITIVE_FILE",
			"use a database outside the folders that hold logins, or ask the user to run it in their own terminal",
			"%s is %s; komando does not use it as %s for an AI agent", p, why, what).NoFlag()
	}
	return nil
}

// loginDirs are the folders where SSH and the cloud and container tools
// keep their logins, some in SQLite databases (gcloud's credentials.db).
var loginDirs = []string{".ssh", ".aws", ".config/gcloud", ".azure", ".kube", ".docker", ".gnupg", ".password-store"}

// dbFileOffLimits says why an AI agent may not use p as a database file,
// or "": what the agent guard keeps from it (localSecret), or a path in a
// login folder, through links too.
func dbFileOffLimits(cl *call, p string) string {
	if why := localSecret(cl, p); why != "" {
		return why
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	abs, err := filepath.Abs(expandHome(p))
	if err != nil {
		return ""
	}
	for _, q := range []string{abs, realPath(abs), realPath(filepath.Dir(abs))} {
		for _, d := range loginDirs {
			if pathIn(q, filepath.Join(home, d)) || pathIn(q, realPath(filepath.Join(home, d))) {
				return "in " + filepath.Join("~", d) + ", where logins are kept"
			}
		}
	}
	return ""
}

// toolEnv is env without the variables the dump tools read as defaults
// for what the URL leaves out (libpq's PG*, the MySQL client's MYSQL_*):
// from the environment an AI agent's process could move the login
// (PGHOSTADDR, MYSQL_HOST) or the CA the tool trusts.
func toolEnv(env []string) []string {
	var keep []string
	for _, kv := range env {
		if !strings.HasPrefix(kv, "PG") && !strings.HasPrefix(kv, "MYSQL") {
			keep = append(keep, kv)
		}
	}
	return keep
}

// dumpTarget checks db dump's conn and its --to file: the conn's file
// (guardConnFile), a file an agent may not write there (guardDBFile), and
// one that exists already (backups are never overwritten).
func dumpTarget(cl *call, c *store.Conn, to string) error {
	if err := guardConnFile(cl, c); err != nil {
		return err
	}
	if err := guardDBFile(cl, to, "a place for a backup"); err != nil {
		return err
	}
	if _, err := os.Stat(to); err == nil {
		return out.Errf(out.ExitConflict, "FILE_EXISTS", "pick a new file name; backups are never overwritten", "%s already exists", to)
	}
	return nil
}

// guardBackupFile checks a backup db restore reads: what the agent guard
// keeps from an agent (guardLocalRead), and a login folder (guardDBFile).
func guardBackupFile(cl *call, path string) error {
	if err := guardLocalRead(cl, path); err != nil {
		return err
	}
	return guardDBFile(cl, path, "a backup to load")
}
