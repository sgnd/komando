package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// db shell opens the database's own client for a person at a terminal. Like
// db query it starts read-only unless --write, but inside the client a
// person can switch that off, so it guards against accidents only; a
// protected conn needs --yes for any shell. Agents use db query instead,
// which returns JSON and classifies every statement.

func dbShellCmd() *cobra.Command {
	var write bool
	c := &cobra.Command{
		Use:   "shell CONN",
		Short: "Open psql, mysql or sqlite3 on a conn (read-only unless --write; for people, not agents)",
		Long: `Opens the database's own interactive client on this computer, connected to
CONN, through its --via path when it has one. The password goes to the client
through its environment. The session starts read-only unless --write; that
guards against accidents, but the client can switch it off, so a protected
conn needs --yes for any shell. Agents and scripts use ` + "`komando db query`" + `
instead.

Needs the client installed here: psql (postgresql-client), mysql
(mysql-client or mariadb-client) or sqlite3.`,
		Example: `  komando db shell prod-db
  komando db shell staging-db --write`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDBShell(cmd.Context(), args[0], write)
		},
	}
	c.Flags().BoolVar(&write, "write", false, "allow changes in this session")
	return c
}

func runDBShell(ctx context.Context, connExpr string, write bool) error {
	if !interactive() {
		return out.Errf(out.ExitUsage, "NEEDS_TERMINAL",
			"agents and scripts use `komando db query CONN \"SQL\"`, which returns JSON and checks every statement",
			"db shell is interactive and needs a person at a terminal")
	}
	st, err := loadState()
	if err != nil {
		return err
	}
	c, err := singleConn(st, connExpr, "db")
	if err != nil {
		return err
	}
	t, err := driver.Parse(c.URL)
	if err != nil {
		return err
	}
	// a person can turn read-only off inside the client, so any shell on a
	// protected conn is treated like a change
	if write || protectedConn(st, c) {
		if err := guardConns(st, []*store.Conn{c}, driver.Verdict{Risk: driver.RiskWrite}); err != nil {
			return err
		}
	}
	client := map[string]string{"postgres": "psql", "mysql": "mysql", "sqlite": "sqlite3"}[t.Kind.Name]
	rec := map[string]any{"conns": []string{c.Name}, "write": write, "client": client}
	if g.dryRun { // before any VPN, SSH or database contact
		audit(st, "db.shell", nil, "", true, rec)
		out.P.Print("db.shell", map[string]any{"conn": c.Name, "client": client, "via": c.Via, "write": write, "dry_run": true}, nil)
		return nil
	}
	fail := func(err error) error {
		rec["error"] = toErr(err).Code
		audit(st, "db.shell", nil, "", false, rec)
		return err
	}

	// check for the client before any SSH or VPN contact
	if _, err := exec.LookPath(client); err != nil {
		return fail(out.Errf(out.ExitNotFound, "TOOL_MISSING", clientInstallHint(runtime.GOOS, linuxDistro(), client, c.Name),
			"%s is not installed on this computer", client))
	}

	// reach the server: directly, or through a local port forwarded over --via
	addr := t.Address
	a, err := openAccess(ctx, st, c)
	if err != nil {
		return fail(err)
	}
	defer a.Close()
	if a.Dial != nil && !t.Kind.File {
		// Ctrl-C belongs to the client (it cancels a query); the forward must
		// outlive komando's own interrupt handling
		local, stop, err := forwardLocal(context.WithoutCancel(ctx), a.Dial, t.Address)
		if err != nil {
			return fail(err)
		}
		defer stop()
		addr = local
	}
	argv, env, err := shellCommand(c, t, a.Password, addr, write)
	if err != nil {
		return fail(err)
	}
	mode := "read-only"
	if write {
		mode = "read-write"
	}
	fmt.Fprintf(os.Stderr, "komando: %s session on %s (%s)\n", argv[0], c.Name, mode)
	p := exec.Command(argv[0], argv[1:]...) // not tied to ctx: Ctrl-C must not kill the session
	p.Env, p.Stdin, p.Stdout, p.Stderr = env, os.Stdin, os.Stdout, os.Stderr
	err = p.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		rec["exit_code"] = ee.ExitCode()
		audit(st, "db.shell", nil, "", false, rec)
		return exitCode(out.ExitRemote)
	}
	if err != nil {
		return fail(out.Errf(out.ExitError, "TOOL_FAILED", "check that "+argv[0]+" is installed: `komando doctor`", "%s: %v", argv[0], err))
	}
	audit(st, "db.shell", nil, "", true, rec)
	return nil
}

// shellCommand builds the client's argv and environment. addr is where to
// connect: the server itself, or the local end of a --via forward.
func shellCommand(c *store.Conn, t driver.Target, password, addr string, write bool) ([]string, []string, error) {
	env := childEnv()
	switch t.Kind.Name {
	case "sqlite":
		argv := []string{"sqlite3"}
		if !write {
			argv = append(argv, "-readonly")
		}
		return append(argv, expandHome(t.Path)), env, nil

	case "postgres":
		host, _, _ := net.SplitHostPort(t.Address)
		ahost, aport, _ := net.SplitHostPort(addr)
		env = append(env, "PGHOST="+host, "PGPORT="+aport, "PGUSER="+t.User, "PGDATABASE="+t.Database,
			"PGPASSWORD="+password, "PGAPPNAME=komando/"+actor())
		if ahost != host {
			// through a forward: connect to the local port, but keep the real
			// host name so TLS still verifies the server's certificate
			env = append(env, "PGHOSTADDR="+ahost)
		}
		if u, err := url.Parse(c.URL); err == nil {
			if m := u.Query().Get("sslmode"); m != "" {
				env = append(env, "PGSSLMODE="+m)
			}
		}
		if !write {
			env = append(env, "PGOPTIONS=-c default_transaction_read_only=on")
		}
		return []string{"psql"}, env, nil

	case "mysql":
		host, port, _ := net.SplitHostPort(addr)
		server, _, _ := net.SplitHostPort(t.Address)
		if host != server && t.TLS == "true" {
			return nil, nil, out.Errf(out.ExitUsage, "TLS_THROUGH_FORWARD",
				"use `komando db query` (it verifies the certificate through --via), or reach the server without --via",
				"the mysql client cannot verify the server certificate's name through a local forward")
		}
		argv := []string{"mysql", "--host", host, "--port", port}
		if t.User != "" {
			argv = append(argv, "--user", t.User)
		}
		if t.TLS != "" {
			version, _ := exec.Command("mysql", "--version").Output()
			flags := mysqlTLSFlags(t.TLS, string(version))
			if flags == nil {
				return nil, nil, out.Usage("tls=%s in the conn URL cannot be passed to mysql; use true, skip-verify, preferred or false", t.TLS)
			}
			argv = append(argv, flags...)
		}
		if !write {
			argv = append(argv, "--init-command=SET SESSION TRANSACTION READ ONLY")
		}
		if t.Database != "" {
			argv = append(argv, t.Database)
		}
		return argv, append(env, "MYSQL_PWD="+password), nil
	}
	return nil, nil, out.Usage("%s conns have no shell", t.Kind.Name)
}

// clientInstallHint says how to install a database client (psql, mysql,
// sqlite3) on this computer. goos is runtime.GOOS; distro is ID and ID_LIKE
// from /etc/os-release on Linux ("ubuntu debian").
func clientInstallHint(goos, distro, client, conn string) string {
	pkgs := map[string]map[string]string{
		"darwin": {
			"psql":    "brew install libpq, then brew link --force libpq (or add $(brew --prefix libpq)/bin to PATH)",
			"mysql":   "brew install mysql-client, then add $(brew --prefix mysql-client)/bin to PATH",
			"sqlite3": "brew install sqlite",
		},
		"debian": {"psql": "sudo apt install postgresql-client", "mysql": "sudo apt install default-mysql-client", "sqlite3": "sudo apt install sqlite3"},
		"fedora": {"psql": "sudo dnf install postgresql", "mysql": "sudo dnf install mysql", "sqlite3": "sudo dnf install sqlite"},
		"alpine": {"psql": "sudo apk add postgresql-client", "mysql": "sudo apk add mysql-client", "sqlite3": "sudo apk add sqlite"},
		"arch":   {"psql": "sudo pacman -S postgresql-libs", "mysql": "sudo pacman -S mariadb-clients", "sqlite3": "sudo pacman -S sqlite"},
	}
	family := goos
	if goos == "linux" {
		family = ""
		for _, id := range strings.Fields(distro) {
			switch id {
			case "debian", "ubuntu":
				family = "debian"
			case "fedora", "rhel", "centos", "rocky", "almalinux":
				family = "fedora"
			case "alpine", "arch":
				family = id
			}
			if family != "" {
				break
			}
		}
	}
	how := pkgs[family][client]
	if how == "" {
		what := map[string]string{"psql": "the PostgreSQL client (psql)", "mysql": "the MySQL or MariaDB client (mysql)", "sqlite3": "sqlite3"}[client]
		how = "install " + what + " with your package manager"
	}
	return how + "; or run SQL now with `komando db query " + conn + " 'select 1'`"
}

// linuxDistro is ID and ID_LIKE from /etc/os-release, or "" elsewhere.
func linuxDistro() string {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	var ids []string
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && (k == "ID" || k == "ID_LIKE") {
			ids = append(ids, strings.Fields(strings.Trim(v, `"'`))...)
		}
	}
	return strings.Join(ids, " ")
}

// childEnv is this process's environment without komando's own secrets.
func childEnv() []string {
	var env []string
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "KOMANDO_VAULT_PASS=") {
			continue
		}
		env = append(env, e)
	}
	return env
}
