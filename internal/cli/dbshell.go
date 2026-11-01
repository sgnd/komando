package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// db shell opens the database's own client for a person at a terminal. Like
// db query it is read-only unless --write; agents use db query instead,
// which returns JSON and classifies every statement.

func dbShellCmd() *cobra.Command {
	var write bool
	c := &cobra.Command{
		Use:   "shell CONN",
		Short: "Open psql, mysql or sqlite3 on a conn (read-only unless --write; for people, not agents)",
		Long: `Opens the database's own interactive client on this computer, connected to
CONN, through its --via path when it has one. The password goes to the client
through its environment. The session is read-only unless --write (protected
conns then need --yes). Agents and scripts use ` + "`komando db query`" + ` instead.

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
	if write {
		if err := guardConns(st, []*store.Conn{c}, driver.Verdict{Risk: driver.RiskWrite}); err != nil {
			return err
		}
	}
	rec := map[string]any{"conns": []string{c.Name}, "write": write}
	fail := func(err error) error {
		rec["error"] = toErr(err).Code
		audit(st, "db.shell", nil, "", false, rec)
		return err
	}

	// reach the server: directly, or through a local port forwarded over --via
	addr := t.Address
	a, err := openAccess(ctx, st, c)
	if err != nil {
		return fail(err)
	}
	defer a.Close()
	if a.Dial != nil && !t.Kind.File {
		local, stop, err := forwardLocal(ctx, a.Dial, t.Address)
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
	rec["client"] = argv[0]
	if g.dryRun {
		audit(st, "db.shell", nil, "", true, rec)
		out.P.Print("db.shell", map[string]any{"conn": c.Name, "client": argv, "write": write, "dry_run": true}, nil)
		return nil
	}
	if _, err := exec.LookPath(argv[0]); err != nil {
		pkg := map[string]string{"psql": "postgresql-client", "mysql": "mysql-client (or mariadb-client)", "sqlite3": "sqlite3"}[argv[0]]
		return fail(out.Errf(out.ExitNotFound, "TOOL_MISSING", "install "+pkg+" on this computer", "%s is not installed here", argv[0]))
	}
	mode := "read-only"
	if write {
		mode = "read-write"
	}
	fmt.Fprintf(os.Stderr, "komando: %s session on %s (%s)\n", argv[0], c.Name, mode)
	p := exec.CommandContext(ctx, argv[0], argv[1:]...)
	p.Env, p.Stdin, p.Stdout, p.Stderr = env, os.Stdin, os.Stdout, os.Stderr
	err = p.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		rec["exit_code"] = ee.ExitCode()
		audit(st, "db.shell", nil, "", false, rec)
		return exitCode(out.ExitRemote)
	}
	if err != nil {
		return fail(out.Errf(out.ExitError, "TOOL_FAILED", "", "%s: %v", argv[0], err))
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
		if host != strings.Split(t.Address, ":")[0] && t.TLS == "true" {
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
