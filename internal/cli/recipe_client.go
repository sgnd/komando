package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/pkg/sftp"

	"github.com/sgnd/komando/internal/cachex"
	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/snippet"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// Client snippets (design 2.5): a built-in whose body is a call on an open
// client, not a text run on a server: SFTP for a host, a read-only SQL
// connection for a database, a cache store, the Kubernetes API for a
// cluster. runClientSnippet is the way to them from `recipe run`: it
// resolves the one entry of the snippet's type, stops by the snippet's
// tier as the replaced command is stopped, opens the entry's client the way
// that command opens it, and hands it to snippet.RunClient, which checks
// every variable first. The client is closed after the call, whatever it
// returns.

// snippetBase is what every type's client carries beside its connection:
// the call and the inventory the body may audit with, and whether the run
// is a dry run (a body that changes something shows its preview then).
type snippetBase struct {
	cl  *call
	st  *store.State
	dry bool
}

// hostClient is the client of a host snippet: the SFTP session of one host.
type hostClient struct {
	snippetBase
	host *store.Host
	ssh  *sshx.Client
	sftp *sftp.Client
}

// dbClient is the client of a database snippet: the conn opened read-only,
// through its --via host when it has one.
type dbClient struct {
	snippetBase
	conn *store.Conn
	db   *sql.DB
}

// cacheClient is the client of a cache snippet.
type cacheClient struct {
	snippetBase
	conn  *store.Conn
	store cachex.Store
}

// clusterClient is the client of a cluster snippet: the Kubernetes API of
// one k8s conn.
type clusterClient struct {
	snippetBase
	conn *store.Conn
	kube *kube.Client
}

// snippetEntry is the one entry a client snippet runs against.
type snippetEntry struct {
	name  string
	conns []*store.Conn // the conn, for a database, cache or cluster
	host  *store.Host   // for a host
	// with opens the entry's client, runs use with it and closes it
	with func(ctx context.Context, use func(snippet.Client) error) error
}

// runClientSnippet runs a client built-in against target.
func runClientSnippet(cl *call, ctx context.Context, b snippet.Builtin, target string, kv map[string]string) error {
	// a bad variable stops the run before any connection is made
	if _, err := snippet.Check(b, kv); err != nil {
		return err
	}
	st, err := loadState()
	if err != nil {
		return err
	}
	e, err := resolveSnippetEntry(cl, st, b, target)
	if err != nil {
		return err
	}
	return runSnippetEntry(cl, ctx, st, b, e, kv)
}

// resolveSnippetEntry finds the one entry of b's type that target names.
// It dials nothing. A target of another type, a Windows host (the SFTP
// snippets have no body for it, N12), a Swarm cluster (the Kubernetes API
// is the only body yet) and a selector of several entries are refused.
func resolveSnippetEntry(cl *call, st *store.State, b snippet.Builtin, target string) (snippetEntry, error) {
	base := snippetBase{cl: cl, st: st, dry: cl.dryRun()}
	switch {
	case b.Type == "host":
		if c := st.Conns[target]; c != nil {
			return snippetEntry{}, snippet.TypeUnsupported(b, target, "conn")
		}
	case b.Type != "cluster": // a cluster may be a Swarm manager: a host, refused below as Swarm
		if h := st.Hosts[target]; h != nil {
			return snippetEntry{}, snippet.TypeUnsupported(b, target, "host")
		}
	}
	switch b.Type {
	case "host":
		h, err := singleHost(cl, st, target)
		if err != nil {
			return snippetEntry{}, err
		}
		if h.Windows() {
			return snippetEntry{}, snippet.Unsupported(b, "windows")
		}
		return snippetEntry{name: h.Name, host: h, with: func(ctx context.Context, use func(snippet.Client) error) error {
			return withClient(cl, ctx, st, h, func(c *sshx.Client) error {
				sc, err := sftpClient(c)
				if err != nil {
					return err
				}
				defer sc.Close()
				return use(&hostClient{snippetBase: base, host: h, ssh: c, sftp: sc})
			})
		}}, nil
	case "database":
		c, err := singleConn(cl, st, target, "db")
		if err != nil {
			return snippetEntry{}, err
		}
		return snippetEntry{name: c.Name, conns: []*store.Conn{c}, with: func(ctx context.Context, use func(snippet.Client) error) error {
			db, closeDB, err := openDB(cl, ctx, st, c, true) // read-only: a write is the database's refusal
			if err != nil {
				return err
			}
			defer closeDB()
			return use(&dbClient{snippetBase: base, conn: c, db: db})
		}}, nil
	case "cache":
		c, err := singleConn(cl, st, target, "cache")
		if err != nil {
			return snippetEntry{}, err
		}
		return snippetEntry{name: c.Name, conns: []*store.Conn{c}, with: func(ctx context.Context, use func(snippet.Client) error) error {
			a, err := openAccess(cl, ctx, st, c)
			if err != nil {
				return err
			}
			defer a.Close()
			timeout := dbTimeout(cl)
			octx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			rc, err := cachex.OpenStore(octx, a.Target, a.Password, a.Dial, timeout)
			if err != nil {
				return err
			}
			defer rc.Close()
			return use(&cacheClient{snippetBase: base, conn: c, store: rc})
		}}, nil
	case "cluster":
		t, err := resolveCluster(cl, st, target)
		if err != nil {
			return snippetEntry{}, err
		}
		if t.conn == nil {
			return snippetEntry{}, snippet.Unsupported(b, "swarm")
		}
		return snippetEntry{name: t.conn.Name, conns: []*store.Conn{t.conn}, with: func(ctx context.Context, use func(snippet.Client) error) error {
			ctx, cancel := kubeDeadline(cl, ctx, st)
			defer cancel()
			k, done, err := kubeClient(cl, ctx, st, t.conn)
			if err != nil {
				return err
			}
			defer done()
			return use(&clusterClient{snippetBase: base, conn: t.conn, kube: k})
		}}, nil
	}
	return snippetEntry{}, fmt.Errorf("snippet %s: no client for the type %q", b.Name, b.Type)
}

// snippetRisk is the driver's risk for a snippet's tier: what GuardConns
// asks by. Read changes nothing; a change is a write; dangerous and above
// is destructive.
func snippetRisk(b snippet.Builtin) driver.Risk {
	switch {
	case b.Tier >= capability.Dangerous:
		return driver.RiskDestructive
	case snippet.Mutating(b):
		return driver.RiskWrite
	}
	return driver.RiskRead
}

// runSnippetEntry runs b against e: the tier stops first (nothing is
// opened for a snippet that is stopped), then the call on the open client,
// then the audit record of a change and the answer.
func runSnippetEntry(cl *call, ctx context.Context, st *store.State, b snippet.Builtin, e snippetEntry, kv map[string]string) error {
	// whatever called, a bad variable stops the run before anything opens
	if _, err := snippet.Check(b, kv); err != nil {
		return err
	}
	risk := snippetRisk(b)
	if e.host != nil && risk > driver.RiskRead {
		// no guard of a host client change is wired yet (fs-write waits on
		// the write rule, Audit Q1): refuse it, so a later built-in cannot
		// reach SFTP without one
		return out.Errf(out.ExitPolicy, "NEEDS_PERSON", "a person runs the command it replaces in their own terminal",
			"snippet %s changes a server over SFTP, which komando does not run as a snippet yet", b.Name)
	}
	if err := snippetTierStop(cl, st, b, e.conns); err != nil {
		audit(cl, st, "snippet.exec", nil, "snippet "+b.Name, false, map[string]any{"conns": connNames(e.conns), "blocked": toErr(err).Code})
		return err
	}
	var res any
	err := e.with(ctx, func(c snippet.Client) error {
		var rerr error
		res, rerr = snippet.RunClient(ctx, b, c, kv)
		return rerr
	})
	if errors.Is(err, errDryRunStopped) && e.host == nil {
		// a dry run stopped at a step only a person can take: the same
		// answer withKube gives
		res, err = map[string]any{"conn": e.name, "dry_run": true}, nil
	}
	if risk > driver.RiskRead {
		rec := map[string]any{"conns": connNames(e.conns), "risk": risk.String(), "snippet": b.Name}
		if err != nil {
			rec["error"] = toErr(err).Code
		}
		audit(cl, st, "snippet.exec", nil, "snippet "+b.Name, err == nil, rec)
	}
	if err != nil {
		return err
	}
	cl.out.Print("snippet.exec", snippet.NewData(b, e.name, res, nil, nil, nil), nil)
	return nil
}

// connNames are the names of conns.
func connNames(conns []*store.Conn) []string {
	names := make([]string, len(conns))
	for i, c := range conns {
		names[i] = c.Name
	}
	return names
}
