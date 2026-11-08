package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/sgnd/komando/internal/dbx"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// MongoDB conns are `db` conns: `db query` takes a command document
// instead of SQL, and `db schema` and `db info` describe the database. The
// SQL-only commands (dump, activity, users, ...) say so.

// mongoConn is the conn expr picks, when it is a MongoDB conn.
func mongoConn(expr string) (*store.State, *store.Conn, bool) {
	st, err := loadState()
	if err != nil {
		return nil, nil, false
	}
	c, err := singleConn(st, expr, "db")
	if err != nil || c.Kind != "mongodb" {
		return nil, nil, false
	}
	return st, c, true
}

func openMongo(ctx context.Context, st *store.State, c *store.Conn) (*dbx.Mongo, func(), error) {
	a, err := openAccess(ctx, st, c)
	if err != nil {
		return nil, nil, err
	}
	m, err := dbx.OpenMongo(ctx, c.URL, a.Target, a.Password, a.Dial, "komando/"+actor(), max(connTimeout(c), sshOpts(st).ConnectTimeout))
	if err != nil {
		a.Close()
		return nil, nil, viaTimeout(c, err)
	}
	return m, func() { m.Close(); a.Close() }, nil
}

type mongoQueryData struct {
	Conn     string `json:"conn"`
	Database string `json:"database"`
	Command  string `json:"command"`
	Risk     string `json:"risk"`
	Write    bool   `json:"write"`
	DryRun   bool   `json:"dry_run,omitempty"`
	Note     string `json:"note,omitempty"`
	*dbx.MongoResult
}

// Text is one document per line, as mongoexport writes them.
func (d mongoQueryData) Text() string {
	var b strings.Builder
	if d.Note != "" {
		b.WriteString(d.Note + "\n")
	}
	if d.MongoResult == nil {
		return b.String()
	}
	for _, doc := range d.Documents {
		j, _ := json.Marshal(doc)
		b.Write(append(j, '\n'))
	}
	if d.Reply != nil {
		j, _ := json.MarshalIndent(d.Reply, "", "  ")
		b.Write(append(j, '\n'))
	}
	if d.Truncated != "" {
		b.WriteString("(cut at " + d.Truncated + ": raise --limit or --max-output)\n")
	}
	return b.String()
}

// runMongoQuery rates, guards, sends and audits one command document.
func runMongoQuery(ctx context.Context, name string, st *store.State, c *store.Conn, text string, f dbFlags) error {
	switch {
	case f.csv || f.tsv:
		return out.Usage("MongoDB documents have no fixed columns: use -o json, or -o text for one document per line")
	case len(f.args) > 0:
		return out.Usage("--arg fills SQL placeholders; write the values into the MongoDB command document")
	}
	cmd, db, err := dbx.ParseMongoCommand(text)
	if err != nil {
		return err
	}
	v := dbx.ClassifyMongo(cmd)
	rec := map[string]any{"conns": []string{c.Name}, "risk": v.Risk.String(), "write": f.write, "mongo_command": cmd[0].Key}
	switch st.Settings.AuditSQL { // the same setting keeps command text out of the log
	case "hash":
		sum := sha256.Sum256([]byte(text))
		rec["mongo_sha256"] = hex.EncodeToString(sum[:])
	case "off":
	default:
		if v.RuleIDs == nil || !strings.Contains(strings.Join(v.RuleIDs, ","), "privileges") {
			rec["mongo"] = strings.TrimSpace(text) // a user's password (privileges) is never kept
		}
	}
	fail := func(err error) error {
		rec["error"] = toErr(err).Code
		audit(st, name, nil, "", false, rec)
		return err
	}
	if !f.write && v.Risk > driver.RiskRead {
		e := out.Errf(out.ExitPolicy, "WRITE_REQUIRES_FLAG", "this command may change data; re-run with --write (try --write --dry-run first)",
			"%s needs --write", cmd[0].Key)
		if len(v.RuleIDs) > 0 {
			e.Message += " and --allow-dangerous: " + strings.Join(v.Reasons, "; ")
			e.Hint = "this command " + strings.Join(v.Reasons, "; ") + ": only if that is intended, confirm with the user and re-run with --write --allow-dangerous"
		}
		return fail(e)
	}
	data := mongoQueryData{Conn: c.Name, Database: firstNonEmpty(db, mongoDB(c)), Command: cmd[0].Key, Risk: v.Risk.String(), Write: f.write, DryRun: g.dryRun}
	if f.write {
		v.Risk = max(v.Risk, driver.RiskWrite)
		if err := guardConns(st, []*store.Conn{c}, v); err != nil {
			return fail(err)
		}
		if g.dryRun { // MongoDB cannot roll back a command outside a transaction
			data.Note = "dry run: nothing was sent (MongoDB cannot roll a write back); the command was rated " + v.Risk.String()
			audit(st, name, nil, "", true, rec)
			out.P.Print(name, data, nil)
			return nil
		}
	}
	m, closeM, err := openMongo(ctx, st, c)
	if err != nil {
		return fail(err)
	}
	defer closeM()
	res, err := dbx.RunMongo(ctx, m, db, cmd, f.limit, maxOutput(st))
	if err != nil {
		return fail(err)
	}
	audit(st, name, nil, "", true, rec)
	data.MongoResult = res
	out.P.Print(name, data, nil)
	return nil
}

func mongoDB(c *store.Conn) string {
	if t, err := driver.Parse(c.URL); err == nil && t.Database != "" {
		return t.Database
	}
	return "admin"
}

type mongoSchemaData struct {
	Conn        string                `json:"conn"`
	Database    string                `json:"database"`
	Collections []dbx.MongoCollection `json:"collections"`
}

func runMongoSchema(ctx context.Context, st *store.State, c *store.Conn, names []string) error {
	m, closeM, err := openMongo(ctx, st, c)
	if err != nil {
		return err
	}
	defer closeM()
	cols, err := dbx.MongoSchema(ctx, m, names)
	audit(st, "db.schema", nil, "", err == nil, map[string]any{"conns": []string{c.Name}})
	if err != nil {
		return err
	}
	out.P.Print("db.schema", mongoSchemaData{Conn: c.Name, Database: m.DB, Collections: cols}, nil)
	return nil
}

func runMongoInfo(ctx context.Context, st *store.State, c *store.Conn) error {
	m, closeM, err := openMongo(ctx, st, c)
	if err != nil {
		return err
	}
	defer closeM()
	res, err := dbx.MongoInfo(ctx, m)
	if err != nil {
		return err
	}
	res["conn"], res["kind"] = c.Name, c.Kind
	out.P.Print("db.info", res, nil)
	return nil
}

// mongoLogin is `conn test`'s login check for a MongoDB conn, on the path
// the test already opened.
func mongoLogin(ctx context.Context, c *store.Conn, a *access, r *connTestResult) error {
	m, err := dbx.OpenMongo(ctx, c.URL, a.Target, a.Password, a.Dial, "komando/"+actor(), connTimeout(c))
	if err != nil {
		return viaTimeout(c, err)
	}
	defer m.Close()
	r.Version, r.Check = dbx.MongoVersion(ctx, m), "login"
	return nil
}

// noDumpTool is db dump and restore on a kind they do not handle.
func noDumpTool(t driver.Target) error {
	if t.Kind.Name == "mongodb" {
		return out.Errf(out.ExitUsage, "NOT_SUPPORTED", "run mongodump on a server that reaches the database, with `komando exec` (or a `komando job` for a big one)",
			"db dump and restore are for SQL databases, not MongoDB")
	}
	return out.Usage("%s conns have no dump tool", t.Kind.Name)
}
