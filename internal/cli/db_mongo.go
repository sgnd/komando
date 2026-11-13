package cli

import (
	"cmp"
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
// instead of SQL, `db schema` and `db info` describe the database, `db
// explain` shows a read's plan and `db activity` what runs now. The
// SQL-only commands (dump, sizes, users, ...) say so.

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
	case f.table != "":
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
		e := out.Errf(out.ExitPolicy, "WRITE_REQUIRES_FLAG", "this command may change data; run it again with --write (try --write --dry-run first)",
			"%s needs --write", cmd[0].Key)
		if len(v.RuleIDs) > 0 {
			e.Message += " and --allow-dangerous: " + strings.Join(v.Reasons, "; ")
			e.Hint = "this command " + strings.Join(v.Reasons, "; ") + ": only if that is intended, confirm with the user and run it again with --write --allow-dangerous"
		}
		return fail(e)
	}
	data := mongoQueryData{Conn: c.Name, Database: cmp.Or(db, mongoDB(c)), Command: cmd[0].Key, Risk: v.Risk.String(), Write: f.write, DryRun: g.dryRun}
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

// mongoExplainData is db explain's answer for MongoDB: the plan document.
type mongoExplainData struct {
	Conn     string `json:"conn"`
	Database string `json:"database"`
	Command  string `json:"command"`
	Plan     any    `json:"plan"`
}

func (d mongoExplainData) Text() string {
	b, _ := json.MarshalIndent(d.Plan, "", "  ")
	return string(b) + "\n"
}

// runMongoExplain asks MongoDB for the plan of a read command (find,
// aggregate, count, distinct); --analyze runs it and adds what it did
// (executionStats). A command that writes is refused: explain would not
// show its plan without running parts of it.
func runMongoExplain(ctx context.Context, st *store.State, c *store.Conn, text string, analyze bool) error {
	cmd, db, err := dbx.ParseMongoCommand(text)
	if err != nil {
		return err
	}
	if v := dbx.ClassifyMongo(cmd); v.Risk > driver.RiskRead {
		return out.Usage("db explain shows the plan of a read (find, aggregate, count, distinct); %s writes", cmd[0].Key)
	}
	m, closeM, err := openMongo(ctx, st, c)
	if err != nil {
		return err
	}
	defer closeM()
	plan, err := dbx.MongoExplain(ctx, m, db, cmd, analyze)
	audit(st, "db.explain", nil, "", err == nil, map[string]any{"conns": []string{c.Name}, "mongo_command": cmd[0].Key})
	if err != nil {
		return err
	}
	out.P.Print("db.explain", mongoExplainData{Conn: c.Name, Database: cmp.Or(db, m.DB), Command: cmd[0].Key, Plan: plan}, nil)
	return nil
}

// runMongoActivity is db activity for MongoDB (currentOp).
func runMongoActivity(ctx context.Context, st *store.State, c *store.Conn, all bool, limit int) error {
	m, closeM, err := openMongo(ctx, st, c)
	if err != nil {
		return err
	}
	defer closeM()
	rows, err := dbx.MongoActivity(ctx, m, all)
	if err != nil {
		return err
	}
	rows = cutRows(rows, limit)
	out.P.Print("db.activity", activityData{Conn: c.Name, Count: len(rows), Sessions: rows}, nil)
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
	if t.Kind.Name == "oracle" {
		return out.Errf(out.ExitUsage, "NOT_SUPPORTED",
			"Oracle backs up with Data Pump (expdp, impdp) or RMAN, which run on the database server and write there: run them with `komando exec` (or a `komando job` for a big one), then fetch the file with `komando download`",
			"db dump and restore are not available for Oracle")
	}
	if t.Kind.Name == "clickhouse" {
		return out.Errf(out.ExitUsage, "NOT_SUPPORTED",
			"ClickHouse backs up with its own BACKUP TABLE or DATABASE ... TO Disk('backups', 'name.zip') (or S3), which the server writes itself: run it with `komando db query CONN --write` (it needs --allow-dangerous, so ask the user first); for a few rows, `komando db query CONN -o csv` is a copy on this computer",
			"db dump and restore are not available for ClickHouse")
	}
	if t.Kind.Name == "snowflake" {
		return out.Errf(out.ExitUsage, "NOT_SUPPORTED",
			"Snowflake unloads tables itself: COPY INTO @STAGE FROM TABLE writes files to a stage (run it with `komando db query CONN --write`; it needs --allow-dangerous, so ask the user first), and Time Travel or CLONE keeps a copy inside Snowflake; for a few rows, `komando db query CONN -o csv` is a copy on this computer",
			"db dump and restore are not available for Snowflake")
	}
	if t.Kind.Name == "bigquery" {
		return out.Errf(out.ExitUsage, "NOT_SUPPORTED",
			"BigQuery exports tables itself: EXPORT DATA OPTIONS (uri = 'gs://BUCKET/PATH/*.parquet', format = 'PARQUET') AS SELECT ... writes files to Cloud Storage (run it with `komando db query CONN --write`; it needs --allow-dangerous, so ask the user first), then `komando storage` fetches them; table snapshots and time travel keep a copy inside BigQuery; for a few rows, `komando db query CONN -o csv` is a copy on this computer",
			"db dump and restore are not available for BigQuery")
	}
	if t.Kind.Name == "sqlserver" {
		return out.Errf(out.ExitUsage, "NOT_SUPPORTED",
			"SQL Server backs up with its own BACKUP DATABASE, which writes a .bak file on the database server: run it with `komando db query CONN --write` (it needs --allow-dangerous, so ask the user first), then fetch the file with `komando download` from that server",
			"db dump and restore are not available for SQL Server yet")
	}
	return out.Usage("%s conns have no dump tool", t.Kind.Name)
}
