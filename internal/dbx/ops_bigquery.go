package dbx

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	kdriver "github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// BigQuery's views for db explain, info, activity, sizes and kill. db
// explain is the dry run; activity and sizes read the INFORMATION_SCHEMA
// of the jobs' location (region-LOCATION.INFORMATION_SCHEMA.JOBS and
// TABLE_STORAGE), and db kill cancels a job through the API (jobs.cancel).
// A job has a text ID; db activity shows a pid komando makes from it (53
// bits of its FNV-1a hash, as for Snowflake's queries), which db kill takes.

// bqWith runs fn with the driver connection behind db.
func bqWith(ctx context.Context, db *sql.DB, fn func(*bqConn) error) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	return bqRaw(conn, fn)
}

func bqRaw(conn *sql.Conn, fn func(*bqConn) error) error {
	return conn.Raw(func(dc any) error {
		cn, ok := dc.(*bqConn)
		if !ok {
			return errors.New("not a bigquery connection")
		}
		return fn(cn)
	})
}

// bqLimit is Options.MaxBilled as a cap: 0 for none.
func bqLimit(maxBilled int64) int64 {
	switch {
	case maxBilled == 0:
		return BQDefaultMaxBytes
	case maxBilled < 0:
		return 0
	}
	return maxBilled
}

func bqArgs(args []any) []driver.NamedValue {
	vals := make([]driver.Value, len(args))
	for i, a := range args {
		vals[i] = a
	}
	return named(vals)
}

// bqDryRunOnly is --dry-run on BigQuery: BigQuery checks the statement
// and says how much it would read, and nothing runs (nor is billed).
func bqDryRunOnly(ctx context.Context, conn *sql.Conn, st kdriver.Statement, o Options, r *StatementResult) error {
	return bqRaw(conn, func(cn *bqConn) error {
		dry, err := cn.c.dryRun(ctx, st.SQL, bqArgs(o.Args))
		if err != nil {
			return err
		}
		if err := cn.c.checkDry(st.SQL, dry, false, bqLimit(o.MaxBilled)); err != nil {
			return err
		}
		n := dry.bytes()
		r.BytesProcessed = &n
		r.Skipped = fmt.Sprintf("dry run: BigQuery checked this %s statement without running it (it would read %s)",
			strings.ReplaceAll(dry.Statistics.Query.StatementType, "_", " "), humanBytes(n))
		return nil
	})
}

// runBQPlan is db explain on BigQuery: the dry run's answer, as rows
// (what it would read is one of them).
func runBQPlan(ctx context.Context, conn *sql.Conn, st kdriver.Statement, o Options, r *StatementResult) error {
	return bqRaw(conn, func(cn *bqConn) error {
		dry, err := cn.c.dryRun(ctx, st.SQL, bqArgs(o.Args))
		if err != nil {
			return err
		}
		q := dry.Statistics.Query
		n := dry.bytes()
		r.Columns = []Column{{Name: "property"}, {Name: "value"}}
		add := func(k, v string) { r.Rows = append(r.Rows, []any{k, v}) }
		add("statement type", q.StatementType)
		read := fmt.Sprintf("%s (%d bytes)", humanBytes(n), n)
		if q.TotalBytesProcessedAccuracy != "" && q.TotalBytesProcessedAccuracy != "PRECISE" {
			read += ", " + strings.ToLower(strings.ReplaceAll(q.TotalBytesProcessedAccuracy, "_", " "))
		}
		add("would read", read)
		if limit := bqLimit(o.MaxBilled); limit > 0 {
			verdict := "within --max-bytes " + humanBytes(limit)
			if n > limit {
				verdict = "more than --max-bytes " + humanBytes(limit) + ": it would not run"
			}
			add("cost cap", verdict)
		}
		var tables []string
		for _, t := range q.ReferencedTables {
			tables = append(tables, t.ProjectID+"."+t.DatasetID+"."+t.TableID)
		}
		if len(tables) > 0 {
			add("tables read", strings.Join(tables, ", "))
		}
		if q.Schema != nil {
			var cols []string
			for _, f := range q.Schema.Fields {
				cols = append(cols, f.Name+" "+bqTypeName(f))
			}
			add("result columns", strings.Join(cols, ", "))
		}
		r.RowCount = len(r.Rows)
		return nil
	})
}

var bqRegionName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// region is the INFORMATION_SCHEMA qualifier of the conn's location
// (`region-eu`): the URL's ?location=, the default dataset's, or US.
func (c *bqConnector) region(ctx context.Context) string {
	loc := c.location
	if loc == "" && c.b.Dataset != "" {
		var ds struct {
			Location string `json:"location"`
		}
		if c.call(ctx, http.MethodGet, c.projectPath()+"/datasets/"+url.PathEscape(c.b.Dataset), nil, nil, &ds) == nil {
			loc = ds.Location
		}
	}
	loc = strings.ToLower(loc)
	if !bqRegionName.MatchString(loc) {
		loc = "us"
	}
	return "`region-" + loc + "`"
}

func bqRegion(ctx context.Context, db *sql.DB) (string, error) {
	var region string
	err := bqWith(ctx, db, func(cn *bqConn) error {
		region = cn.c.region(ctx)
		return nil
	})
	return region, err
}

func bigqueryInfo(ctx context.Context, db *sql.DB) (map[string]any, error) {
	res := map[string]any{"version": "BigQuery"}
	err := bqWith(ctx, db, func(cn *bqConn) error {
		c := cn.c
		res["project"] = c.b.Project
		if c.b.Dataset != "" {
			res["dataset"] = c.b.Dataset
		}
		if !c.google {
			res["endpoint"] = c.b.Endpoint
		}
		res["location"] = strings.ToUpper(strings.TrimSuffix(strings.TrimPrefix(c.region(ctx), "`region-"), "`"))
		var list struct {
			Datasets []any `json:"datasets"`
		}
		if err := c.call(ctx, http.MethodGet, c.projectPath()+"/datasets", url.Values{"maxResults": {"1000"}}, nil, &list); err != nil {
			return err
		}
		res["datasets"] = len(list.Datasets)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if r, err := oneRow(ctx, db, "SELECT SESSION_USER() AS user"); err == nil {
		res["user"] = r["user"]
	}
	return res, nil
}

// bqRunning are the jobs that are not done, but this one (its text holds
// the marker it leaves out).
const bqRunning = `
SELECT job_id, project_id, user_email AS user, job_type, statement_type, state,
       TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), creation_time, SECOND) AS running_seconds,
       total_bytes_processed AS bytes_processed, LEFT(query, 500) AS query
FROM %s.INFORMATION_SCHEMA.JOBS
WHERE state != 'DONE' AND creation_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 2 DAY)
  AND IFNULL(query, '') NOT LIKE '%%komando db activity%%'
ORDER BY creation_time`

func bigqueryActivity(ctx context.Context, db *sql.DB) ([]map[string]any, error) {
	region, err := bqRegion(ctx, db)
	if err != nil {
		return nil, err
	}
	rows, err := rowsOf(ctx, db, fmt.Sprintf(bqRunning, region))
	for _, r := range rows {
		r["pid"] = sfPID(fmt.Sprint(r["job_id"]))
	}
	return rows, err
}

func bigquerySizes(ctx context.Context, db *sql.DB, limit int, res map[string]any) error {
	region, err := bqRegion(ctx, db)
	if err != nil {
		return err
	}
	if res["databases"], err = rowsOf(ctx, db, fmt.Sprintf(`
SELECT table_schema AS name, SUM(total_logical_bytes) AS bytes, SUM(total_physical_bytes) AS physical_bytes
FROM %s.INFORMATION_SCHEMA.TABLE_STORAGE WHERE NOT deleted GROUP BY 1 ORDER BY 2 DESC`, region)); err != nil {
		return err
	}
	res["tables"], err = rowsOf(ctx, db, fmt.Sprintf(`
SELECT table_schema AS schema, table_name AS name, total_logical_bytes AS total_bytes,
       total_physical_bytes AS physical_bytes, total_rows AS rows
FROM %s.INFORMATION_SCHEMA.TABLE_STORAGE WHERE NOT deleted
ORDER BY total_logical_bytes DESC LIMIT %d`, region, max(limit, 1)))
	return err
}

var bqJobID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,1000}$`)

// bigqueryKill cancels the job db activity showed as pid. BigQuery stops
// jobs, not sessions, so there is no --session.
func bigqueryKill(ctx context.Context, db *sql.DB, pid int64, session bool) error {
	if session {
		return out.Errf(out.ExitUsage, "NOT_SUPPORTED",
			"BigQuery cancels jobs, not connections: drop --session (a BigQuery session ends with CALL BQ.ABORT_SESSION('ID') through `komando db query CONN --write`; it needs --allow-dangerous, so ask the user first)",
			"db kill --session is not available for bigquery")
	}
	rows, err := bigqueryActivity(ctx, db)
	if err != nil {
		return err
	}
	region, err := bqRegion(ctx, db)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if r["pid"] != pid {
			continue
		}
		id, project := fmt.Sprint(r["job_id"]), fmt.Sprint(r["project_id"])
		if !bqJobID.MatchString(id) {
			return fmt.Errorf("unexpected job ID %q", id)
		}
		loc := strings.TrimSuffix(strings.TrimPrefix(region, "`region-"), "`")
		return bqWith(ctx, db, func(cn *bqConn) error {
			return cn.c.cancelJob(ctx, bqJobRef{ProjectID: project, JobID: id, Location: loc})
		})
	}
	return out.Errf(out.ExitNotFound, "SESSION_NOT_FOUND", "list running jobs with `komando db activity CONN`", "no running job %d", pid)
}

func bqNoLocks() error {
	return out.Errf(out.ExitUsage, "NOT_SUPPORTED",
		"BigQuery has no locks to wait for: `komando db activity CONN` shows the jobs that are not done",
		"db locks is not available for bigquery")
}

// BQNoUsers is db user, db grant, revoke and grants on BigQuery, whose
// users and rights are Google Cloud IAM.
func BQNoUsers(what string) error {
	return out.Errf(out.ExitUsage, "NOT_SUPPORTED",
		"BigQuery's users and rights are Google Cloud IAM (the console's IAM page); a dataset's own grants are in INFORMATION_SCHEMA.OBJECT_PRIVILEGES, which `komando db query CONN` reads, and GRANT ... TO \"user:NAME@example.com\" goes through `db query --write` (it needs --allow-dangerous, so ask the user first)",
		"%s is not available for bigquery", what)
}
