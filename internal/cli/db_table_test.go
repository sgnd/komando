package cli

import (
	"bytes"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// tableRun runs komando without -o json and returns what it printed.
func tableRun(t *testing.T, args ...string) (string, *out.Error) {
	t.Helper()
	tcl.flags.dryRun, tcl.flags.yes, tcl.flags.maxOutput = false, false, 0
	var buf bytes.Buffer
	saved := tcl.out.W
	tcl.out.W = &buf
	defer func() { tcl.out.W = saved }()
	root := newRoot(tcl)
	t.Cleanup(endCommand) // the next test starts with none of this command's flags
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		return buf.String(), toErr(err)
	}
	return buf.String(), nil
}

func tableDB(t *testing.T, rows int) {
	t.Helper()
	invHome(t)
	mustRun(t, "conn", "add", "lite", "sqlite://"+filepath.Join(t.TempDir(), "app.db"))
	mustRun(t, "db", "query", "lite", "--write", "create table t (id int, name text)")
	mustRun(t, "db", "query", "lite", "--write", "with recursive n(i) as (select 1 union all select i+1 from n where i < "+
		strconv.Itoa(rows)+") insert into t select i, 'row ' || i from n")
}

// -o csv and -o tsv print every row unless --limit says otherwise; the
// default row cap of 500 is for JSON and tables only.
func TestDBQueryTableOutput(t *testing.T) {
	tableDB(t, 600)
	for _, c := range []struct {
		args  []string
		lines int
		first string
	}{
		{[]string{"-o", "csv"}, 601, "id,name"},
		{[]string{"-o", "tsv"}, 601, "id\tname"},
		{[]string{"-o", "csv", "--limit", "10"}, 11, "id,name"},
		{[]string{"-o", "tsv", "-n", "3"}, 4, "id\tname"},
	} {
		s, e := tableRun(t, append(append([]string{"db", "query", "lite"}, c.args...), "select id, name from t order by id")...)
		lines := strings.Split(strings.TrimSpace(s), "\n")
		if e != nil || len(lines) != c.lines || lines[0] != c.first {
			t.Errorf("%v: %d lines, first %q, %v", c.args, len(lines), lines[0], e)
		}
	}
}

func TestDBQueryTableConflicts(t *testing.T) {
	tableDB(t, 3)
	q := "select id from t"
	if s, e := tableRun(t, "db", "query", "lite", "-o", "tsv", "-o", "csv", q); e != nil || !strings.HasPrefix(s, "id\n") {
		t.Errorf("the last -o wins: %q %+v", s, e)
	}
	if _, e := tableRun(t, "list", "-o", "csv"); e == nil || e.Code != "USAGE" || !strings.Contains(e.Message, "db query") {
		t.Errorf("-o csv elsewhere: %+v", e)
	}
}

// An export cut by the output size cap prints nothing and fails, so a
// file never looks whole when it is not.
func TestDBQueryTableTruncated(t *testing.T) {
	tableDB(t, 200)
	s, e := tableRun(t, "db", "query", "lite", "-o", "csv", "--max-output", "1000", "select id, name from t")
	if e == nil || e.Code != "OUTPUT_TRUNCATED" || e.Exit != out.ExitError || s != "" {
		t.Errorf("cut export: %q %+v", s, e)
	}
}
