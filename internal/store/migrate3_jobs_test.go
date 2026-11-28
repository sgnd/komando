package store

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
)

// oldJobsHome is a format-2 store with three v0.17 job records: j1 and j3
// not seen ending, j2 ended. j1's command holds a secret value.
func oldJobsHome(t *testing.T) {
	t.Helper()
	format2Store(t)
	started := time.Date(2026, 11, 20, 9, 30, 0, 0, time.UTC)
	format2Runtime(t, func(s *State) {
		s.Jobs["j1"] = &Job{ID: "j1", Host: "web", Command: "PGPASSWORD=" + sentinel + " /usr/bin/pg_dump --password " + sentinel + " shop",
			PID: 4242, RemoteDir: "$HOME/.komando/jobs/j1", StartedAt: started}
		s.Jobs["j2"] = &Job{ID: "j2", Host: "web", Command: "uptime", PID: 4243, Ended: "exited"}
		s.Jobs["j3"] = &Job{ID: "j3", Host: "db", Command: "sleep 600", PID: 4244, StartedAt: started}
	})
	Close()
}

// Rule R3 (C606): doctor lists each v0.17 job record with no end: its ID,
// server, command name and start, never the command's arguments.
func TestOldJobsListed(t *testing.T) {
	oldJobsHome(t)
	jobs, err := OldJobs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 || jobs[0].ID != "j1" || jobs[1].ID != "j3" {
		t.Fatalf("old jobs: %+v", jobs)
	}
	j := jobs[0]
	if j.Host != "web" || j.Name != "pg_dump" || !j.Started.Equal(time.Date(2026, 11, 20, 9, 30, 0, 0, time.UTC)) || j.Folder != "$HOME/.komando/jobs/j1" {
		t.Errorf("j1 listed as %+v", j)
	}
	if jobs[1].Folder != "$HOME/.komando/jobs/j3" {
		t.Errorf("j3's folder %q: a record with no folder has v0.17's own", jobs[1].Folder)
	}
	if s := strings.Join([]string{j.ID, j.Host, j.Name, j.Folder}, " "); strings.Contains(s, sentinel) {
		t.Errorf("the listing holds a secret value: %s", s)
	}
}

// A stale record the person marks ended no longer stops the move, and it
// is carried with its mark.
func TestOldJobMarkedThenMoved(t *testing.T) {
	oldJobsHome(t)
	if err := EndOldJobs(context.Background(), []string{"j1", "j3"}); err != nil {
		t.Fatal(err)
	}
	Close()
	if jobs, err := OldJobs(context.Background()); err != nil || len(jobs) != 0 {
		t.Fatalf("after the marks: %+v %v", jobs, err)
	}
	Close()
	if _, err := migrateFormat3(context.Background(), personOpts()); err != nil {
		t.Fatalf("the move after the marks: %v", err)
	}
	// the marks are in the audit log, in the move's own write (audit A3)
	if e := lastAudit(t); !strings.Contains(e, `"event":"doctor.end-old-jobs"`) || !strings.Contains(e, `"jobs":["j1","j3"]`) {
		t.Errorf("the last audit record is %s, want the marked jobs", e)
	}
	rt, err := ReadRuntime()
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{"j1": "marked", "j2": "exited", "j3": "marked"} {
		if j := rt.Jobs[id]; j == nil || j.Ended != want {
			t.Errorf("job %s after the move: %+v, want ended %q", id, j, want)
		}
	}
}

// Only records with no end are marked; an ID the store does not hold, or
// one that ended, is refused and nothing is written.
func TestEndOldJobsUnknownID(t *testing.T) {
	oldJobsHome(t)
	for _, ids := range [][]string{{"j9"}, {"j2"}, {"j1", "j9"}} {
		err := EndOldJobs(context.Background(), ids)
		var e *out.Error
		if !errors.As(err, &e) || e.Code != "STORE_IN_USE" {
			t.Fatalf("%v: want STORE_IN_USE, got %v", ids, err)
		}
		Close()
		if jobs, err := OldJobs(context.Background()); err != nil || len(jobs) != 2 {
			t.Fatalf("%v: %+v %v", ids, jobs, err)
		}
		Close()
	}
}

// The dry run says the move would stop on the old jobs, by count only, and
// writes nothing.
func TestMigrationPreviewOldJobs(t *testing.T) {
	oldJobsHome(t)
	before := treeOf(t, Home())
	p, err := PreviewMigration(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if after := treeOf(t, Home()); !maps.Equal(before, after) {
		t.Fatalf("the dry run changed the home:\nbefore %v\nafter  %v", before, after)
	}
	want := "2 v0.17 job records have no end: `komando doctor` offers to mark each one ended"
	if p.WouldMove || !slices.Contains(p.WouldRefuse, want) {
		t.Fatalf("preview %+v", p)
	}
	if b, _ := json.Marshal(p); strings.Contains(string(b), "j1") || strings.Contains(string(b), sentinel) {
		t.Errorf("the dry run names a job or a value: %s", b)
	}
}

// A store of format 3, or none, has no old jobs and nothing to mark.
func TestOldJobsNoneOnFormat3(t *testing.T) {
	sealedHome(t)
	if _, err := DB(true); err != nil {
		t.Fatal(err)
	}
	Close()
	if jobs, err := OldJobs(context.Background()); err != nil || len(jobs) != 0 {
		t.Fatalf("format 3: %+v %v", jobs, err)
	}
}

func TestCommandName(t *testing.T) {
	for in, want := range map[string]string{
		"apt-get -y upgrade":                     "apt-get",
		"A=1 B=" + sentinel + " /opt/x/run.sh 2": "run.sh",
		`"/usr/bin/mysql" -p` + sentinel:         "mysql",
		"":                                       "",
		"X=" + sentinel:                          "",
	} {
		if got := commandName(in); got != want {
			t.Errorf("commandName(%q) = %q, want %q", in, got, want)
		}
	}
}
