package store

import (
	"context"
	"maps"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
)

// Rule R3 (C606): v0.18 has no job commands and no exec session takes a
// v0.17 job ID, so the move to format 3 stops while a v0.17 job record has
// no end (noLiveProcesses). Doctor lists those records (OldJobs) and, on
// the person's yes, marks them ended in the format-2 store (EndOldJobs).

// oldJobRoot is v0.17's folder of job folders on a server.
const oldJobRoot = "$HOME/.komando/jobs"

// jobMarked is Job.Ended for a record a person marked ended before the move.
const jobMarked = "marked"

// OldJob is a v0.17 job record with no end, as doctor lists it.
type OldJob struct {
	ID      string    `json:"id"`
	Host    string    `json:"server"`
	Name    string    `json:"command_name"` // the program alone: the arguments may hold secret values
	Started time.Time `json:"started"`
	Folder  string    `json:"folder"` // on the server
}

// OldJobs lists the job records with no end of a format-2 store, by ID. A
// store of format 3, or none, has none.
func OldJobs(ctx context.Context) ([]OldJob, error) {
	if ok, err := needsMigration3(ctx); !ok || err != nil {
		return nil, err
	}
	s, err := openRuntime2(ctx)
	if err != nil {
		return nil, err
	}
	var jobs []OldJob
	for _, id := range slices.Sorted(maps.Keys(s.Runtime.Jobs)) {
		if j := s.Runtime.Jobs[id]; j.Ended == "" {
			jobs = append(jobs, OldJob{ID: id, Host: j.Host, Name: commandName(j.Command), Started: j.StartedAt, Folder: oldJobFolder(j)})
		}
	}
	return jobs, nil
}

// EndOldJobs marks each named record ended in the format-2 store, so the
// move goes ahead. Each must be a record with no end. A job runs on its
// server, which this computer cannot see: the person who marks it looked
// there (doctor says so).
func EndOldJobs(ctx context.Context, ids []string) error {
	unlock, err := Lock(storeLock)
	if err != nil {
		return err
	}
	defer unlock()
	unlockRuntime, err := Lock(runtimeLock)
	if err != nil {
		return err
	}
	defer unlockRuntime()
	ok, err := needsMigration3(ctx)
	if err != nil {
		return err
	}
	var s *State
	if ok {
		if s, err = openRuntime2(ctx); err != nil {
			return err
		}
	}
	for _, id := range ids {
		if s == nil || s.Runtime.Jobs[id] == nil || s.Runtime.Jobs[id].Ended != "" {
			// doctor names only what OldJobs listed: the records changed meanwhile
			return out.Errf(out.ExitConflict, "STORE_IN_USE", "run `komando doctor` again",
				"no v0.17 job %s without an end in %s any more; nothing was marked", id, Path(StoreFile))
		}
	}
	for _, id := range ids {
		s.Runtime.Jobs[id].Ended = jobMarked
	}
	return s.saveRuntime()
}

// openRuntime2 opens the format-2 store and reads its runtime file.
func openRuntime2(ctx context.Context) (*State, error) {
	d, master, err := openFormat2()
	if err != nil {
		return nil, err
	}
	defer clear(master)
	if err := primeRuntimeKey(master); err != nil {
		return nil, err
	}
	return runtimeState2(ctx, d)
}

// unendedJobs counts the job records with no end in the runtime file of
// the format-2 store d, for the dry run: it reads and writes nothing else.
func unendedJobs(ctx context.Context, d *sealdb.DB, master []byte) (int, error) {
	if err := primeRuntimeKey(master); err != nil {
		return 0, err
	}
	s, err := runtimeState2(ctx, d)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, j := range s.Runtime.Jobs {
		if j.Ended == "" {
			n++
		}
	}
	return n, nil
}

// oldJobFolder is the job's folder on its server.
func oldJobFolder(j *Job) string {
	if j.RemoteDir != "" {
		return j.RemoteDir
	}
	return oldJobRoot + "/" + j.ID
}

// commandName is the program a command line runs, without its folder,
// leading VAR=value settings or arguments.
func commandName(cmd string) string {
	for _, f := range strings.Fields(cmd) {
		if strings.Contains(f, "=") {
			continue
		}
		return path.Base(strings.Trim(f, `'"`))
	}
	return ""
}

