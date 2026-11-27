package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
)

// The format-3 migration (vault note
// 2026-11-24-komando-v2-7-stored-data-migration-design, section 5). The first
// open of a format-2 store calls it (migrateOnOpen); MigrateCaller lets only
// `komando doctor` typed by a person start it (cli doctor_migrate.go).

// migrate3Opts is what the caller knows: how it may start the
// migration (MigrateCall), which processes are alive, and the vault's
// reference guard.
type migrate3Opts struct {
	way      MigrateWay
	why      string                 // who asked, for NEEDS_PERSON
	ask      func(text string) bool // the approval window (MigrateWindow)
	alive    func(pid int, procStart string) bool
	refGuard func(kind, name string) error
	now      func() time.Time
	// beforeLock runs between the first look at the format and the lock
	// (tests: another migration finishes meanwhile)
	beforeLock func()
	// afterPlan runs between the plan and the write step (tests: another
	// process writes meanwhile)
	afterPlan func()
}

// migrate3Result is the report for the person, and what the step read
// back (for the tests and the checks; never printed).
type migrate3Result struct {
	report     migration3Report
	readBack   []record3
	auditEntry string
}

func migrationFailed(format string, a ...any) error {
	return out.Errf(out.ExitError, "STORE_MIGRATION_FAILED",
		"fix it with komando "+LastFormat2Release+", then run `komando doctor` again",
		format+"; nothing was changed", a...)
}

// migrateFormat3 moves this home's store from format 2 to format 3. Every
// stop leaves the file as it was.
func migrateFormat3(ctx context.Context, o migrate3Opts) (migrate3Result, error) {
	var res migrate3Result
	if o.now == nil {
		o.now = time.Now
	}
	// 0 and 1: who asks, and the format
	if ok, err := needsMigration3(ctx); !ok || err != nil {
		return res, err
	}
	shown, err := migrateGate(ctx, o)
	if err != nil {
		return res, err
	}
	if o.beforeLock != nil {
		o.beforeLock()
	}
	// 2. the store lock; 3. the format again under it (another person may
	// have moved the store while this one waited); 4. no komando process
	// at work (Audit M6)
	unlock, err := Lock(storeLock)
	if err != nil {
		return res, err
	}
	defer unlock()
	if err := migrateStepDone(2); err != nil {
		return res, err
	}
	if ok, err := needsMigration3(ctx); !ok || err != nil {
		return res, err
	}
	if err := migrateStepDone(3); err != nil {
		return res, err
	}
	d, master, vc, carried, err := openForMove(ctx, o, shown)
	if err != nil {
		return res, err
	}
	defer clear(master)
	// 8. the plan, before the backup: a store the plan cannot move gets
	// no backup, since nothing is written (Audit E1 M1)
	var snap *snapshot2
	if err := d.View(ctx, func(tx *sealdb.Tx) error {
		var err error
		snap, err = readFormat2(tx)
		return err
	}); err != nil {
		return res, err
	}
	p, err := planFormat3(snap, o.refGuard)
	if err != nil {
		return res, err
	}
	// 7. the backup, under the name the person was shown when it is free
	at := o.now()
	if shown != nil {
		at = shown.at
	}
	backup, err := backupFormat2(ctx, d, master, at)
	if err != nil {
		return res, err
	}
	p.report.Backup = backup
	if err := migrateStepDone(8); err != nil {
		return res, err
	}
	if shown != nil && shown.backup != backup {
		p.report.BackupNote = fmt.Sprintf("the backup is %s: the name shown before the move, %s, was taken by then",
			filepath.Base(backup), filepath.Base(shown.backup))
	}
	if o.afterPlan != nil {
		o.afterPlan()
	}
	return writeMove(ctx, o, d, master, vc, p, snap, carried, backup)
}

// openForMove is steps 5, 4 and 6 under the lock: the normal open (old-copy
// count and policy MAC), no komando process at work, the audit chain, and
// the counts the window showed. The caller clears master.
func openForMove(ctx context.Context, o migrate3Opts, shown *shownWindow) (d *sealdb.DB, master []byte, vc *valueCipher, carried *Runtime, err error) {
	// 5. the normal open: old-copy count and policy MAC (Audit M4); it
	// writes nothing, and the process check below reads runtime.json
	// against this store's mark
	d, master, err = openFormat2()
	if err != nil {
		if pe := PolicyErr(err); pe != nil {
			return nil, nil, nil, nil, pe
		}
		return nil, nil, nil, nil, err
	}
	m := master
	defer func() {
		if err != nil {
			clear(m) // a stop past the open leaves no key behind
		}
	}()
	if err := primeRuntimeKey(master); err != nil {
		return nil, nil, nil, nil, err
	}
	vc, err = newValueCipher(master)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	rt, err := runtimeOf2(ctx, d)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// 4. under the lock: no komando process at work (Audit M6)
	if err := noLiveProcesses(rt, o.alive); err != nil {
		return nil, nil, nil, nil, err
	}
	if err := migrateStepDone(4); err != nil {
		return nil, nil, nil, nil, err
	}
	carried = &Runtime{Jobs: rt.Jobs, ExecSessions: rt.ExecSessions}
	carried.init()
	if err := migrateStepDone(5); err != nil {
		return nil, nil, nil, nil, err
	}
	// 6. the audit chain (Audit M3)
	if err := d.View(ctx, checkChain); err != nil {
		return nil, nil, nil, nil, out.Errf(out.ExitPolicy, "NEEDS_PERSON",
			"a person finds out what changed the audit log, then runs `komando audit verify` and `komando doctor`",
			"the audit log of %s is broken (%v), so the store does not move to a new format; nothing was changed", Path(StoreFile), err)
	}
	if err := migrateStepDone(6); err != nil {
		return nil, nil, nil, nil, err
	}
	// the counts the person was shown must still hold: something wrote
	// meanwhile otherwise
	if shown != nil {
		var now map[string]int
		if err := d.View(ctx, func(tx *sealdb.Tx) error { now, err = countTypes(tx); return err }); err != nil {
			return nil, nil, nil, nil, err
		}
		if !maps.Equal(shown.counts, now) {
			return nil, nil, nil, nil, out.Errf(out.ExitConflict, "STORE_IN_USE", "run `komando doctor` again",
				"%s changed after the plan was shown; nothing was changed", Path(StoreFile))
		}
	}
	return d, master, vc, carried, nil
}

// writeMove is steps 9 to 14: one write step that the store reads back,
// then the runtime records and the report.
func writeMove(ctx context.Context, o migrate3Opts, d *sealdb.DB, master []byte, vc *valueCipher, p *plan3, snap *snapshot2, carried *Runtime, backup string) (migrate3Result, error) {
	var res migrate3Result
	// 9 to 11: one write step
	ks, err := keysFor3(master)
	if err != nil {
		return res, err
	}
	via := "terminal"
	if o.way == MigrateWindow {
		via = "window"
	}
	entry, err := json.Marshal(map[string]any{
		"ts": o.now().UTC().Format(time.RFC3339Nano), "command": "store.migrate", "ok": true, "dry_run": false,
		"actor": "komando", "format": Format3, "counts": p.report.Counts, "via": via, "backup": filepath.Base(backup),
	})
	if err != nil {
		return res, err
	}
	var mark string
	err = d.Migrate(ctx, 2, Format3, ks.row, ks.policy,
		func(tx *sealdb.Tx) error {
			// the counts the plan was made from, again under the write
			// lock: a process that wrote since then stops the move
			now, err := countTypes(tx)
			if err != nil {
				return err
			}
			if !maps.Equal(snap.counts, now) {
				return out.Errf(out.ExitConflict, "STORE_IN_USE", "run `komando doctor` again",
					"%s changed after the move was planned; nothing was changed", Path(StoreFile))
			}
			if err := writeFormat3(tx, p, snap, vc, entry); err != nil {
				return err
			}
			// Q7: the runtime records that outlive the migration go into
			// the same step, under a new mark
			if mark, err = putRuntimeCopy(tx, carried); err != nil {
				return err
			}
			return migrateStepDone(9)
		},
		func(tx *sealdb.Tx) error {
			recs, err := readFormat3(tx, p, vc)
			res.readBack = recs
			if err == nil {
				err = migrateStepDone(10)
			}
			return err
		})
	if err != nil {
		res.readBack = nil
		var oe *out.Error
		if errors.As(err, &oe) {
			return res, err
		}
		return res, migrationFailed("%v", err)
	}
	if err := migrateStepDone(11); err != nil {
		return res, err
	}
	// 12. the keychain's change count was raised by the store's commit
	// hook; 13. runtime.json written from the store's copy
	if err := migrateStepDone(12); err != nil {
		return res, err
	}
	carried.Mark = mark
	if err := finishRuntimeCopy(*carried); err != nil {
		notice(fmt.Sprintf("could not write %s (%v); it is rebuilt from the store at the next open", runtimePath(), err))
	}
	if err := migrateStepDone(13); err != nil {
		return res, err
	}
	// 14. the report
	res.report, res.auditEntry = p.report, string(entry)
	return res, nil
}

// needsMigration3 reports whether this home's store is of format 2 (step
// 1). A missing store or one of format 3 has nothing to do.
func needsMigration3(ctx context.Context) (bool, error) {
	meta, err := sealdb.Peek(ctx, DBPath())
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	switch meta["format"] {
	case "2":
		return true, nil
	case "3":
		return false, nil
	case "1":
		return false, migrationFailed("%s is of format 1; open it once with komando %s first", Path(StoreFile), LastFormat2Release)
	}
	return false, migrationFailed("%s is of format %q", Path(StoreFile), meta["format"])
}

// shownWindow is the plan the person was shown before the move, at the
// terminal or in the approval window.
type shownWindow struct {
	at     time.Time // the backup's name is made from it
	backup string
	counts map[string]int
}

// needsPerson is the refusal for a caller that may not start the
// migration: an AI agent, a script, CI, a window that cannot be trusted.
func needsPerson(why string) error {
	if why == "" {
		why = "this caller"
	}
	return out.Errf(out.ExitPolicy, "NEEDS_PERSON", "run `komando doctor` with no flags once in your own terminal",
		"%s is to move to a new format, which only `komando doctor` typed by a person in their own terminal starts, not %s; nothing was changed: run `komando doctor` with no flags once in your own terminal", Path(StoreFile), why)
}

// migrateGate is step 0: a person at a terminal or in the approval window
// is shown the plan (shownWindow.plan) and answers yes or no; every other
// caller gets NEEDS_PERSON. It returns what the person was shown.
func migrateGate(ctx context.Context, o migrate3Opts) (*shownWindow, error) {
	if (o.way != MigrateTerminal && o.way != MigrateWindow) || o.ask == nil {
		return nil, needsPerson(o.why)
	}
	d, master, err := openFormat2()
	if err != nil {
		if pe := PolicyErr(err); pe != nil {
			return nil, pe // as openForMove: a changed deny rule is POLICY_MAC_FAILED
		}
		return nil, err
	}
	clear(master)
	at := o.now()
	backup, err := backupName(at)
	if err != nil {
		return nil, migrationFailed("no name for the backup (%v)", err)
	}
	w := &shownWindow{at: at, backup: backup}
	var snap *snapshot2
	if err := d.View(ctx, func(tx *sealdb.Tx) error {
		if w.counts, err = countTypes(tx); err != nil {
			return err
		}
		snap, err = readFormat2(tx)
		return err
	}); err != nil {
		return nil, err
	}
	// a store the plan cannot move asks nothing: the plan's stop comes first
	if _, err := planFormat3(snap, o.refGuard); err != nil {
		return nil, err
	}
	if !o.ask(w.plan()) {
		return nil, out.Errf(out.ExitPolicy, "NEEDS_PERSON", "run `komando doctor` again when you are ready",
			"the store was not moved to format 3: the answer was not yes; nothing was changed")
	}
	return w, nil
}

// noLiveProcesses stops while a komando background process of the
// runtime file still runs: it would write format-2 rows.
func noLiveProcesses(rt *Runtime, alive func(int, string) bool) error {
	if alive == nil {
		return errors.New("store: the migration was given no way to check for running komando processes")
	}
	var running []string
	for _, n := range slices.Sorted(maps.Keys(rt.Sessions)) {
		if s := rt.Sessions[n]; alive(s.PID, s.ProcStart) {
			running = append(running, fmt.Sprintf("VPN %s (stop it: komando vpn down %s)", n, n))
		}
	}
	for _, n := range slices.Sorted(maps.Keys(rt.Logins)) {
		if l := rt.Logins[n]; alive(l.PID, l.ProcStart) {
			running = append(running, fmt.Sprintf("server login %s (end it: komando logout %s)", n, n))
		}
	}
	for _, n := range slices.Sorted(maps.Keys(rt.Tunnels)) {
		if tn := rt.Tunnels[n]; alive(tn.PID, tn.ProcStart) {
			running = append(running, fmt.Sprintf("tunnel %s (stop it: komando tunnel stop %s)", n, n))
		}
	}
	// jobs and exec sessions run on servers: their records are carried
	// into the new store (carriedRuntime), never a reason to stop
	if len(running) > 0 {
		return out.Errf(out.ExitConflict, "STORE_IN_USE", "end each one as listed, then run `komando doctor` again",
			"%s is to move to a new format, and komando still runs: %s", Path(StoreFile), strings.Join(running, "; "))
	}
	return nil
}

// checkChain reads the whole audit chain.
func checkChain(tx *sealdb.Tx) error {
	var after int64
	for {
		rows, err := tx.Audit(after, 1000)
		if err != nil {
			return err
		}
		if len(rows) < 1000 {
			return nil
		}
		after = rows[len(rows)-1].Seq
	}
}

// migrationTypes are the record types the migration reads and counts.
var migrationTypes = []string{
	KindHost, KindConn, KindVpn, KindKey, KindRecipe, kindSettings, "secret", keyDataType, vpnStateType,
	KindHostCA, KindPin, KindPinRevoked, KindCredential, KindCredStore, KindGroup, KindApprovalSeed,
}

func countTypes(tx *sealdb.Tx) (map[string]int, error) {
	n := map[string]int{}
	for _, typ := range migrationTypes {
		rs, err := tx.List(typ)
		if err != nil {
			return nil, err
		}
		n[typ] = len(rs)
	}
	return n, nil
}

// backupPrefix starts the name of every backup the migration makes.
const backupPrefix = "store-v0-17-backup-"

// backupName is the first free backup name at now: neither the backup
// nor its .partial file exists. Any other error of a look stops it.
func backupName(now time.Time) (string, error) {
	base := backupPrefix + now.Format("2006-01-02-150405")
	path := Path(base + ".db")
	for i := 2; ; i++ {
		free := true
		for _, p := range []string{path, path + ".partial"} {
			if _, err := os.Lstat(p); err == nil {
				free = false
			} else if !errors.Is(err, os.ErrNotExist) {
				return "", err
			}
		}
		if free {
			return path, nil
		}
		path = Path(fmt.Sprintf("%s-%d.db", base, i)) // never over an earlier backup
	}
}

// backupFormat2 copies the store beside it, 0600, before anything
// changes: under a .partial name first, opened and counted, then renamed
// (Audit E1-6), so a backup under its final name is always whole.
func backupFormat2(ctx context.Context, d *sealdb.DB, master []byte, now time.Time) (string, error) {
	path, err := backupName(now)
	if err != nil {
		return "", migrationFailed("no name for the backup (%v)", err)
	}
	part := path + ".partial"
	if err := d.Backup(ctx, part); err != nil {
		return "", migrationFailed("the backup %s could not be made (%v)", path, err)
	}
	if err := migrateStepDone(7); err != nil {
		return "", err
	}
	ks, err := keysFor(master, "2")
	if err != nil {
		return "", err
	}
	var want, got map[string]int
	if err := d.View(ctx, func(tx *sealdb.Tx) error { want, err = countTypes(tx); return err }); err != nil {
		return "", err
	}
	b, err := sealdb.Open(ctx, part, ks.row)
	if err != nil {
		return "", migrationFailed("the backup %s does not open (%v)", path, err)
	}
	err = b.View(ctx, func(tx *sealdb.Tx) error { got, err = countTypes(tx); return err })
	b.Close()
	if err != nil {
		return "", migrationFailed("the backup %s cannot be read (%v)", path, err)
	}
	if !maps.Equal(want, got) {
		return "", migrationFailed("the backup %s does not hold what the store holds", path)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return "", migrationFailed("the backup name %s was taken while it was written", path)
	}
	if err := os.Rename(part, path); err != nil {
		return "", migrationFailed("the backup %s could not be named (%v)", path, err)
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return "", migrationFailed("the backup %s could not be synced (%v)", path, err)
	}
	return path, nil
}

// BackupParts names the .partial files of backups that a stopped
// migration left, never a backup under its final name. It changes
// nothing (doctor --dry-run).
func BackupParts() ([]string, error) {
	es, err := os.ReadDir(Home())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var parts []string
	for _, e := range es {
		if n := e.Name(); e.Type().IsRegular() && strings.HasPrefix(n, backupPrefix) && strings.HasSuffix(n, ".db.partial") {
			parts = append(parts, n)
		}
	}
	return parts, nil
}

// RemoveBackupParts removes the files BackupParts names (doctor), under
// the store lock: a move at work writes its backup under a .partial name
// while it holds the lock. It returns the names removed.
func RemoveBackupParts() ([]string, error) {
	unlock, err := Lock(storeLock)
	if err != nil {
		return nil, err
	}
	defer unlock()
	parts, err := BackupParts()
	if err != nil {
		return nil, err
	}
	var removed []string
	for _, n := range parts {
		if err := os.Remove(Path(n)); err != nil {
			return removed, err
		}
		removed = append(removed, n)
	}
	return removed, nil
}

// readFormat2 is the snapshot the plan reads.
func readFormat2(tx *sealdb.Tx) (*snapshot2, error) {
	s, err := loadFormat2(tx)
	if err != nil {
		return nil, err
	}
	snap := &snapshot2{state: s, secrets: map[string]secret2{}}
	rows, err := tx.List("secret")
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		var e struct {
			Name  string `json:"name"`
			Nonce []byte `json:"nonce"`
			Data  []byte `json:"data"`
		}
		if err := json.Unmarshal(r.Data, &e); err != nil {
			return nil, fmt.Errorf("secret record %s: %w", r.ID, err)
		}
		if _, dup := snap.secrets[e.Name]; e.Name == "" || dup {
			return nil, fmt.Errorf("secret record %s: %w", r.ID, sealdb.ErrTampered)
		}
		snap.secrets[e.Name] = secret2{id: r.ID, value: SealedValue{Nonce: e.Nonce, Data: e.Data}}
	}
	snap.counts, err = countTypes(tx)
	return snap, err
}

// writeFormat3 writes the plan inside the migration step.
func writeFormat3(tx *sealdb.Tx, p *plan3, snap *snapshot2, vc *valueCipher, entry []byte) error {
	for _, id := range p.deletes {
		if err := tx.Delete(id); err != nil {
			return err
		}
	}
	credIDs := map[string]string{}
	for _, cp := range p.creds {
		c := cp.cred
		if cp.copyKeydata != "" {
			r, err := tx.Get(cp.copyKeydata)
			if err != nil {
				return fmt.Errorf("the key pair of credential %s: %w", c.Name, err)
			}
			nr, err := tx.Put(keyDataType, "", r.Data)
			if err != nil {
				return err
			}
			c.Key.Path = sealedKeyPrefix + nr.ID
		}
		if cp.valueFrom != "" {
			v := snap.secrets[cp.valueFrom].value
			if c.Name != cp.valueFrom {
				var err error
				if v, err = vc.rename(cp.valueFrom, c.Name, v); err != nil {
					return fmt.Errorf("credential %s: %w", c.Name, err)
				}
			}
			c.Value = &v
		}
		id, err := putJSON(tx, KindCredential, "", c)
		if err != nil {
			return err
		}
		credIDs[c.Name] = id
	}
	for _, id := range slices.Sorted(maps.Keys(p.hosts)) {
		h := p.hosts[id]
		h.CredentialID = credIDs[h.Credential]
		if _, err := putJSON(tx, KindHost, id, h); err != nil {
			return err
		}
	}
	for _, id := range slices.Sorted(maps.Keys(p.conns)) {
		if _, err := putJSON(tx, KindConn, id, p.conns[id]); err != nil {
			return err
		}
	}
	for _, id := range slices.Sorted(maps.Keys(p.vpns)) {
		if _, err := putJSON(tx, KindVpn, id, p.vpns[id]); err != nil {
			return err
		}
	}
	for _, s := range p.swarms {
		if _, err := putJSON(tx, KindConn, "", s); err != nil {
			return err
		}
	}
	for _, s := range p.stores {
		if _, err := putJSON(tx, KindCredStore, "", s); err != nil {
			return err
		}
	}
	for _, g := range p.groups {
		if _, err := putJSON(tx, KindGroup, "", g); err != nil {
			return err
		}
	}
	if p.seed != nil {
		// sealed under ApprovalSeedName as before: no new seal
		if _, err := putJSON(tx, KindApprovalSeed, "", approvalSeed{Value: p.seed.value}); err != nil {
			return err
		}
	}
	return tx.AppendAudit(entry)
}

func putJSON(tx *sealdb.Tx, typ, id string, v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	r, err := tx.Put(typ, id, b)
	return r.ID, err
}

// readFormat3 reads the migrated store back inside the step: the counts,
// the F10 check, every value opens under its name, every key pair is
// there, the seed opens and is no credential (Audit M1, M2).
func readFormat3(tx *sealdb.Tx, p *plan3, vc *valueCipher) ([]record3, error) {
	got, err := countTypes(tx)
	if err != nil {
		return nil, err
	}
	for typ, n := range p.expect {
		if got[typ] != n {
			return nil, fmt.Errorf("%d %s records after the migration, want %d", got[typ], typ, n)
		}
	}
	var recs []record3
	decode := func(typ string, mk func() any, name func(any) string) error {
		rows, err := tx.List(typ)
		if err != nil {
			return err
		}
		for _, r := range rows {
			v := mk()
			if err := json.Unmarshal(r.Data, v); err != nil {
				return fmt.Errorf("%s record %s: %w", typ, r.ID, err)
			}
			recs = append(recs, record3{typ: typ, id: r.ID, name: name(v), data: v})
		}
		return nil
	}
	steps := []struct {
		typ  string
		mk   func() any
		name func(any) string
	}{
		{KindHost, func() any { return &HostV3{} }, func(v any) string { return v.(*HostV3).Name }},
		{KindConn, func() any { return &ServiceV3{} }, func(v any) string { return v.(*ServiceV3).Name }},
		{KindVpn, func() any { return &VpnV3{} }, func(v any) string { return v.(*VpnV3).Name }},
		{KindCredential, func() any { return &Credential{} }, func(v any) string { return v.(*Credential).Name }},
		{KindCredStore, func() any { return &CredentialStore{} }, func(v any) string { return v.(*CredentialStore).Name }},
		{KindGroup, func() any { return &Group{} }, func(v any) string { return v.(*Group).Name }},
		{KindApprovalSeed, func() any { return &approvalSeed{} }, func(any) string { return ApprovalSeedName }},
	}
	for _, s := range steps {
		if err := decode(s.typ, s.mk, s.name); err != nil {
			return nil, err
		}
	}
	for _, typ := range []string{KindRecipe, keyDataType, vpnStateType, KindHostCA, KindPin, KindPinRevoked} {
		rows, err := tx.List(typ)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			recs = append(recs, record3{typ: typ, id: r.ID})
		}
	}
	if err := checkOldRefs3(recs); err != nil {
		return nil, err
	}
	for _, r := range recs {
		if err := checkRecord3(tx, r, vc); err != nil {
			return nil, err
		}
	}
	return recs, nil
}

func checkRecord3(tx *sealdb.Tx, r record3, vc *valueCipher) error {
	switch v := r.data.(type) {
	case *Credential:
		if err := ReservedCredential(v.Name); err != nil {
			return err
		}
		if v.Value != nil {
			plain, err := vc.open(v.Name, *v.Value)
			clear(plain)
			if err != nil {
				return fmt.Errorf("credential %s does not open under its name", v.Name)
			}
		}
		if v.Key != nil && strings.HasPrefix(v.Key.Path, sealedKeyPrefix) {
			if _, err := tx.Get(strings.TrimPrefix(v.Key.Path, sealedKeyPrefix)); err != nil {
				return fmt.Errorf("credential %s: its key pair: %w", v.Name, err)
			}
		}
	case *approvalSeed:
		plain, err := vc.open(ApprovalSeedName, v.Value)
		clear(plain)
		if err != nil {
			return errors.New("the approval code's seed does not open")
		}
	}
	return nil
}
