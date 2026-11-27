package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
)

// The format-3 migration (vault note
// 2026-11-24-komando-v2-7-stored-data-migration-design, section 5). It is
// not switched on: migrateFormat3 is unexported and only its tests call
// it; the v2.7 cut calls it at the first open of a format-2 store.

// migrate3Opts is what the caller knows: whether a person runs it, which
// processes are alive, and the vault's reference guard.
type migrate3Opts struct {
	person   bool
	alive    func(pid int, procStart string) bool
	refGuard func(kind, name string) error
	now      func() time.Time
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
		"fix it with komando v0.17.0, then run `komando doctor` again",
		format+"; nothing was changed", a...)
}

// migrateFormat3 moves this home's store from format 2 to format 3. Every
// stop leaves the file as it was.
func migrateFormat3(ctx context.Context, o migrate3Opts) (migrate3Result, error) {
	var res migrate3Result
	if o.now == nil {
		o.now = time.Now
	}
	if ok, err := needsMigration3(ctx, o.person); !ok || err != nil {
		return res, err
	}
	// 3. the store lock, then 4. no komando process at work (Audit M6)
	unlock, err := Lock(storeLock)
	if err != nil {
		return res, err
	}
	defer unlock()
	if err := noLiveProcesses(o.alive); err != nil {
		return res, err
	}
	// 5. the normal open: old-copy count and policy MAC (Audit M4)
	d, err := DB(false)
	if err != nil {
		if pe := PolicyErr(err); pe != nil {
			return res, pe
		}
		return res, err
	}
	master, err := MasterKey()
	if err != nil {
		return res, err
	}
	defer clear(master)
	vc, err := newValueCipher(master)
	if err != nil {
		return res, err
	}
	// 6. the audit chain (Audit M3)
	if err := d.View(ctx, checkChain); err != nil {
		return res, out.Errf(out.ExitPolicy, "NEEDS_PERSON",
			"a person finds out what changed the audit log, then runs `komando audit verify` and `komando doctor`",
			"the audit log of %s is broken (%v), so the store does not move to a new format; nothing was changed", Path(StoreFile), err)
	}
	// 7. the backup
	backup, err := backupFormat2(ctx, d, master, o.now())
	if err != nil {
		return res, err
	}
	// 8. the plan
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
	p.report.Backup = backup
	// 9 to 11: one write step
	ks, err := keysFor3(master)
	if err != nil {
		return res, err
	}
	entry, err := json.Marshal(map[string]any{
		"ts": o.now().UTC().Format(time.RFC3339Nano), "command": "store.migrate", "ok": true, "dry_run": false,
		"actor": "komando", "format": Format3, "counts": p.report.Counts,
	})
	if err != nil {
		return res, err
	}
	err = d.Migrate(ctx, 2, Format3, ks.row, ks.policy,
		func(tx *sealdb.Tx) error { return writeFormat3(tx, p, snap, vc, entry) },
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
	// 12. the keychain's change count was raised by the store's commit
	// hook; 13. no process runs, so the runtime file goes
	if err := os.Remove(runtimePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		notice(fmt.Sprintf("could not remove %s (%v); its sessions are gone", runtimePath(), err))
	}
	// 14. the report
	res.report, res.auditEntry = p.report, string(entry)
	return res, nil
}

// needsMigration3 reports whether this home's store is to move: a store
// of format 2, a person at a terminal (steps 1 and 2). A missing store or
// one of format 3 has nothing to do.
func needsMigration3(ctx context.Context, person bool) (bool, error) {
	if !person {
		return false, out.Errf(out.ExitPolicy, "NEEDS_PERSON", "run `komando doctor` once in your own terminal",
			"%s is to move to a new format, and only a person starts that", Path(StoreFile))
	}
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
		return false, migrationFailed("%s is of format 1; open it once with komando v0.17.0 first", Path(StoreFile))
	}
	return false, migrationFailed("%s is of format %q", Path(StoreFile), meta["format"])
}

// noLiveProcesses stops while a komando background process of the
// runtime file still runs: it would write format-2 rows.
func noLiveProcesses(alive func(int, string) bool) error {
	if alive == nil {
		return errors.New("store: the migration was given no way to check for running komando processes")
	}
	rt, err := ReadRuntime()
	if errors.Is(err, os.ErrNotExist) {
		return nil // no runtime file: nothing runs
	}
	if err != nil {
		return err
	}
	var running []string
	for _, n := range slices.Sorted(maps.Keys(rt.Sessions)) {
		if s := rt.Sessions[n]; alive(s.PID, s.ProcStart) {
			running = append(running, fmt.Sprintf("VPN %s (stop it: komando vpn KIND stop %s)", n, n))
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
	for _, n := range slices.Sorted(maps.Keys(rt.Jobs)) {
		if j := rt.Jobs[n]; j.Ended == "" && alive(j.PID, "") {
			running = append(running, fmt.Sprintf("job %s (wait for it: komando job wait %s)", n, n))
		}
	}
	// a run on a server: this computer cannot see whether it ended, and its
	// record here is the only way to stop it, so a record alone stops this
	for _, n := range slices.Sorted(maps.Keys(rt.ExecSessions)) {
		e := rt.ExecSessions[n]
		running = append(running, fmt.Sprintf("exec session %s on %s (read it to the end: komando exec %s --attach %s; or stop it: komando exec %s --attach %s --stop, then komando exec %s --attach %s --remove)",
			n, e.Host, e.Host, n, e.Host, n, e.Host, n))
	}
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

// backupFormat2 copies the store beside it, 0600, before anything
// changes, and checks the copy opens and holds as many records.
func backupFormat2(ctx context.Context, d *sealdb.DB, master []byte, now time.Time) (string, error) {
	base := "store-v0-17-backup-" + now.Format("2006-01-02-150405")
	path := Path(base + ".db")
	for i := 2; ; i++ {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			break
		}
		path = Path(fmt.Sprintf("%s-%d.db", base, i)) // never over an earlier backup
	}
	if err := d.Backup(ctx, path); err != nil {
		return "", migrationFailed("the backup %s could not be made (%v)", path, err)
	}
	ks, err := keysFor(master, "2")
	if err != nil {
		return "", err
	}
	var want, got map[string]int
	if err := d.View(ctx, func(tx *sealdb.Tx) error { want, err = countTypes(tx); return err }); err != nil {
		return "", err
	}
	b, err := sealdb.Open(ctx, path, ks.row)
	if err != nil {
		return "", migrationFailed("the backup %s does not open (%v)", path, err)
	}
	defer b.Close()
	if err := b.View(ctx, func(tx *sealdb.Tx) error { got, err = countTypes(tx); return err }); err != nil {
		return "", migrationFailed("the backup %s cannot be read (%v)", path, err)
	}
	if !maps.Equal(want, got) {
		return "", migrationFailed("the backup %s does not hold what the store holds", path)
	}
	return path, nil
}

// readFormat2 is the snapshot the plan reads.
func readFormat2(tx *sealdb.Tx) (*snapshot2, error) {
	s, err := loadSealed(tx)
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
