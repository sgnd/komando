package store

import "context"

// Who may move a format-2 store to format 3 (cut step E1; design note
// 2026-11-25-cut-e1-migration-design, section 5). The CLI sets
// MigrateCaller from the call: the store reads no environment itself.

// MigrateWay is how this call may start the migration.
type MigrateWay int

const (
	// MigrateRefuse: an AI agent, a script or CI; it gets NEEDS_PERSON.
	MigrateRefuse MigrateWay = iota
	// MigrateTerminal: a person at a terminal.
	MigrateTerminal
	// MigrateWindow: the person answers komando's safety-tier approval
	// window (`komando doctor` run by the Komando app).
	MigrateWindow
)

// MigrateCall is what the caller hands the store.
type MigrateCall struct {
	Way      MigrateWay
	Why      string                               // who the caller is, for NEEDS_PERSON
	Ask      func(text string) bool               // the approval window (MigrateWindow)
	Alive    func(pid int, procStart string) bool // whether a local komando process runs
	RefGuard func(kind, name string) error        // the vault's reference guard
}

// migrateOnOpen runs the migration at the first open of a format-2
// store, as MigrateCaller allows, and tells the person what it did.
func migrateOnOpen() error {
	c := MigrateCaller()
	res, err := migrateFormat3(context.Background(), migrate3Opts{
		way: c.Way, why: c.Why, ask: c.Ask, alive: c.Alive, refGuard: c.RefGuard,
	})
	dropHome()
	if err != nil {
		return err
	}
	if res.report.Backup != "" {
		notice(res.report.text())
	}
	return nil
}

// MigrateCaller is this process's caller. Unset, nobody migrates.
var MigrateCaller = func() MigrateCall { return MigrateCall{Way: MigrateRefuse} }
