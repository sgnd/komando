package store

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
	Way   MigrateWay
	Why   string                               // who the caller is, for NEEDS_PERSON
	Ask   func(text string) bool               // the approval window (MigrateWindow)
	Alive func(pid int, procStart string) bool // whether a local komando process runs
}

// MigrateCaller is this process's caller. Unset, nobody migrates.
var MigrateCaller = func() MigrateCall { return MigrateCall{Way: MigrateRefuse} }
