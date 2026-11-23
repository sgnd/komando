//go:build migratehook

package store

// migrateHook, set by the kill-between-steps test, runs at the end of a
// migration step. It exists only under the migratehook build tag, which
// the release workflow never sets (TestReleaseHasNoMigrateHook).
var migrateHook func(step int) error

func migrateStepDone(step int) error {
	if migrateHook != nil {
		return migrateHook(step)
	}
	return nil
}
