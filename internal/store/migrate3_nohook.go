//go:build !migratehook

package store

// migrateStepDone does nothing in every build the release workflow makes.
func migrateStepDone(int) error { return nil }
