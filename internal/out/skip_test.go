package out

import "testing"

// A command that resolves its target twice (exec checks the OS mix, then
// runs) must still list each skipped target once.
func TestSkipListsATargetOnce(t *testing.T) {
	p := &Printer{}
	p.Skip(Skipped{Name: "pg", Kind: "postgres", Reason: "a database"})
	p.Skip(Skipped{Name: "cache", Kind: "redis", Reason: "a cache"})
	p.Skip(Skipped{Name: "pg", Kind: "postgres", Reason: "a database"})
	p.Skip(Skipped{Name: "pg", Kind: "host", Reason: "a server with the same name"})
	if len(p.skipped) != 3 {
		t.Fatalf("skipped = %+v, want pg/postgres, cache, pg/host", p.skipped)
	}
}
