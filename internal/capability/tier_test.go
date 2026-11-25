package capability

import (
	"slices"
	"strings"
	"testing"
)

func TestShellIsPerson(t *testing.T) {
	for _, l := range All() {
		if l.Verb != "shell" {
			continue
		}
		person := false
		for _, r := range Rows(l.Key) {
			if r.Tier == Person && r.When.Flags == nil && r.When.Words == nil {
				person = true
			}
		}
		if !person {
			t.Errorf("%s: a shell is for a person only, but no unconditional person row reaches it", l.Key)
		}
	}
}

// TestLoginIsPerson: today's login commands are for a person only, so a
// leaf that carries one keeps a person row for its sign-in step.
func TestLoginIsPerson(t *testing.T) {
	for _, l := range All() {
		for _, id := range l.Carries {
			if id != "login" && !strings.HasPrefix(id, "login.") {
				continue
			}
			person := false
			for _, r := range Rows(l.Key) {
				person = person || r.Tier == Person
			}
			if !person {
				t.Errorf("%s: carries %s, a person-only command, but no person row reaches it", l.Key, id)
			}
		}
	}
}

func TestTierKeysExist(t *testing.T) {
	for _, r := range TierRows() {
		reached := false
		for _, l := range All() {
			if r.Reaches(l.Key) {
				reached = true
			}
		}
		if !reached {
			t.Errorf("tier row %s (%q): no leaf has this key", r.Key, r.What+r.Dynamic)
		}
	}
}

// TestTierFlagsExist: a row's condition names options, and each one is an
// option of every leaf the row reaches, so renaming a flag fails here
// instead of silently dropping the row's tier.
func TestTierFlagsExist(t *testing.T) {
	for _, r := range TierRows() {
		for _, l := range All() {
			if !r.Reaches(l.Key) {
				continue
			}
			for _, f := range r.When.Flags {
				if _, ok := l.Option(f); !ok {
					t.Errorf("%s: the tier row for --%s reaches it, but it has no option --%s", l.Key, f, f)
				}
			}
		}
	}
}

func TestReachesProvider(t *testing.T) {
	row := TierRow{Key: Key{Type: "host", Provider: "ssh", Verb: "add"}}
	tests := []struct {
		name string
		key  Key
		want bool
	}{
		{"same provider", Key{Type: "host", Provider: "ssh", Verb: "add"}, true},
		{"other provider", Key{Type: "host", Provider: "winrm", Verb: "add"}, false},
		{"other verb", Key{Type: "host", Provider: "ssh", Verb: "edit"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := row.Reaches(tt.key); got != tt.want {
				t.Errorf("Reaches(%s) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
	wild := TierRow{Key: Key{Type: "host", Verb: "shell"}}
	if !wild.Reaches(Key{Type: "host", Provider: "serial", Verb: "shell"}) {
		t.Error("a row without a provider must reach every provider")
	}
}

// TestFloor: a verb that only looks has the floor read, every other verb
// change; Highest is the floor or the highest row that reaches the leaf,
// whatever its condition.
func TestFloor(t *testing.T) {
	tests := []struct {
		key  Key
		want Tier
	}{
		{Key{Type: "host", Provider: "ssh", Verb: "list"}, Read},
		{own("credential", "", "show"), Read},
		{top("status"), Read},
		{Key{Type: "database", Provider: "postgres", Verb: "backup"}, Change}, // writes the data to a file: change unless a row says read
		{top("export"), Change},
		{Key{Type: "host", Provider: "ssh", Verb: "test"}, Read},
		{Key{Type: "host", Provider: "ssh", Verb: "check"}, Read},
		{Key{Type: "host", Provider: "ssh", Verb: "add"}, Change},
		{Key{Type: "host", Provider: "ssh", Verb: "exec"}, Change},
		{top("ssh-gate"), Change}, // a kept word: not a verb that only looks
	}
	for _, tt := range tests {
		if got := Floor(tt.key); got != tt.want {
			t.Errorf("Floor(%s) = %d, want %d", tt.key, got, tt.want)
		}
	}
	for _, v := range readVerbs {
		if !slices.ContainsFunc(Verbs(), func(x Verb) bool { return x.Name == v }) {
			t.Errorf("readVerbs has %q, which is no verb of the closed vocabulary", v)
		}
	}
	if got := Highest(Key{Type: "host", Provider: "ssh", Verb: "exec"}); got != Dangerous {
		t.Errorf("Highest(host ssh exec) = %d, want dangerous (its row)", got)
	}
	if got := Highest(Key{Type: "host", Provider: "ssh", Verb: "list"}); got != Read {
		t.Errorf("Highest(host ssh list) = %d, want read (no row, a looking verb)", got)
	}
}

// TestDataOutHasARow: a leaf that writes data out of komando (backup,
// export) has an explicit row with no condition, so its tier is decided
// for it and never taken from a floor. A row of read is given only where
// today's command reads (TestLeafFloorNotWeaker).
func TestDataOutHasARow(t *testing.T) {
	n := 0
	for _, l := range leaves {
		if l.Verb != "backup" && l.Verb != "export" {
			continue
		}
		n++
		if !slices.ContainsFunc(Rows(l.Key), func(r TierRow) bool { return r.When.zero() && r.Dynamic == "" }) {
			t.Errorf("%s: writes data out but has no row with no condition", l.Key)
		}
	}
	if n == 0 {
		t.Fatal("no leaf writes data out: the check ran over nothing")
	}
	want := map[Key]Tier{
		{Type: "database", Provider: "postgres", Verb: "backup"}: Read,
		top("export"):                       Read,
		own("audit", "recording", "export"): Person, // a recording holds what was typed, secrets included (chief, 2026-11-25)
		own("audit", "", "export"):          Change,
	}
	for k, w := range want {
		if got := Base(k); got != w {
			t.Errorf("Base(%s) = %d, want %d", k, got, w)
		}
	}
	if got := Highest(top("export")); got != Person {
		t.Errorf("Highest(export) = %d, want person (--sealed, --for-phone)", got)
	}
}
