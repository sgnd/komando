package cli

import (
	"slices"
	"testing"

	"github.com/sgnd/komando/internal/capability"
)

// Until the cut, today's tier rows (riskRows) and the v2.7 rows of
// internal/capability are two tables of two trees. TestLeafNotWeaker ties
// them: every v2.7 leaf is at least as strict as each command of today it
// carries, so the cut, which switches to the v2.7 rows, cannot lower a
// tier. A leaf may be weaker only where notWeakerExceptions says why.

// notWeakerExceptions are "leaf key | today ID" pairs with the reason the
// leaf may stay below today's highest row.
var notWeakerExceptions = map[string]string{}

func TestTierScalesMatch(t *testing.T) {
	pairs := []struct {
		today tier
		v27   capability.Tier
	}{{tierRead, capability.Read}, {tierChange, capability.Change}, {tierProtected, capability.Protected},
		{tierDangerous, capability.Dangerous}, {tierSafety, capability.Safety}, {tierPerson, capability.Person}}
	for _, p := range pairs {
		if int(p.today) != int(p.v27) {
			t.Errorf("tier %d of today is %d in internal/capability: the two scales must match", p.today, p.v27)
		}
	}
}

func TestLeafNotWeaker(t *testing.T) {
	for _, l := range capability.All() {
		got := leafTier(l.Key)
		for _, id := range slices.Concat(l.Today, l.Carries) {
			want := todayTier(cmdKeys[id])
			if int(got) >= int(want) {
				continue
			}
			pair := l.Key.String() + " | " + id
			if _, ok := notWeakerExceptions[pair]; ok {
				continue
			}
			t.Errorf("%s: carries %s, whose highest tier today is %d, but its own highest is %d", l.Key, id, want, got)
		}
	}
	for pair := range notWeakerExceptions {
		if !exceptionUsed(pair) {
			t.Errorf("notWeakerExceptions has %q, which no leaf needs: drop it", pair)
		}
	}
}

// todayTier is the highest tier of today's rows for key, whatever their
// condition.
func todayTier(key safetyKey) tier {
	best := tierRead
	for _, r := range riskRows {
		if r.key == key && r.tier > best {
			best = r.tier
		}
	}
	return best
}

// leafTier is the highest tier of the v2.7 rows that reach k, whatever
// their condition.
func leafTier(k capability.Key) capability.Tier {
	best := capability.Read
	for _, r := range capability.Rows(k) {
		best = max(best, r.Tier)
	}
	return best
}

func exceptionUsed(pair string) bool {
	for _, l := range capability.All() {
		for _, id := range slices.Concat(l.Today, l.Carries) {
			if l.Key.String()+" | "+id == pair && int(leafTier(l.Key)) < int(todayTier(cmdKeys[id])) {
				return true
			}
		}
	}
	return false
}
