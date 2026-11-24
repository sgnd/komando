package cli

import (
	"maps"
	"slices"
	"testing"
)

// The commands list names in sorted order with slices.Sorted(maps.Keys(m)).
// The first test states what that gives where it matters (an empty or nil
// map gives nothing to range over); the others cover the two places that
// return such a list.

func TestSortedKeysFromTheStandardLibrary(t *testing.T) {
	m := map[string]int{"web2": 2, "db": 1, "Web1": 3, "": 4, "web10": 5}
	want := []string{"", "Web1", "db", "web10", "web2"}
	if got := slices.Sorted(maps.Keys(m)); !slices.Equal(got, want) {
		t.Errorf("sorted keys = %q, want %q", got, want)
	}
	for name, e := range map[string]map[string]bool{"empty": {}, "nil": nil} {
		if got := slices.Sorted(maps.Keys(e)); len(got) != 0 {
			t.Errorf("sorted keys of a %s map = %q, want nothing", name, got)
		}
	}
}

// sortedStrings is one of the two places that return a helper's result: a
// sorted list without repeats, joined into a line of text.
func TestSortedStrings(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"sorted without repeats", []string{"b", "a", "b", "c"}, []string{"a", "b", "c"}},
		{"nothing in, nothing out", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sortedStrings(tt.in); !slices.Equal(got, tt.want) {
				t.Errorf("sortedStrings(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// kindValues is the other: the words a completion offers for a kind.
func TestKindValuesAreSortedAndComplete(t *testing.T) {
	got := kindValues()
	if !slices.IsSorted(got) {
		t.Errorf("kindValues is not sorted: %q", got)
	}
	for _, want := range []string{"kind:host", "kind:conn", "kind:vpn", "kind:postgres"} {
		if !slices.Contains(got, want) {
			t.Errorf("kindValues has no %q", want)
		}
	}
	if len(slices.Compact(slices.Clone(got))) != len(got) {
		t.Errorf("kindValues repeats a word: %q", got)
	}
}
