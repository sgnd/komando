package cli

import (
	"slices"
	"testing"
)

// These tests pin what the two sorted-keys helpers give, and the two places
// that return their result, before the helpers are replaced by the
// standard library. The tests of the helpers themselves go with them; the
// tests of the callers stay.

func TestMapKeysAndSortedKeysAreSorted(t *testing.T) {
	m := map[string]int{"web2": 2, "db": 1, "Web1": 3, "": 4, "web10": 5}
	want := []string{"", "Web1", "db", "web10", "web2"}
	if got := mapKeys(m); !slices.Equal(got, want) {
		t.Errorf("mapKeys = %q, want %q", got, want)
	}
	if got := sortedKeys(m); !slices.Equal(got, want) {
		t.Errorf("sortedKeys = %q, want %q", got, want)
	}
}

func TestMapKeysAndSortedKeysOfAnEmptyMap(t *testing.T) {
	for name, m := range map[string]map[string]bool{"empty": {}, "nil": nil} {
		if got := mapKeys(m); len(got) != 0 {
			t.Errorf("mapKeys of a %s map = %q, want nothing", name, got)
		}
		if got := sortedKeys(m); len(got) != 0 {
			t.Errorf("sortedKeys of a %s map = %q, want nothing", name, got)
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
