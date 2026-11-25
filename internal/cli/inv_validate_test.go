package cli

import (
	"errors"
	"testing"

	"github.com/sgnd/komando/internal/inventory"
	"github.com/sgnd/komando/internal/out"
)

// The two name checks print the entry that was typed in quotes and say what
// kind of name it cannot be, not the other way round.
func TestInvalidNameMessageNamesTheEntry(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		want string
	}{
		{"validName", inventory.ValidName("host", "bad name"), `"bad name" cannot be a host name: use letters, digits and . _ - (at most 63)`},
		{"validLabelName", inventory.ValidLabelName("group", "bad name"), `"bad name" cannot be a group name`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var e *out.Error
			if !errors.As(tt.err, &e) {
				t.Fatalf("got %v, want an *out.Error", tt.err)
			}
			if e.Message != tt.want {
				t.Errorf("message = %q, want %q", e.Message, tt.want)
			}
		})
	}
}
