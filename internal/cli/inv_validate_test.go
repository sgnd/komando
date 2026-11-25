package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sgnd/komando/internal/inventory"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
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

// The inventory's address rules, as today's code gives them: a conn's
// resource key, a host name as DNS compares it, an IP that needs no lookup,
// and ~ in a local path.
func TestInventoryAddressRules(t *testing.T) {
	for url, want := range map[string]string{
		"postgres://app@DB.Example.:5432/app": "db db.example:5432",
		"postgres://app@[::1]:5432/app":       "db [::1]:5432",
		"s3://key@S3.Example.com/bucket-a":    "bucket s3.amazonaws.com:443/S3.Example.com",
		"sqlite:///tmp/app.db":                "file /tmp/app.db",
		"redis://Cache.Local.:6379":           "cache cache.local:6379",
		"bad url %%":                          "",
	} {
		if got := connAddrKey(&store.Conn{URL: url}); got != want {
			t.Errorf("connAddrKey(%q) = %q, want %q", url, got, want)
		}
	}
	for in, want := range map[string]string{" Target. ": "target", "[::1]": "::1", "Host.Example.COM": "host.example.com", "10.0.0.1": "10.0.0.1"} {
		if got := normAddr(in); got != want {
			t.Errorf("normAddr(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"[::1]": "::1", " 10.0.0.1 ": "10.0.0.1"} {
		if got := lookupIPs(context.Background(), in); len(got) != 1 || got[0] != want {
			t.Errorf("lookupIPs(%q) = %q, want [%s]", in, got, want)
		}
	}
	home, _ := os.UserHomeDir()
	for in, want := range map[string]string{"~/x/y": filepath.Join(home, "x", "y"), "/abs": "/abs", "~user/x": "~user/x"} {
		if got := expandHome(in); got != want {
			t.Errorf("expandHome(%q) = %q, want %q", in, got, want)
		}
	}
}
