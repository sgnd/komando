package execsession

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

func TestNewID(t *testing.T) {
	pattern := regexp.MustCompile(`^[a-z2-7]{52}$`)
	seen := map[string]bool{}
	for range 200 {
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		if !pattern.MatchString(id) {
			t.Fatalf("id %q does not match the pattern", id)
		}
		if seen[id] {
			t.Fatalf("id %q came twice", id)
		}
		seen[id] = true
	}
}

// A failed random read is an error, never a weaker ID.
func TestNewIDRandomFails(t *testing.T) {
	saved := randRead
	randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	t.Cleanup(func() { randRead = saved })
	if id, err := NewID(); err == nil || id != "" {
		t.Fatalf("NewID = %q, %v; want an error and no ID", id, err)
	}
}

func TestCheckID(t *testing.T) {
	good := strings.Repeat("a", 50) + "27"
	if err := CheckID(good); err != nil {
		t.Errorf("%q: %v", good, err)
	}
	for _, bad := range []string{
		"",
		strings.Repeat("a", 51),
		strings.Repeat("a", 53),
		"../" + strings.Repeat("a", 49),
		strings.Repeat("A", 52),
		strings.Repeat("a", 51) + "1",
		strings.Repeat("a", 51) + ";",
		strings.Repeat("a", 51) + "\n",
		strings.Repeat("a", 52) + "\n",
	} {
		err := CheckID(bad)
		var oe *out.Error
		if !errors.As(err, &oe) || oe.Exit != out.ExitUsage {
			t.Errorf("%q: %v, want a usage error", bad, err)
		}
	}
}
