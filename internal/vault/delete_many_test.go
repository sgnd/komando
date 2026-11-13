package vault

import (
	"errors"
	"strings"
	"testing"
)

// DeleteMany removes every name in one change, or none when one is missing.
func TestDeleteManyAllOrNone(t *testing.T) {
	keyfileHome(t)
	for _, n := range []string{"a", "b", "c"} {
		if err := Set(n, "v-"+n); err != nil {
			t.Fatal(err)
		}
	}
	err := DeleteMany([]string{"a", "gone", "b"})
	if !errors.Is(err, ErrNotFound) || !strings.HasSuffix(err.Error(), ": gone") {
		t.Fatalf("err %v", err)
	}
	for _, n := range []string{"a", "b"} {
		if _, err := Get(n); err != nil {
			t.Errorf("%s was removed although another name was missing: %v", n, err)
		}
	}
	if err := DeleteMany([]string{"a", "b"}); err != nil {
		t.Fatal(err)
	}
	l, _ := List()
	if len(l) != 1 || l[0].Name != "c" {
		t.Errorf("left %v", l)
	}
}
