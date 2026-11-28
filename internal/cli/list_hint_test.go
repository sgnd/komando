package cli

import (
	"regexp"
	"strings"
	"testing"
)

// The hint of an empty provider list is that provider's own add.
func TestConnAddHint(t *testing.T) {
	for kind, want := range map[string]string{
		"postgres": "database postgres add NAME URL", "redis": "cache redis add NAME URL",
		"k8s": "cluster kubernetes add NAME URL", "registry": "registry oci add NAME URL",
		"": "TYPE PROVIDER add NAME URL",
	} {
		if got := connAddHint(kind); got != want {
			t.Errorf("%q: %q, want %q", kind, got, want)
		}
	}
}

// Every command the empty inventory tells a person to type is a command.
func TestEmptyInventoryNamesRealCommands(t *testing.T) {
	root := newRoot(tcl)
	found := 0
	for _, m := range regexp.MustCompile(`komando ((?:[a-z0-9]+ ){1,2}add)`).FindAllStringSubmatch(emptyInventory, -1) {
		found++
		if cmdByKey(root, m[1]) == nil {
			t.Errorf("`komando %s` is no command", m[1])
		}
	}
	if found < 5 || strings.Contains(emptyInventory, "komando conn") {
		t.Errorf("%d add commands in: %s", found, emptyInventory)
	}
}
