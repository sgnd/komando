package cli

import (
	"reflect"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// One code, one next step (C79): the codes that meant several things are
// split, the codes that meant one thing are merged, and none of the old
// names is left anywhere a command can give it (no aliases).
var retiredCodes = []string{
	"PROTECTED_HOST", "CONNECT_FAILED",
	"K8S_UNREACHABLE", "REGISTRY_UNREACHABLE", "WINRM_UNREACHABLE", "RELEASES_UNREACHABLE",
	"HOST_NOT_FOUND", "CONN_NOT_FOUND", "VPN_NOT_FOUND",
	"KEY_NOT_FOUND", "NOT_FOUND", "REGISTRY_NOT_FOUND", "CONTAINER_NOT_FOUND",
	"FAILED", "REVEAL_NEEDS_HUMAN",
}

// newCodes each give one of the things a retired or two-exit code gave.
var newCodes = map[string]int{
	"SSH_KEY_NOT_FOUND": 3, "CACHE_KEY_NOT_FOUND": 3,
	"SWARM_SERVICE_NOT_FOUND": 3, "SWARM_STACK_NOT_FOUND": 3, "SWARM_OBJECT_NOT_FOUND": 3,
	"DOCKER_OBJECT_NOT_FOUND": 3, "CACHE_SECTION_NOT_FOUND": 3,
	"REPOSITORY_NOT_FOUND": 3, "IMAGE_TAG_NOT_FOUND": 3,
	"K8S_POD_NOT_FOUND": 3, "K8S_CONTAINER_NOT_FOUND": 3,
	"REVEAL_NEEDS_TERMINAL": 6, "SQL_TX_CHECK_REQUIRED": 6, "SQL_SAFE_SETTINGS_REQUIRED": 6, "REMOTE_WRITE_FAILED": 5,
}

func TestOneCodeEach(t *testing.T) {
	codes, mixed := scanErrorCodes(t)
	got := map[string]int{}
	for _, c := range codes {
		got[c.Code] = c.Exit
	}
	for _, c := range retiredCodes {
		if _, ok := got[c]; ok {
			t.Errorf("%s is retired (C79) but a command still gives it", c)
		}
	}
	for c, exit := range newCodes {
		if e, ok := got[c]; !ok || e != exit {
			t.Errorf("%s: want exit %d, got %d (given: %v)", c, exit, e, ok)
		}
	}
	// every code has one exit: no exceptions left (scanErrorCodes says which)
	for _, m := range mixed {
		t.Error(m)
	}
	// removing codes is a change of the JSON envelope: the contract goes up
	if out.Contract != 2 {
		t.Errorf("meta.contract is %d, want 2", out.Contract)
	}
	// error.thing told shared codes apart; with one code each it is gone
	if _, ok := reflect.TypeOf(out.Error{}).FieldByName("Thing"); ok {
		t.Error("out.Error still has Thing (error.thing)")
	}
}
