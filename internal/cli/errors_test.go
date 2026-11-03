package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

func TestLocalFileErr(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.txt")
	_, err := os.ReadFile(missing)
	e := localFileErr("FILE_NOT_FOUND", err, "")
	if e.Message != missing+" does not exist on this computer" || e.Hint == "" || e.Exit != out.ExitNotFound {
		t.Fatalf("got %+v", e)
	}
	if e := localFileErr("FILE_NOT_FOUND", err, "give the backup's path"); e.Hint != "give the backup's path" {
		t.Fatalf("hint not kept: %+v", e)
	}
	// an untyped file error is a problem on this computer, not REMOTE_ERROR
	if e := toErr(err); e.Code != "FILE_ERROR" || strings.Contains(e.Message, "no such file") {
		t.Fatalf("toErr: %+v", e)
	}
}

func TestWithHost(t *testing.T) {
	for msg, want := range map[string]string{
		"no authentication method available for web1": "no authentication method available for web1",
		"web1: connection refused":                    "web1: connection refused",
		"connection refused":                          "web1: connection refused",
		"web10 is down":                               "web1: web10 is down",
	} {
		if got := withHost("web1", msg); got != want {
			t.Errorf("withHost(%q) = %q, want %q", msg, got, want)
		}
	}
}

func TestColonHint(t *testing.T) {
	// a missing local file keeps its own hint: the colon is not the problem
	path := localFileErr("PATH_NOT_FOUND", &os.PathError{Op: "stat", Path: "./a", Err: os.ErrNotExist}, "")
	if e := toErr(colonHint(path, "web1:/tmp/")); strings.Contains(e.Hint, "./web1") {
		t.Fatalf("hint about the wrong argument: %q", e.Hint)
	}
	// an unknown target with a colon may be a local file name
	e := toErr(colonHint(out.Errf(out.ExitNotFound, "HOST_NOT_FOUND", "run `komando list`", "no server named %q", "a"), "a:b"))
	if !strings.HasPrefix(e.Hint, "if a:b is a file on this computer, write it as ./a:b; otherwise run") {
		t.Fatalf("hint: %q", e.Hint)
	}
	e = toErr(colonHint(&out.Error{Code: "TARGET_EMPTY", Exit: out.ExitNotFound}, "a:b"))
	if strings.HasSuffix(e.Hint, "; ") {
		t.Fatalf("dangling separator: %q", e.Hint)
	}
}
