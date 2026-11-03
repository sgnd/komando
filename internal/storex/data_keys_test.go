package storex

import (
	"testing"

	"github.com/sgnd/komando/internal/out"
)

func TestFolderMarkers(t *testing.T) {
	cases := []struct {
		key, listed string
		recursive   bool
		want        bool
	}{
		{"e2e/tree/", "e2e/tree/", true, true},     // the folder's own marker
		{"e2e/tree/sub/", "e2e/tree/", true, true}, // a marker below it
		{"e2e/tree/a.txt", "e2e/tree/", true, false},
		{"e2e/tree/", "e2e/tree/", false, true},
		{"e2e/tree/sub/", "e2e/tree/", false, false}, // a folder of this level
	}
	for _, c := range cases {
		if got := isMarker(c.key, c.listed, c.recursive); got != c.want {
			t.Errorf("%+v: got %v", c, got)
		}
	}
}

func TestContentDisposition(t *testing.T) {
	if got := contentDisposition("rapor ü\"q.pdf"); got != `attachment; filename="rapor __q.pdf"; filename*=UTF-8''rapor%20%C3%BC%22q.pdf` {
		t.Errorf("got %s", got)
	}
}

func TestCheckKeyAndFolderError(t *testing.T) {
	if CheckKey("../escape.txt") == nil || CheckKey("") == nil || CheckKey("a/b.txt") != nil {
		t.Error("CheckKey")
	}
	if e := FolderNotFound("x/").(*out.Error); e.Exit != out.ExitNotFound {
		t.Errorf("exit %d", e.Exit)
	}
}
