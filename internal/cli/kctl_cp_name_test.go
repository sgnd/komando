package cli

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// C04: a copy from a pod of a file named like a secret stops before the
// pod is asked for anything, as download stops before it reads (the
// client is nil here: any read from the pod would panic).
func TestPodCopyNameCheckedFirst(t *testing.T) {
	invHome(t)
	asAgent(t, false, false)
	dst := filepath.Join(t.TempDir(), "x")
	for _, src := range []string{"web-1:/srv/app/.env", "shop/web-1:/root/.ssh/id_ed25519"} {
		r := &kctlRun{cl: tcl, ctx: context.Background(), a: kargs{verb: "cp", pos: []string{src, dst}}}
		var err error
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("%s: the pod was read before the name was checked", src)
				}
			}()
			err = r.cp()
		}()
		var ke *kctlError
		if t.Failed() {
			continue
		}
		if !errors.As(err, &ke) || ke.stop == nil || ke.stop.Code != "SENSITIVE_FILE" {
			t.Errorf("%s: want SENSITIVE_FILE, got %v", src, err)
		}
	}
}
