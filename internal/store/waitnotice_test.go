package store

import (
	"bytes"
	"strings"
	"testing"
)

// The line a person sees on stderr while komando waits for the store.
func TestWaitNoticeLine(t *testing.T) {
	var b bytes.Buffer
	waitNotice(&b)()
	if got := b.String(); !strings.HasPrefix(got, "komando: waiting for another komando process") || !strings.HasSuffix(got, "\n") || strings.Count(got, "\n") != 1 {
		t.Errorf("notice %q", got)
	}
}
