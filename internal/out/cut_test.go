package out

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// A list cut at --limit sets meta.truncated; text mode says it on stderr
// once, unless the command's own text says it (CutNoted).
func TestCutTruncated(t *testing.T) {
	var buf bytes.Buffer
	p := &Printer{Format: "json", W: &buf}
	p.Cut(20)
	p.Print("x", []string{"a"}, nil)
	var env Envelope
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil || !env.Meta.Truncated {
		t.Fatalf("meta.truncated not set: %s", buf.String())
	}
	p.Reset()
	buf.Reset()
	p.Print("x", []string{"a"}, nil)
	if strings.Contains(buf.String(), "truncated") {
		t.Fatalf("Reset keeps the cut: %s", buf.String())
	}

	p = &Printer{Format: "text", W: &buf}
	p.Cut(20)
	if got := captureStderr(t, func() { p.Print("x", []string{"a"}, nil) }); !strings.Contains(got, "showing 20 of more; use --limit 0 for all") {
		t.Errorf("text stderr: %q", got)
	}
	p = &Printer{Format: "text", W: &buf}
	p.CutNoted()
	if got := captureStderr(t, func() { p.Print("x", []string{"a"}, nil) }); strings.Contains(got, "showing") {
		t.Errorf("CutNoted printed a second note: %q", got)
	}
}
