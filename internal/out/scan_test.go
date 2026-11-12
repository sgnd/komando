package out

import (
	"encoding/base64"
	"testing"
)

func TestValueScanner(t *testing.T) {
	p := &Printer{Secrets: func() map[string]string { return map[string]string{"db": "hunter2-long"} }}
	for _, chunks := range [][]string{
		{"\x00abc hunter2-long xyz"},
		{"\x00abc hunt", "er2-lo", "ng"},
		{"x" + base64.StdEncoding.EncodeToString([]byte("hunter2-long"))},
	} {
		s := p.NewValueScanner()
		for _, c := range chunks {
			_, _ = s.Write([]byte(c))
		}
		if !s.Found() {
			t.Errorf("not found in %q", chunks)
		}
	}
	s := p.NewValueScanner()
	_, _ = s.Write([]byte("hunter2-lon"))
	_, _ = s.Write([]byte("x hunter2"))
	if s.Found() {
		t.Error("found in text without it")
	}
}
