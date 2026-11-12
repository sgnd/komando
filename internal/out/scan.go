package out

import "bytes"

// ValueScanner watches bytes written to it for a vault value (as is, or
// in the base64 and URL forms Redact also hides), across write edges. It
// is for data that cannot be rewritten with [secret:NAME] (a binary file),
// so it can be stopped instead.
type ValueScanner struct {
	vals  [][]byte
	tail  []byte
	keep  int
	found bool
}

// NewValueScanner watches for p's secret values; with none, it finds nothing.
func (p *Printer) NewValueScanner() *ValueScanner {
	p.load()
	s := &ValueScanner{}
	for _, h := range p.hide {
		s.vals = append(s.vals, []byte(h.raw))
		if len(h.raw) > s.keep {
			s.keep = len(h.raw)
		}
	}
	return s
}

// Write never fails.
func (s *ValueScanner) Write(b []byte) (int, error) {
	if s.found || len(s.vals) == 0 {
		return len(b), nil
	}
	buf := append(s.tail, b...)
	for _, v := range s.vals {
		if bytes.Contains(buf, v) {
			s.found = true
			return len(b), nil
		}
	}
	if len(buf) >= s.keep {
		buf = buf[len(buf)-s.keep+1:]
	}
	s.tail = append(s.tail[:0], buf...)
	return len(b), nil
}

// Found reports whether a value was seen.
func (s *ValueScanner) Found() bool { return s.found }
