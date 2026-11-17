package out

import (
	"fmt"
	"slices"
)

// Need records flags the real run needs besides the one this stop's code
// names, e.g. --yes on a protected target for a POLICY_BLOCKED stop.
func (e *Error) Need(flags ...string) *Error { e.need = append(e.need, flags...); return e }

// Flags are every flag the real run needs, from this stop's code and
// Need, sorted; none for a stop no flag lifts.
func (e *Error) Flags() []string {
	f := ApprovalFlag(e)
	if f == "" {
		return nil
	}
	res := []string{f}
	for _, n := range e.need {
		if !slices.Contains(res, n) {
			res = append(res, n)
		}
	}
	slices.Sort(res)
	return res
}

// Cut records that a list stopped at --limit n (meta.truncated). In text
// mode one line on stderr says so after the result.
func (p *Printer) Cut(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cut = true
	if n > p.cutAt {
		p.cutAt = n
	}
}

// CutNoted is Cut for a command whose own text already says the list was
// cut: meta.truncated only, no extra stderr line.
func (p *Printer) CutNoted() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cut, p.cutNoted = true, true
}

// printCut tells a person, on stderr, that a list stopped at --limit.
func (p *Printer) printCut() {
	p.mu.Lock()
	cut, noted, n := p.cut, p.cutNoted, p.cutAt
	p.mu.Unlock()
	if cut && !noted && n > 0 {
		fmt.Fprintf(p.Stderr(), "Note: showing the first %d; --limit 0 shows all\n", n)
	}
}
