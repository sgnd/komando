package engine

import "sync"

// Session is the state of one call's approvals: what a person allowed in a
// window, what they confirmed at a terminal. One answer covers the call,
// so a call that passes two checks asks once; the next call asks again.
type Session struct {
	mu sync.Mutex
	// a window was asked, and its answer
	asked, allowed bool
	// why there was no yes, for the error hint
	why string
	// why the window could not show the command
	unshown string
	// the actions a window named
	shown map[string]bool
	// the last window closed itself (nobody clicked Deny)
	gaveUp bool

	safetyApproved  map[string]bool // safety changes a person allowed
	dangerConfirmed map[string]bool // destructive actions confirmed by name
	personSaidNo    bool            // a person answered no at a terminal
}

// NewSession is a fresh call's state.
func NewSession() *Session { return &Session{} }

// Reset forgets every answer, as NewSession starts: the next command of
// the call asks again. It locks by itself, so it is safe while other
// goroutines read the session.
func (s *Session) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked, s.allowed, s.why, s.unshown, s.gaveUp = false, false, "", "", false
	s.shown, s.safetyApproved, s.dangerConfirmed, s.personSaidNo = nil, nil, nil, false
}

// Window is a snapshot of the approval window's state.
type Window struct {
	Asked, Allowed bool
	Why, Unshown   string
	GaveUp         bool
}

// Lock and Unlock guard a check that reads and then sets the window state.
func (s *Session) Lock()   { s.mu.Lock() }
func (s *Session) Unlock() { s.mu.Unlock() }

// The accessors below are called with the session locked where a check
// reads and then writes; alone, each is safe by itself.

func (s *Session) Window() Window {
	return Window{s.asked, s.allowed, s.why, s.unshown, s.gaveUp}
}
func (s *Session) SetAsked(allowed bool)   { s.asked, s.allowed = true, allowed }
func (s *Session) SetAllowed(allowed bool) { s.allowed = allowed }
func (s *Session) SetWhy(why string)       { s.why = why }
func (s *Session) SetUnshown(why string)   { s.unshown = why }
func (s *Session) SetGaveUp(g bool)        { s.gaveUp = g }
func (s *Session) GaveUp() bool            { return s.gaveUp }

// Shown reports whether a window already named what.
func (s *Session) Shown(what string) bool { return s.shown[what] }

// MarkShown records that a window named what.
func (s *Session) MarkShown(what string) {
	if s.shown == nil {
		s.shown = map[string]bool{}
	}
	s.shown[what] = true
}

// Allowed reports a yes in the window, locking by itself.
func (s *Session) Allowed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allowed
}

// SafetyApproved and its setter: a safety change a person allowed.
func (s *Session) SafetyApproved(what string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.safetyApproved[what]
}
func (s *Session) ApproveSafety(what string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.safetyApproved == nil {
		s.safetyApproved = map[string]bool{}
	}
	s.safetyApproved[what] = true
}

// DangerConfirmed and its setter: a destructive action a person confirmed
// by typing its name.
func (s *Session) DangerConfirmed(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dangerConfirmed[key]
}
func (s *Session) ConfirmDanger(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dangerConfirmed == nil {
		s.dangerConfirmed = map[string]bool{}
	}
	s.dangerConfirmed[key] = true
}

// PersonSaidNo and its setter: a person answered no at a terminal, so the
// stop that follows is their decision, not something to retry.
func (s *Session) PersonSaidNo() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.personSaidNo
}
func (s *Session) SaidNo(no bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.personSaidNo = s.personSaidNo || no
}
