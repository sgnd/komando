package engine

import "testing"

// Reset forgets every answer in place, as a new session starts: the next
// command of the call asks again.
func TestSessionReset(t *testing.T) {
	s := NewSession()
	s.Lock()
	s.SetAsked(true)
	s.SetWhy("why")
	s.SetUnshown("unshown")
	s.SetGaveUp(true)
	s.MarkShown("ssh-keygen")
	s.Unlock()
	s.ApproveSafety("audit off")
	s.ConfirmDanger("rm web1")
	s.SaidNo(true)
	s.Reset()
	if s.Window() != (Window{}) || s.Shown("ssh-keygen") || s.SafetyApproved("audit off") || s.DangerConfirmed("rm web1") || s.PersonSaidNo() {
		t.Fatalf("an answer outlived Reset: %+v", s.Window())
	}
}
