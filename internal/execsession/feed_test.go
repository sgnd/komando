package execsession

import "testing"

func TestFeed(t *testing.T) {
	if got, want := Feed(false), `{ [ ! -f "$d/env" ] || { cat "$d/env"; rm -f "$d/env"; }; [ ! -f "$d/in" ] || { cat "$d/in"; rm -f "$d/in"; }; }`; got != want {
		t.Errorf("got %s", got)
	}
	if got, want := Feed(true), `{ cat "$d/pw"; rm -f "$d/pw"; [ ! -f "$d/env" ] || { cat "$d/env"; rm -f "$d/env"; }; [ ! -f "$d/in" ] || { cat "$d/in"; rm -f "$d/in"; }; }`; got != want {
		t.Errorf("got %s", got)
	}
}
