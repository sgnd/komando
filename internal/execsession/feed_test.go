package execsession

import (
	"testing"
	"time"
)

// job start's root process is the same text it was before it moved here.
func TestWrapperKeepsJobText(t *testing.T) {
	if got, want := Wrapper("S", 0), `umask "$1"; S; umask 077; wait $w 2>/dev/null; c=$?; [ -f "$d/killed" ] || echo $c > "$d/exit"; rm -f "$d/env" "$d/in" "$d/pw"`; got != want {
		t.Errorf("no timeout:\n got %s\nwant %s", got, want)
	}
	want := `umask "$1"; S; umask 077; ( trap 'kill $t 2>/dev/null; exit 0' TERM; sleep 61 & t=$!; wait $t; ` +
		`kill -0 $w 2>/dev/null && { printf 'TERM timeout\n' > "$d/killed"; kill -TERM -$$ 2>/dev/null || kill -TERM $w; } ) & s=$!; ` +
		`wait $w 2>/dev/null; c=$?; kill $s 2>/dev/null; [ -f "$d/killed" ] || echo $c > "$d/exit"; rm -f "$d/env" "$d/in" "$d/pw"`
	if got := Wrapper("S", 60*time.Second+time.Millisecond); got != want {
		t.Errorf("timeout 60.001 s:\n got %s\nwant %s", got, want)
	}
}

func TestFeed(t *testing.T) {
	if got, want := Feed(false), `{ [ ! -f "$d/env" ] || { cat "$d/env"; rm -f "$d/env"; }; [ ! -f "$d/in" ] || { cat "$d/in"; rm -f "$d/in"; }; }`; got != want {
		t.Errorf("got %s", got)
	}
	if got, want := Feed(true), `{ cat "$d/pw"; rm -f "$d/pw"; [ ! -f "$d/env" ] || { cat "$d/env"; rm -f "$d/env"; }; [ ! -f "$d/in" ] || { cat "$d/in"; rm -f "$d/in"; }; }`; got != want {
		t.Errorf("got %s", got)
	}
}
