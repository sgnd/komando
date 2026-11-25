package execsession

import (
	"strings"
	"testing"
)

func hideTok(s string) string { return strings.ReplaceAll(s, "tok123", "[hidden]") }

func TestLinesReleasesWholeLines(t *testing.T) {
	l := Lines{Redact: hideTok}
	text, used := l.Read([]byte("one tok123\ntwo tok"), false)
	if text != "one [hidden]\n" || used != len("one tok123\n") {
		t.Fatalf("got %q, %d", text, used)
	}
	// the next read starts at a line start, so the split token is whole
	text, used = l.Read([]byte("two tok123\n"), false)
	if text != "two [hidden]\n" || used != 11 {
		t.Fatalf("got %q, %d", text, used)
	}
}

func TestLinesEndReleasesTheLastLine(t *testing.T) {
	l := Lines{Redact: hideTok}
	text, used := l.Read([]byte("a\nlast tok123"), true)
	if text != "a\nlast [hidden]" || used != 13 {
		t.Fatalf("got %q, %d", text, used)
	}
}

const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"

func TestLinesHoldsAnOpenKey(t *testing.T) {
	l := Lines{Redact: hideTok}
	half := "x\n" + pem[:45]
	text, used := l.Read([]byte(half), false)
	if text != "x\n" || used != 2 {
		t.Fatalf("an open key was let out: %q, %d", text, used)
	}
	text, used = l.Read([]byte(pem+"y\n"), false)
	if text != pem+"y\n" || used != len(pem)+2 {
		t.Fatalf("got %q, %d", text, used)
	}
}

func TestLinesHidesAKeyLeftOpenAtTheEnd(t *testing.T) {
	l := Lines{Redact: hideTok}
	text, _ := l.Read([]byte("x\n"+pem[:45]), true)
	if strings.Contains(text, "AAAA") || !strings.Contains(text, "[hidden: private key]") {
		t.Fatalf("got %q", text)
	}
}

func TestLinesHidesAKeyLongerThanARead(t *testing.T) {
	l := Lines{Redact: hideTok}
	body := pem[:36] + strings.Repeat("QUFB\n", ReadMax/5+1)
	text, used := l.Read([]byte(body[:ReadMax]), false)
	if text != "[hidden: private key]\n" || used != ReadMax {
		t.Fatalf("got %q, %d", text, used)
	}
	rest := "QUFB\n-----END OPENSSH PRIVATE KEY-----\nafter\n"
	text, used = l.Read([]byte(rest), false)
	if text != "after\n" || used != len(rest) {
		t.Fatalf("the rest of the key showed: %q, %d", text, used)
	}
}

func TestLinesLongLineForAnAgent(t *testing.T) {
	long := strings.Repeat("z", LineMax+1)
	l := Lines{Redact: hideTok, Agent: true}
	text, used := l.Read([]byte(long+"\nok\n"), false)
	if text != "[hidden: a line over 64 KiB]\nok\n" || used != len(long)+4 {
		t.Fatalf("got %q, %d", text[:min(len(text), 80)], used)
	}
	// a long line cut by the read size: the rest is dropped up to its end
	l = Lines{Redact: hideTok, Agent: true}
	text, used = l.Read([]byte(long), false)
	if text != "[hidden: a line over 64 KiB]\n" || used != len(long) {
		t.Fatalf("got %q, %d", text[:min(len(text), 80)], used)
	}
	text, used = l.Read([]byte("zzz\nnext\n"), false)
	if text != "next\n" || used != 9 {
		t.Fatalf("got %q, %d", text, used)
	}
}

func TestLinesLongLineForAPerson(t *testing.T) {
	// a line that fills a whole read is hidden for a person too: masked
	// per read, a token across the cut would come out whole
	long := strings.Repeat("z", ReadMax-3) + "tok"
	l := Lines{Redact: hideTok}
	text, used := l.Read([]byte(long), false)
	if text != hiddenLongLine || used != ReadMax {
		t.Fatalf("a full read without a newline: %q, %d", text[:min(len(text), 40)], used)
	}
	if text, used = l.Read([]byte("123 rest\nnext\n"), false); text != "next\n" || used != 14 {
		t.Fatalf("the rest of the line: %q, %d", text, used)
	}
	short := Lines{Redact: hideTok}
	line := strings.Repeat("y", LineMax+1) + "\n"
	if text, _ := short.Read([]byte(line), false); text != line {
		t.Fatal("a person's line under a read is shown")
	}
}

// next_from stays at the start of a line while a hidden line or key runs
// on: a read from there hides it again.
func TestLinesOpenKeepsTheLineStart(t *testing.T) {
	long := strings.Repeat("z", LineMax+1)
	l := Lines{Redact: hideTok, Agent: true}
	_, used := l.Read([]byte("ok\n"+long), false)
	if used != 3+len(long) || l.Open() != len(long) {
		t.Fatalf("used %d, open %d", used, l.Open())
	}
	l.Read([]byte("zz"), false)
	if l.Open() != len(long)+2 {
		t.Fatalf("open %d after the line ran on", l.Open())
	}
	if _, used = l.Read([]byte("z\nnext\n"), false); used != 7 || l.Open() != 0 {
		t.Fatalf("used %d, open %d after the line ended", used, l.Open())
	}
	k := Lines{Redact: hideTok}
	body := pem[:36] + strings.Repeat("QUFB\n", ReadMax/5+1)
	k.Read([]byte(body[:ReadMax]), false)
	if k.Open() != ReadMax {
		t.Fatalf("open %d inside a hidden key", k.Open())
	}
}
