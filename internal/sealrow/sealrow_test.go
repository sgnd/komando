package sealrow

import (
	"bytes"
	"errors"
	"testing"
)

func testKey(t *testing.T, fill byte) *Key {
	t.Helper()
	k, err := NewKey(bytes.Repeat([]byte{fill}, MasterLen))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRoundTrip(t *testing.T) {
	k := testKey(t, 1)
	r := Row{ID: "a1", Type: "server", Version: 3}
	for _, plain := range [][]byte{nil, []byte("web-1"), bytes.Repeat([]byte("x"), 1<<16)} {
		s, err := k.Seal(r, plain)
		if err != nil {
			t.Fatal(err)
		}
		got, err := k.Open(r, s)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("got %q", got)
		}
	}
}

func TestPlainNotVisible(t *testing.T) {
	k := testKey(t, 1)
	s, _ := k.Seal(Row{ID: "a", Type: "server", Version: 1}, []byte("prod-db.example.com"))
	if bytes.Contains(s, []byte("prod-db")) {
		t.Fatal("name readable in sealed row")
	}
}

func TestSealIsRandomized(t *testing.T) {
	k := testKey(t, 1)
	r := Row{ID: "a", Type: "server", Version: 1}
	a, _ := k.Seal(r, []byte("same"))
	b, _ := k.Seal(r, []byte("same"))
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same row are equal")
	}
}

func TestMovedRowDoesNotOpen(t *testing.T) {
	k := testKey(t, 1)
	r := Row{ID: "a", Type: "server", Version: 2}
	s, _ := k.Seal(r, []byte("v"))
	for _, moved := range []Row{
		{ID: "b", Type: "server", Version: 2},
		{ID: "a", Type: "secret", Version: 2},
		{ID: "a", Type: "server", Version: 1},
		{ID: "as", Type: "erver", Version: 2}, // length prefix
	} {
		if _, err := k.Open(moved, s); !errors.Is(err, ErrOpen) {
			t.Fatalf("%+v: err %v, want ErrOpen", moved, err)
		}
	}
}

func TestWrongKeyAndDamage(t *testing.T) {
	r := Row{ID: "a", Type: "server", Version: 1}
	s, _ := testKey(t, 1).Seal(r, []byte("v"))
	if _, err := testKey(t, 2).Open(r, s); !errors.Is(err, ErrOpen) {
		t.Fatalf("other key: %v", err)
	}
	k := testKey(t, 1)
	for i := range s {
		d := bytes.Clone(s)
		d[i] ^= 1
		if _, err := k.Open(r, d); err == nil {
			t.Fatalf("flip at %d opened", i)
		}
	}
	for _, short := range [][]byte{nil, s[:1], s[:2], s[:20]} {
		if _, err := k.Open(r, short); !errors.Is(err, ErrOpen) {
			t.Fatalf("short %d: %v", len(short), err)
		}
	}
}

func TestNewerFormat(t *testing.T) {
	k := testKey(t, 1)
	r := Row{ID: "a", Type: "server", Version: 1}
	s, _ := k.Seal(r, []byte("v"))
	for _, h := range [][2]byte{{Format + 1, SuiteAESGCM}, {Format, SuiteAESGCM + 1}} {
		d := bytes.Clone(s)
		d[0], d[1] = h[0], h[1]
		if _, err := k.Open(r, d); !errors.Is(err, ErrNewerFormat) {
			t.Fatalf("%v: %v", h, err)
		}
	}
	d := bytes.Clone(s)
	d[0] = 0
	if _, err := k.Open(r, d); !errors.Is(err, ErrOpen) {
		t.Fatalf("format 0: %v", err)
	}
}

func TestBadInput(t *testing.T) {
	if _, err := NewKey(make([]byte, 16)); err == nil {
		t.Fatal("short master key accepted")
	}
	k := testKey(t, 1)
	if _, err := k.Seal(Row{Type: "server"}, nil); err == nil {
		t.Fatal("empty ID accepted")
	}
	if _, err := k.Seal(Row{ID: "a"}, nil); err == nil {
		t.Fatal("empty type accepted")
	}
}

func TestNewID(t *testing.T) {
	a, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewID()
	if len(a) != 32 || a == b {
		t.Fatalf("ids %q %q", a, b)
	}
}

func FuzzOpen(f *testing.F) {
	k, _ := NewKey(bytes.Repeat([]byte{1}, MasterLen))
	r := Row{ID: "a", Type: "server", Version: 1}
	s, _ := k.Seal(r, []byte("seed"))
	f.Add(s)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = k.Open(r, b) // must not panic
	})
}
