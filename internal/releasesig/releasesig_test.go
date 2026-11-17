package releasesig

import (
	"errors"
	"strings"
	"testing"
)

func testKey(t *testing.T) (pub, priv string) {
	t.Helper()
	pub, priv, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	saved := Keys
	Keys = []string{pub}
	t.Cleanup(func() { Keys = saved })
	return pub, priv
}

func sign(t *testing.T, priv, sums string) string {
	t.Helper()
	line, err := Sign(priv, []byte(sums))
	if err != nil {
		t.Fatal(err)
	}
	return line
}

const sums = "abc123  komando_linux_amd64.tar.gz\n"

func TestVerify(t *testing.T) {
	pub, priv := testKey(t)
	_, other, _ := NewKey()
	good := sign(t, priv, sums)
	for _, c := range []struct {
		name, sums, sig string
		want            error
	}{
		{"good signature", sums, good, nil},
		{"good signature, Windows line ends", sums, strings.TrimSuffix(good, "\n") + "\r\n", nil},
		{"signed by another key", sums, sign(t, other, sums), ErrBadSignature},
		{"checksums.txt changed after signing", sums + "def456  komando_extra.tar.gz\n", good, ErrBadSignature},
		{"one signature of two is ours", sums, sign(t, other, sums) + good, nil},
		{"missing signature", sums, "", ErrNotSigned},
		{"not a signature", sums, "hello\n", ErrNotSigned},
		{"a key, not a signature", sums, pub + "\n", ErrNotSigned},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := Verify([]byte(c.sums), []byte(c.sig)); !errors.Is(err, c.want) {
				t.Errorf("Verify = %v, want %v", err, c.want)
			}
		})
	}
}

func TestVerifyNeedsAGoodBuiltInKey(t *testing.T) {
	_, priv := testKey(t)
	sig := []byte(sign(t, priv, sums))
	Keys = nil
	if err := Verify([]byte(sums), sig); !errors.Is(err, ErrNoKeys) {
		t.Errorf("no keys: %v", err)
	}
	Keys = []string{"not base64!"}
	if err := Verify([]byte(sums), sig); err == nil || !strings.Contains(err.Error(), "not a base64 Ed25519 key") {
		t.Errorf("bad key: %v", err)
	}
}

func TestKeys(t *testing.T) {
	pub, priv := testKey(t)
	if got, err := PublicOf(priv + "\n"); err != nil || got != pub {
		t.Errorf("PublicOf = %q, %v; want %q", got, err, pub)
	}
	for _, bad := range []string{"", "short", pub + pub} {
		if _, err := PublicOf(bad); err == nil {
			t.Errorf("PublicOf(%q) took it", bad)
		}
		if _, err := Sign(bad, []byte(sums)); err == nil {
			t.Errorf("Sign with %q worked", bad)
		}
	}
	// the keys built into komando are well formed
	if _, err := publicKeys(Keys); err != nil {
		t.Error(err)
	}
}
