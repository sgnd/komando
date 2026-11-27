package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// devicePub writes a phone's public key file, named komando-phone-anna.
func devicePub(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "komando-phone-anna.pub")
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " komando-phone-anna\n"
	if err := os.WriteFile(p, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestDeviceKeyChecksFirst pins C372's order: every value is checked by
// komando before anything else, then only a person at a terminal goes on.
// Mutant: dropping the NEEDS_PERSON stop lets the script reach the
// inventory (HOST_NOT_FOUND), which turns the last lines red.
func TestDeviceKeyChecksFirst(t *testing.T) {
	invHome(t)
	good := devicePub(t)
	priv := filepath.Join(t.TempDir(), "id")
	if err := os.WriteFile(priv, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dev := []string{"key", "deploy", "web1", "--user", "anna", "--public-key-file", good}
	for _, c := range []struct {
		args []string
		code string
	}{
		{[]string{"key", "deploy", "web1", "--user", "anna"}, "USAGE"},
		{[]string{"key", "deploy", "web1", "--public-key-file", good}, "USAGE"},
		{[]string{"key", "deploy", "web1", "--user", "root;id", "--public-key-file", good}, "USAGE"},
		{[]string{"key", "deploy", "web1", "--user", "-x", "--public-key-file", good}, "USAGE"},
		{append(dev[:len(dev):len(dev)], "--from-address", `10.0.0.1",command="/bin/sh`), "USAGE"},
		{append(dev[:len(dev):len(dev)], "--from-address", "10.0.0.1 10.0.0.2"), "USAGE"},
		{append(dev[:len(dev):len(dev)], "--set-default"), "USAGE"},
		{[]string{"key", "deploy", "k", "web1", "--user", "anna", "--public-key-file", good}, "USAGE"},
		{[]string{"key", "deploy", "web1", "--user", "anna", "--public-key-file", priv}, "KEY_INVALID"},
		{dev, "NEEDS_PERSON"}, // a script
	} {
		if _, e := invRun(t, c.args...); e == nil || e.Code != c.code {
			t.Errorf("%q: %+v, want %s", c.args, e, c.code)
		}
	}
	setCallerEnv(t, "CLAUDECODE", "1")
	if _, e := invRun(t, dev...); e == nil || e.Code != "NEEDS_PERSON" {
		t.Errorf("an agent installed a device's key: %+v", e)
	}
}

// TestDeviceKeyTier: the --public-key-file form is person tier in every
// spelling; key deploy without it stays as it was. The ssh gate on the
// komando computer refuses the form for every key.
func TestDeviceKeyTier(t *testing.T) {
	invHome(t)
	gateInventory(t)
	for line, want := range map[string]tier{
		"key deploy web1 --user anna --public-key-file k.pub": tierPerson,
		"key deploy web1 --user anna --public-key-file=k.pub": tierPerson,
		"key deploy k.pub web1":                               tierChange,
	} {
		if got := riskOfLine(strings.Fields(line)).tier; got != want {
			t.Errorf("%s: %s, want %s", line, got, want)
		}
	}
	if code := gateAnswer(t, "komando key deploy web --user anna --public-key-file /tmp/k.pub", false); code != "SSH_GATE_REFUSED" {
		t.Errorf("the gate lets a key install a device's key: %s", code)
	}
}
