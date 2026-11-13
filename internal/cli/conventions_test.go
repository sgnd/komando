package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
)

// TestConventions checks the naming rules of docs/design/ux.md on every
// command, so a new command cannot drift from them.
func TestConventions(t *testing.T) {
	// one meaning per short flag: TestStandardShorthands (shorthand_test.go)
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		path := c.CommandPath()
		if slices.Contains([]string{"remove", "delete", "del"}, c.Name()) {
			t.Errorf("%s: name it rm (remove, delete and del are aliases)", path)
		}
		if c.Name() == "rm" && !slices.Equal(c.Aliases, rmAliases) {
			t.Errorf("%s: aliases %v, want %v", path, c.Aliases, rmAliases)
		}
		if other, ok := map[string]string{"list": "ls", "ls": "list"}[c.Name()]; ok {
			if !slices.Contains(c.Aliases, other) {
				t.Errorf("%s: aliases %v, want %s too", path, c.Aliases, other)
			}
			if sib, _, err := c.Parent().Find([]string{other}); err == nil && sib != c && sib != c.Parent() {
				t.Errorf("%s: %s is another command here", path, other)
			}
		}
		// every command people run shows one real example (ux.md, section 10)
		if c.Runnable() && !c.HasSubCommands() && !c.Hidden && c.Example == "" && c.Name() != "help" && c.Parent().Name() != "completion" {
			t.Errorf("%s: no example; set Example or add one to examples (help_examples.go)", path)
		}
		if _, ok := examples[path]; ok && c.Annotations[exampleFromTable] == "" {
			t.Errorf("%s: has its own Example; remove it from help_examples.go", path)
		}
		// command lists fit 80 columns: `komando --help` puts a top-level
		// Short at column 15, a sub-command's a little further right
		if limit := map[bool]int{true: 64, false: 72}[c.Parent() == c.Root()]; len(c.Short) > limit {
			t.Errorf("%s: Short is %d characters, over %d; move the detail to Long", path, len(c.Short), limit)
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(newRoot())
}

// genericText are the change commands whose -o text still comes from the
// generic renderer (S-9.7). The list may only shrink: give the command a
// Text method of its own (changeText for one record), then drop it here.
var genericText = []string{}

// S-9.7: every change command that works on komando's own list has its own
// text. Each runs here in -o text (dry runs where a person's yes is
// needed); one that falls back to the generic renderer fails, unless it is
// in genericText.
func TestChangeCommandsOwnText(t *testing.T) {
	invHome(t)
	used := map[string]string{}
	var line string
	out.OnGenericText = func(c string) { used[c] = line }
	defer func() { out.OnGenericText = nil }()
	setSecret(t, "s1", "x")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "")
	pub := filepath.Join(t.TempDir(), "id")
	if err := os.WriteFile(pub, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, a := range [][]string{
		{"host", "add", "web1", "u@10.0.0.1"}, {"host", "edit", "web1", "--port", "2222"}, {"host", "rename", "web1", "web2"},
		{"conn", "add", "app-db", "postgres://app@10.0.0.9/app"}, {"conn", "edit", "app-db", "--notes", "x"}, {"conn", "rename", "app-db", "db2"},
		{"vpn", "add", "office", "socks", "--proxy-address", "10.0.0.1:1080"}, {"vpn", "edit", "office", "--notes", "x"}, {"vpn", "rename", "office", "off2"},
		{"group", "add", "g1", "web2"}, {"group", "rename", "g1", "g2"}, {"group", "rm", "g2", "web2"},
		{"key", "gen", "k1"}, {"key", "add", "k3", pub}, {"key", "rename", "k1", "k2"},
		{"secret", "set", "s4", "--from-env", "PATH"}, {"secret", "rename", "s1", "s2"}, {"secret", "cp", "s2", "s3"},
		{"recipe", "add", "r1", "uptime", "--read-only"}, {"recipe", "rm", "r1"}, {"policy", "deny", "foo bar"},
		{"config", "set", "default_timeout", "5m"}, {"rename", "db2", "db3"}, {"--dry-run", "host", "trust", "web2"},
		{"--dry-run", "export", "--to", filepath.Join(t.TempDir(), "x.json")}, {"--dry-run", "secret", "rm", "s3"},
		{"--dry-run", "seal"}, {"tunnel", "stop", "--all"}, {"host", "rm", "web2"}, {"conn", "rm", "db3"},
		{"vpn", "rm", "off2"}, {"key", "rm", "k2"},
	} {
		line = strings.Join(a, " ")
		if _, err := textRun(t, a...); err != nil {
			t.Errorf("%s: %v", line, err)
		}
	}
	allowCheck(t, "S-9.7 (the generic renderer)", used, genericText)
}
