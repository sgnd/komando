package cli

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// Tests that lived with the menu and are about what stays: the line a
// command is shown as, how a built command runs, imports, guide install.

func TestImportVetHosts(t *testing.T) {
	// --overwrite with a copy that is refused (its --via does not exist)
	// keeps the server it would have replaced
	s := &store.State{Hosts: map[string]*store.Host{"web1": {Name: "web1", Address: "10.0.0.1", User: "u"}}}
	v, err := vetImportHosts(s, []*store.Host{{Name: "web1", Address: "10.0.0.9", Via: "nosuch"}}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Invalid) != 1 || len(v.Add) != 0 || s.Hosts["web1"] == nil || s.Hosts["web1"].Address != "10.0.0.1" {
		t.Errorf("a refused --overwrite must keep the old server: invalid %v, web1 %+v", v.Invalid, s.Hosts["web1"])
	}
	// what was left out of a server is said only for one that is added,
	// in words that are true for --dry-run too
	v, err = vetImportHosts(s, []*store.Host{
		{Name: "web2", Address: "10.0.0.2", Identity: "/no/such/key"},
		{Name: "web3", Address: "10.0.0.3", Identity: "/no/such/key", Via: "nosuch"},
	}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"web2: its identity file /no/such/key was not found; left out"}; !slices.Equal(v.Notes, want) {
		t.Errorf("notes %q, want %q", v.Notes, want)
	}
}

func TestGuideInstallDryRunText(t *testing.T) {
	files := []skillFile{{Path: "/h/.claude/skills/komando/SKILL.md", Action: "created"},
		{Path: "/h/.claude/settings.json", Action: "updated", Backup: "/h/.claude/settings.json.bak"}}
	g.dryRun = true
	dry := skillResult{Files: files}.Text()
	g.dryRun = false
	for _, line := range strings.Split(dry, "\n") {
		if strings.HasPrefix(line, "created") || strings.HasPrefix(line, "updated") || strings.Contains(line, "Restart") {
			t.Errorf("dry run says it was done: %q", line)
		}
	}
	if !strings.Contains(dry, "would create") || !strings.Contains(dry, "would be kept") {
		t.Errorf("dry run:\n%s", dry)
	}
	if real := (skillResult{Files: files}).Text(); !strings.HasPrefix(real, "created  ") {
		t.Errorf("real run:\n%s", real)
	}
}

func TestCommandKeepsVaultPass(t *testing.T) {
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	vault.Passphrase() // what every command does first (root.go)
	if _, ok := os.LookupEnv("KOMANDO_VAULT_PASS"); ok {
		t.Fatal("Passphrase left the variable in the environment")
	}
	c := pickCommand("/bin/true", []string{"list"})
	if !slices.Contains(c.Env, "KOMANDO_VAULT_PASS=test") {
		t.Error("a command komando runs does not get the vault passphrase")
	}
	if c.Stdin != os.Stdin || c.Stdout != os.Stdout || c.Stderr != os.Stderr {
		t.Error("a command komando runs must have the terminal")
	}
}

func TestCommandLineQuoting(t *testing.T) {
	cases := map[string][]string{
		"shell web1":                    {"shell", "web1"},
		"audit --limit 20":              {"audit", "--limit", "20"},
		"host add web1 deploy@10.0.0.5": {"host", "add", "web1", "deploy@10.0.0.5"},
		"host add web1 'a;b'":           {"host", "add", "web1", "a;b"},
		`host add web1 'it'\''s'`:       {"host", "add", "web1", "it's"},
	}
	for want, args := range cases {
		if got := pickCommandLine(args); got != want {
			t.Errorf("pickCommandLine(%q) = %q, want %q", args, got, want)
		}
	}
}

func TestFirstRunImport(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir reads USERPROFILE on Windows
	cfg := filepath.Join(home, ".ssh", "config")
	_, err := os.Open(cfg)
	e := toErr(sshConfigErr(cfg, err))
	if e.Code != "FILE_NOT_FOUND" || e.Message != "there is no ~/.ssh/config on this computer" || !strings.Contains(e.Hint, "komando host add web1") {
		t.Errorf("no ~/.ssh/config: %+v", e)
	}
	other := filepath.Join(home, "other")
	_, err = os.Open(other)
	if e := toErr(sshConfigErr(other, err)); !strings.Contains(e.Message, other+" does not exist") || strings.Contains(e.Hint, "host add") {
		t.Errorf("a path someone typed: %+v", e)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}

	r := importResult{File: "~/.ssh/config", Hosts: []string{}, NotFound: []string{"Host *: used as defaults, not a server"}}
	if got := r.Text(); got != "nothing to import from ~/.ssh/config\nnot imported: Host *: used as defaults, not a server\n" {
		t.Errorf("nothing added:\n%s", got)
	}
	// a note about a server that was added is not "not imported"; which
	// notes those are is known, not guessed from the text
	about := "bastion: its identity file ~/.ssh/id_x was not found; left out"
	r.Hosts = []string{"web1", "bastion"}
	r.NotFound = []string{"Host *: used as defaults, not a server", about, "web1: a note from the source file"}
	r.aboutAdded = []string{about}
	want := "servers added: web1, bastion\n" +
		"not imported: Host *: used as defaults, not a server\n" +
		about + "\n" +
		"not imported: web1: a note from the source file\n"
	if got := r.Text(); got != want {
		t.Errorf("notes about added servers carry no 'not imported':\n%s\nwant\n%s", got, want)
	}
}
