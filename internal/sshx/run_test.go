package sshx

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

func TestBuildCommandRejectsBadEnvKeys(t *testing.T) {
	for _, k := range []string{"A;reboot;B", "1X", "A B", "A=B", "$(id)"} {
		if _, _, err := BuildCommand(nil, RunRequest{Command: "true", Env: map[string]string{k: "1"}}); err == nil {
			t.Errorf("env key %q must be refused", k)
		}
	}
	cmd, _, err := BuildCommand(&Client{Host: &store.Host{Env: map[string]string{"APP_ENV": "prod"}}}, RunRequest{Command: "true"})
	if err != nil || !strings.Contains(cmd, "export APP_ENV='prod'; ") {
		t.Errorf("valid env key: %q %v", cmd, err)
	}
}

// readAll collects what the gate lets through to the command's stdin.
func readAll(g *sudoGate) <-chan string {
	ch := make(chan string, 1)
	go func() { b, _ := io.ReadAll(g.stdin); ch <- string(b) }()
	return ch
}

func TestSudoGateNoPrompt(t *testing.T) {
	var out bytes.Buffer
	g := newSudoGate(&out, []byte("s3cret\n"), []byte("input"))
	got := readAll(g)
	g.Write([]byte(sudoReady + "\nwarning: x\n"))
	if s := <-got; s != "input" {
		t.Errorf("stdin = %q: the password must not reach a command sudo did not ask for", s)
	}
	g.flush()
	g.close()
	if out.String() != "warning: x\n" {
		t.Errorf("stderr = %q", out.String())
	}
}

func TestSudoGatePrompt(t *testing.T) {
	var out bytes.Buffer
	g := newSudoGate(&out, []byte("s3cret\n"), []byte("input"))
	got := readAll(g)
	g.Write([]byte(sudoPrompt))
	g.Write([]byte(sudoReady + "\r\n"))
	if s := <-got; s != "s3cret\ninput" {
		t.Errorf("stdin = %q", s)
	}
	g.flush()
	g.close()
	if out.Len() != 0 {
		t.Errorf("markers must be removed, stderr = %q", out.String())
	}
}

func TestSudoGateWrongPassword(t *testing.T) {
	var out bytes.Buffer
	g := newSudoGate(&out, []byte("wrong\n"), []byte("input"))
	g.Write([]byte(sudoPrompt))
	pass := make([]byte, len("wrong\n")) // sudo reads the password before it asks again
	if _, err := io.ReadFull(g.stdin, pass); err != nil || string(pass) != "wrong\n" {
		t.Fatalf("password = %q %v", pass, err)
	}
	got := readAll(g)
	g.Write([]byte("Sorry, try again.\n" + sudoPrompt))
	if s := <-got; s != "" {
		t.Errorf("stdin = %q: a second prompt must get end of input, not the command's stdin", s)
	}
	g.flush()
	g.close()
	if out.String() != "Sorry, try again.\n" {
		t.Errorf("stderr = %q", out.String())
	}
}

// A value from the vault never goes on the command line (ps, sudo's log):
// it reaches the command on its input, read back exactly by every common
// shell, and the command's own input follows untouched.
func TestSecretEnvGoesOnInput(t *testing.T) {
	dialHome(t)
	t.Setenv("KOMANDO_VAULT_PASS", "test-passphrase-long-enough")
	weird := "p@ss 'q\" $(id) `x` \\n\\0101 \\ \nline2\ttab\x01\x7fend é\n\n"
	if err := vault.Set("db", weird); err != nil {
		t.Fatal(err)
	}
	c := &Client{Host: &store.Host{Env: map[string]string{"APP_ENV": "prod", "TOKEN": "secret:db"}}}
	r := RunRequest{Command: `printf '%s|%s|%s|' "$APP_ENV" "$DB_PASS" "$TOKEN"; cat`, Env: map[string]string{"DB_PASS": "secret:db"}, Stdin: []byte("rest of input")}
	cmd, _, stdin, err := runCommand(c, r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cmd, "p@ss") || !strings.Contains(cmd, "export APP_ENV='prod'; ") {
		t.Fatalf("command line: %s", cmd)
	}
	if shown, _, _ := BuildCommand(c, r); shown != cmd {
		t.Errorf("--dry-run shows %q, Run sends %q", shown, cmd)
	}
	want := "prod|" + weird + "|" + weird + "|rest of input"
	if runtime.GOOS == "windows" {
		t.Skip("Unix only: runs the command in the shells a server has")
	}
	ran := 0
	for _, sh := range []string{"sh", "bash", "dash", "zsh", "ksh"} {
		path, err := exec.LookPath(sh)
		if err != nil {
			continue
		}
		ran++
		x := exec.Command(path, "-c", cmd)
		x.Stdin = bytes.NewReader(stdin)
		got, err := x.CombinedOutput()
		if err != nil || string(got) != want {
			t.Errorf("%s: %v\n got %q\nwant %q", sh, err, got, want)
		}
	}
	if ran == 0 {
		t.Skip("no shell to run the command with")
	}
	// with sudo the values stay off its command line (and its log) too
	sudo, _, sin, err := buildCommand(c, RunRequest{Command: "true", Sudo: true, Env: r.Env})
	if err != nil || strings.Contains(sudo, "p@ss") || len(sin) == 0 {
		t.Errorf("sudo: %q %v", sudo, err)
	}
	// no input arrives: the command does not run without its environment
	x := exec.Command("sh", "-c", cmd)
	x.Stdin = strings.NewReader("")
	if got, err := x.CombinedOutput(); err == nil || strings.Contains(string(got), "prod|") {
		t.Errorf("ran without its environment: %q %v", got, err)
	}
}

// A terminal (--pty) cuts long lines: a value too long for one is refused,
// not cut.
func TestSecretEnvTooLongForTerminal(t *testing.T) {
	dialHome(t)
	t.Setenv("KOMANDO_VAULT_PASS", "test-passphrase-long-enough")
	if err := vault.Set("cert", strings.Repeat("A", maxTerminalLine+1)); err != nil {
		t.Fatal(err)
	}
	r := RunRequest{Command: "true", Env: map[string]string{"CERT": "secret:cert"}}
	if _, _, _, err := buildCommand(nil, r); err != nil {
		t.Errorf("without a terminal: %v", err)
	}
	r.PTY = true
	if _, _, _, err := buildCommand(nil, r); err == nil || !strings.Contains(err.Error(), "--pty") {
		t.Errorf("with a terminal: %v", err)
	}
}

func TestEnvLineEscapes(t *testing.T) {
	if got := string(envLine("a\\b\nc\x1bd é")); got != `a\\b\0012c\0033d é`+"\n" {
		t.Errorf("got %q", got)
	}
}

// SaveInput takes exactly its bytes off the input, into a file only the
// user can read, and leaves the rest for the next step.
func TestSaveInput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix only: runs a server's sh script")
	}
	f := filepath.Join(t.TempDir(), "env")
	x := exec.Command("sh", "-c", SaveInput(len("export A='1\n2'; "), `"$F"`)+` && cat`)
	x.Env = append(os.Environ(), "F="+f)
	x.Stdin = strings.NewReader("export A='1\n2'; the sudo password\n")
	got, err := x.CombinedOutput()
	if err != nil || string(got) != "the sudo password\n" {
		t.Fatalf("the rest of the input: %q %v", got, err)
	}
	b, err := os.ReadFile(f)
	fi, _ := os.Stat(f)
	if err != nil || string(b) != "export A='1\n2'; " || fi.Mode().Perm() != 0o600 {
		t.Errorf("saved %q (%v), mode %v", b, err, fi.Mode())
	}
}
