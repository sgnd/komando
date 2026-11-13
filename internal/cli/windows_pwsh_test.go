package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// These tests run komando's PowerShell for real: a loopback SSH server
// hands each command to pwsh in a Docker container, the way Windows
// OpenSSH hands it to powershell.exe. They are skipped unless
// KOMANDO_PWSH_CONTAINER names a running container with PowerShell 7, e.g.
//
//	docker run -d --rm --name komando-pwsh --entrypoint /bin/sh mcr.microsoft.com/powershell -c 'sleep 3600'
//	KOMANDO_PWSH_CONTAINER=komando-pwsh go test ./internal/cli -run PwshReal
//
// PowerShell 7 on Linux is not Windows PowerShell 5.1 on Windows: this
// checks the bootstrap, quoting, exit codes and the file scripts, not
// Windows itself (services, CIM, the registry).

// pwshServer starts the bridge and a host "win" that points at it.
func pwshServer(t *testing.T) {
	t.Helper()
	box := os.Getenv("KOMANDO_PWSH_CONTAINER")
	if box == "" {
		t.Skip("set KOMANDO_PWSH_CONTAINER to a container with pwsh to run this")
	}
	realHome := os.Getenv("HOME") // the docker command finds its settings there
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp) // os.UserHomeDir reads USERPROFILE on Windows
	setHome(t, filepath.Join(tmp, ".komando"))
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("KOMANDO_OUTPUT", "json")
	_, hostKey, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(hostKey)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go bridgePwsh(nc, cfg, box, realHome)
		}
	}()
	_, clientKey, _ := ed25519.GenerateKey(rand.Reader)
	blk, _ := ssh.MarshalPrivateKey(clientKey, "")
	keyPath := filepath.Join(tmp, "id_test")
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(blk), 0o600)
	if err := store.Update(func(st *store.State) error {
		st.Hosts["win"] = &store.Host{Name: "win", Address: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, User: "u", Identity: keyPath, OS: store.OSWindows}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	savedW := out.P.W
	out.P.W = io.Discard
	t.Cleanup(func() { out.P.W = savedW })
}

// bridgePwsh runs each exec as `docker exec -i BOX pwsh ARGS`.
func bridgePwsh(nc net.Conn, cfg *ssh.ServerConfig, box, home string) {
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		ch, creqs, err := nch.Accept()
		if err != nil {
			continue
		}
		go func() {
			for r := range creqs {
				_ = r.Reply(r.Type == "exec", nil)
				if r.Type != "exec" {
					continue
				}
				var p struct{ Cmd string }
				_ = ssh.Unmarshal(r.Payload, &p)
				args, ok := strings.CutPrefix(p.Cmd, "powershell ")
				code := 127
				if ok {
					cmd := exec.Command("docker", append([]string{"exec", "-i", "-e", "DOTNET_GCHeapHardLimit=0x10000000", box, "/opt/microsoft/powershell/7/pwsh"}, strings.Fields(args)...)...)
					cmd.Env = append(os.Environ(), "HOME="+home)
					cmd.Stdin, cmd.Stdout, cmd.Stderr = ch, ch, ch.Stderr()
					err := cmd.Run()
					code = 0
					if ee, ok := err.(*exec.ExitError); ok {
						code = ee.ExitCode()
					} else if err != nil {
						code = 126
					}
				}
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{uint32(code)}))
				_ = ch.Close()
			}
		}()
	}
}

func TestPwshRealExec(t *testing.T) {
	pwshServer(t)
	cases := []struct {
		cmd, want string
		code      string
	}{
		{`Write-Output "a'b $env:MODE"`, `a'b it's`, ""},
		{`cmd-that-does-not-exist`, "", "FAILED"},
		{`exit 7`, "", "FAILED"},
		{`Get-Location`, "/tmp", ""},
		{`[Console]::In.ReadToEnd()`, "from stdin", ""},
	}
	in := filepath.Join(t.TempDir(), "in.txt")
	_ = os.WriteFile(in, []byte("from stdin"), 0o600)
	for _, c := range cases {
		var err error
		got := captureOutput(t, func() error {
			err = runRoot(t, "exec", "win", "-e", "MODE=it's", "-C", "/tmp", "--stdin-file", in, "--", c.cmd)
			return err
		})
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: output %s", c.cmd, got)
		}
		if (c.code == "") != (err == nil) {
			t.Errorf("%s: err %v, output %s", c.cmd, err, got)
		}
	}
	got := captureOutput(t, func() error { return runRoot(t, "exec", "win", "--", "exit 7") })
	if !strings.Contains(got, `"exit_code":7`) {
		t.Errorf("exit 7: %s", got)
	}
	got = captureOutput(t, func() error { return runRoot(t, "facts", "win") })
	if !strings.Contains(got, `"powershell":"7.`) || !strings.Contains(got, `"ok":true`) {
		t.Errorf("facts: %s", got)
	}
	// test asks Windows who logs in, which PowerShell on Linux cannot say:
	// it must report that clearly, not as a broken connection
	got = captureOutput(t, func() error { return runRoot(t, "test", "win") })
	if !strings.Contains(got, `"POWERSHELL_FAILED"`) {
		t.Errorf("test: %s", got)
	}
}

func TestPwshRealFiles(t *testing.T) {
	pwshServer(t)
	dir := "/tmp/komando-" + strings.ReplaceAll(t.Name(), "/", "-") + "-it's"
	p := dir + "/app.conf"
	run := func(args ...string) (string, error) {
		var err error
		got := captureOutput(t, func() error { err = runRoot(t, args...); return err })
		return got, err
	}
	_, _ = run("exec", "win", "--", "Remove-Item -Recurse -Force -LiteralPath '"+strings.ReplaceAll(dir, "'", "''")+"' -ErrorAction SilentlyContinue")
	if got, err := run("fs", "write", "win", p, "--content", "one\n", "-p"); err != nil || !strings.Contains(got, `"changed":true`) {
		t.Fatalf("fs write: %v %s", err, got)
	}
	if got, err := run("fs", "write", "win", p, "--content", "two\n", "--backup"); err != nil || !strings.Contains(got, `app.conf.bak`) {
		t.Fatalf("fs write --backup: %v %s", err, got)
	}
	if got, err := run("fs", "write", "win", p, "--content", "two\n", "--if-changed"); err != nil || !strings.Contains(got, `"changed":false`) {
		t.Errorf("fs write --if-changed: %v %s", err, got)
	}
	if got, err := run("fs", "cat", "win", p); err != nil || !strings.Contains(got, `"content":"two\n"`) {
		t.Errorf("fs cat: %v %s", err, got)
	}
	if got, err := run("fs", "cat", "win", p+".bak"); err != nil || !strings.Contains(got, `"content":"one\n"`) {
		t.Errorf("backup: %v %s", err, got)
	}
	if got, err := run("fs", "ls", "win", dir); err != nil || !strings.Contains(got, `"count":2`) {
		t.Errorf("fs ls: %v %s", err, got)
	}
	if got, err := run("fs", "stat", "win", p, "--sha256"); err != nil || !strings.Contains(got, `"sha256":"`) {
		t.Errorf("fs stat: %v %s", err, got)
	}
	if got, _ := run("fs", "stat", "win", dir+"/nope"); !strings.Contains(got, `"exists":false`) {
		t.Errorf("fs stat missing: %s", got)
	}
	if _, err := run("fs", "cat", "win", dir+"/nope"); errCode(err) != "PATH_NOT_FOUND" {
		t.Errorf("fs cat missing: %v", err)
	}
	if _, err := run("fs", "write", "win", dir+"/no/such/x", "--content", "x"); errCode(err) != "FOLDER_NOT_FOUND" {
		t.Errorf("fs write without -p: %v", err)
	}
	if _, err := run("fs", "write", "win", p, "--content", "bad", "--validate", "if ((Get-Content %s) -ne 'good') { exit 3 }"); errCode(err) != "VALIDATION_FAILED" {
		t.Errorf("--validate: %v", err)
	}
	if got, err := run("fs", "write", "win", p, "--content", "good", "--validate", "if ((Get-Content %s) -ne 'good') { exit 3 }"); err != nil {
		t.Errorf("--validate passing: %v %s", err, got)
	}
	if got, _ := run("fs", "ls", "win", dir); !strings.Contains(got, `"count":2`) {
		t.Errorf("a failed --validate must leave no temporary file: %s", got)
	}
	body := strings.Repeat("0123456789abcdef", 20000) // 320 KB: several input lines
	src := filepath.Join(t.TempDir(), "big.bin")
	_ = os.WriteFile(src, []byte(body), 0o600)
	if got, err := run("upload", "win", src, dir+"/"); err != nil || !strings.Contains(got, `"bytes":320000`) {
		t.Fatalf("upload: %v %s", err, got)
	}
	to := t.TempDir()
	if got, err := run("download", "win", dir+"/big.bin", "--to", to); err != nil {
		t.Fatalf("download: %v %s", err, got)
	}
	if b, _ := os.ReadFile(filepath.Join(to, "big.bin")); string(b) != body {
		t.Errorf("download: %d bytes back", len(b))
	}
	_, _ = run("exec", "win", "--", "Remove-Item -Recurse -Force -LiteralPath '"+strings.ReplaceAll(dir, "'", "''")+"'")
}

// TestPwshRealParse has PowerShell parse every script komando sends to
// Windows, also those that need Windows itself to run (services, facts).
func TestPwshRealParse(t *testing.T) {
	box := os.Getenv("KOMANDO_PWSH_CONTAINER")
	if box == "" {
		t.Skip("set KOMANDO_PWSH_CONTAINER to a container with pwsh to run this")
	}
	now := time.Now()
	scripts := map[string]string{
		"facts":       winFactsScript,
		"svc status":  winSvcStatusScript([]string{"W3SVC", "sshd"}),
		"svc start":   winSvcScript("start", []string{"W3SVC"}, false, 10),
		"svc enable":  winSvcScript("enable", []string{"W3SVC"}, true, 0),
		"svc disable": winSvcScript("disable", []string{"W3SVC"}, true, 0),
		"svc list":    winSvcListScript,
		"write":       winWriteScript(`C:\a b\it's.txt`, winWriteOpts{backup: true, mkdirs: true, noFollow: true, validate: "Test-Path %s", intoDir: "x.txt"}, now),
		"ls":          winPath("~/x") + winCatch("Get-ChildItem -LiteralPath $p"),
	}
	for name, s := range scripts {
		check := `$e = $null; [void][System.Management.Automation.Language.Parser]::ParseInput([Console]::In.ReadToEnd(), [ref]$null, [ref]$e); if ($e) { $e | ForEach-Object { $_.ToString() }; exit 1 }`
		cmd := exec.Command("docker", "exec", "-i", "-e", "DOTNET_GCHeapHardLimit=0x10000000", box, "/opt/microsoft/powershell/7/pwsh", "-NoProfile", "-NonInteractive", "-Command", check)
		cmd.Stdin = strings.NewReader(s)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s does not parse: %s\n%s", name, b, s)
		}
	}
}
