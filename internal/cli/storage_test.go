package cli

import (
	"context"
	"os"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// An sftp:// conn reaches an SSH server, so it must not be a way around
// that server's protection.
func TestSFTPConnInheritsHostProtection(t *testing.T) {
	st := &store.State{
		Hosts: map[string]*store.Host{"web1": {Name: "web1", Address: "10.0.0.5", Protected: true}},
		Conns: map[string]*store.Conn{},
	}
	same := &store.Conn{Name: "files", URL: "sftp://deploy@10.0.0.5/uploads"}
	other := &store.Conn{Name: "elsewhere", URL: "sftp://deploy@10.0.0.6/uploads"}
	port := &store.Conn{Name: "otherport", URL: "sftp://deploy@10.0.0.5:2222/uploads"}
	if !protectedConn(st, same) {
		t.Error("sftp conn to a protected host is not protected")
	}
	if protectedConn(st, other) || protectedConn(st, port) {
		t.Error("sftp conn to another server counted as protected")
	}
}

// smb:// conns open an SMB share; KOMANDO_TEST_SMB (with the password in
// KOMANDO_TEST_SMB_PASSWORD) names a real one to list.
func TestOpenBucketSMB(t *testing.T) {
	t.Setenv("KOMANDO_TEST_SMB_PW", os.Getenv("KOMANDO_TEST_SMB_PASSWORD"))
	st := &store.State{Hosts: map[string]*store.Host{}, Conns: map[string]*store.Conn{}}
	c := &store.Conn{Name: "share", URL: "smb://alice@127.0.0.1:1/team", PasswordRef: "env:KOMANDO_TEST_SMB_PW"}
	if _, err := openBucket(context.Background(), st, c); toErr(err).Code != "STORAGE_CONNECT" {
		t.Errorf("closed port: %v", err)
	}
	if c.URL = os.Getenv("KOMANDO_TEST_SMB"); c.URL == "" {
		return
	}
	b, err := openBucket(context.Background(), st, c)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, _, err := b.List(context.Background(), "", false, 10); err != nil {
		if oe, ok := err.(*out.Error); !ok || oe.Code != "FOLDER_NOT_FOUND" {
			t.Error(err)
		}
	}
}
