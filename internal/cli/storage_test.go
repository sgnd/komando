package cli

import (
	"testing"

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
