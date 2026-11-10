package cli

import (
	"os"
	"path/filepath"
)

// authPipe on Windows: komando does not run openvpn as an administrator
// there, so no other process reads the login; it is a file of this user's
// only, removed by done.
func authPipe(dir, name, content string) (string, func(), error) {
	path := filepath.Join(dir, name+".auth")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", nil, err
	}
	return path, func() { os.Remove(path) }, nil
}
