// Package execsession keeps a long exec running on a Unix server after the
// connection drops: a session folder on the server, its ID, the record on
// this computer, and the shell text that starts, reads and stops it
// (vault note 2026-11-24-komando-exec-session-and-winrm-design). The
// shell text is komando's own; the only value from outside that goes into
// it is an ID that passed CheckID.
package execsession

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"regexp"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// idBytes is 256 bits: an ID is the name agents pass around to read a run.
const idBytes = 32

// randRead is crypto/rand.Read; tests make it fail.
var randRead = rand.Read

var (
	idPattern = regexp.MustCompile(`^[a-z2-7]{52}$`)
	idText    = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// NewID makes a session ID: 256 random bits as 52 lowercase base32
// letters. A failed random read is an error, never a weaker ID.
func NewID() (string, error) {
	b := make([]byte, idBytes)
	if _, err := randRead(b); err != nil {
		return "", fmt.Errorf("session id: %w", err)
	}
	return strings.ToLower(idText.EncodeToString(b)), nil
}

// CheckID refuses anything but an ID NewID could make, before it goes into
// a path or shell text: an ID an agent passes in is outside input.
func CheckID(id string) error {
	if !idPattern.MatchString(id) {
		return out.Usage("%q is not a session ID: an ID is the 52 letters and digits exec printed as \"session\"", id)
	}
	return nil
}
