package sshx

import (
	"errors"
	"strings"
)

// Refused reports whether err is a refused connection: nothing listens on
// the port. Windows words it "No connection could be made because the
// target machine actively refused it", in the system's language, so the
// error number is what counts; the words are for errors that kept only
// their text.
func Refused(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errRefused) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "connection refused") || strings.Contains(msg, "actively refused")
}
