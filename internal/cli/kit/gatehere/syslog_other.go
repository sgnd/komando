//go:build windows || plan9

package gatehere

import "errors"

// SystemLog: the server mode runs on Unix servers; here there is no
// system log to write to.
func SystemLog(string) error { return errors.New("no system log on this system") }
