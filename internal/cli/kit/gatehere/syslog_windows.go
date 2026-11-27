//go:build windows

package gatehere

import "errors"

// SystemLog: the server mode runs on Unix servers; Windows has no system
// log to write to.
func SystemLog(string) error { return errors.New("no system log on this system") }
