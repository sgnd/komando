//go:build !windows

package gatehere

import "log/syslog"

// SystemLog writes line to this system's log (auth facility), where a
// user cannot change or remove it.
func SystemLog(line string) error {
	w, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_NOTICE, "komando-ssh-gate")
	if err != nil {
		return err
	}
	defer w.Close()
	return w.Notice(line)
}
