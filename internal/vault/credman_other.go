//go:build !windows

package vault

import "errors"

var errNoCredman = errors.New("the Windows Credential Manager exists only on Windows")

func credAvailable() error                   { return errNoCredman }
func credRead(string) ([]byte, error)        { return nil, errNoCredman }
func credWrite(string, string, []byte) error { return errNoCredman }
func credDelete(string) error                { return errNoCredman }
