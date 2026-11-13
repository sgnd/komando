package sshx

import "golang.org/x/sys/windows"

// errRefused is the error number of a refused connection (WSAECONNREFUSED).
var errRefused error = windows.WSAECONNREFUSED
