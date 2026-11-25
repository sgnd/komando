package term

import "os"

// Raise does nothing on Windows, where a signal cannot end a process: the
// caller's exit ends it.
func Raise(os.Signal) {}
