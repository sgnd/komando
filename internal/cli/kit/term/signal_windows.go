package term

import "os"

// raise does nothing on Windows, where a signal cannot end a process: the
// caller's exit ends it.
func raise(os.Signal) {}
