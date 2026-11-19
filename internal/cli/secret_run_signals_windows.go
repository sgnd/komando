package cli

import "os"

// Windows has no SIGTERM to catch; a Ctrl-C ends the program too.
var forwardedSignals = []os.Signal{os.Interrupt}
