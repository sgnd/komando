package tmpclean

import "os"

// mine: on Windows the temporary folder is the user's own
// (%LOCALAPPDATA%\Temp), so what is in it is theirs.
func mine(os.FileInfo) bool { return true }
