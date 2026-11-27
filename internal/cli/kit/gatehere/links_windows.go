package gatehere

import "io/fs"

// links: the server mode runs on Unix servers; on Windows a file counts
// as one name.
func links(fs.FileInfo) uint64 { return 1 }
