package cli

import (
	"io"
	"os"

	"github.com/sgnd/komando/internal/out"
)

// readStdinIfPiped reads stdin when it is a pipe or a file (nil when it is
// a terminal), up to limit bytes (see readLimited).
func readStdinIfPiped(limit int64, what string) ([]byte, error) {
	fi, err := os.Stdin.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice != 0 {
		return nil, nil
	}
	return readLimited(os.Stdin, limit, what)
}

// maxStdinValue is the most komando reads from stdin for one value (a
// secret, a queue message): far more than any of them, and a wrong pipe
// (`cat big.iso | komando secret set x`) stops early instead of filling
// memory.
const maxStdinValue = 1 << 20

// readLimited reads all of r, up to limit bytes (none when limit is 0).
// More than that is a USAGE error that names what was read.
func readLimited(r io.Reader, limit int64, what string) ([]byte, error) {
	if limit <= 0 {
		return io.ReadAll(r)
	}
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, out.Usage("%s on stdin is more than %s, the most komando reads for it", what, humanBytes(limit))
	}
	return b, nil
}
