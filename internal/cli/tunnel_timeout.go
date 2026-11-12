package cli

import (
	"os"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// tunnelTimeout is TUNNEL_TIMEOUT: the last lines of the tunnel's log in
// the message and a command to try, as an AI agent may not read the log.
func tunnelTimeout(host, logPath string) error {
	return out.Errf(out.ExitTimeout, "TUNNEL_TIMEOUT", "check that "+host+" answers: `komando test "+host+"`; the whole log is "+logPath+" (for a person to read)",
		"tunnel did not become ready%s", logTail(logPath, 5))
}

// logTail is the last n lines of a background process's log, cleaned, as
// ": line; line" for a message (an AI agent may not read the file itself),
// or "" when there is none.
func logTail(path string, n int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l = cleanText(strings.TrimSpace(l)); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	if len(lines) == 0 {
		return ""
	}
	return ": " + strings.Join(lines, "; ")
}
