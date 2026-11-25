package term

import "github.com/sgnd/komando/internal/out"

// Interrupted is the CANCELLED stop ("interrupted") of a command or a
// question that Ctrl-C or a signal ended. Each call builds a new error, so
// a caller may change the one it gets.
func Interrupted() *out.Error {
	return (&out.Error{Code: "CANCELLED", Message: "interrupted", Exit: out.ExitError,
		Hint: "it stopped before the end (Ctrl-C or a signal); check what it left, then run it again"}).
		Say("Stopped (Ctrl-C) before the end; what already ran stays as it is", "check what it left, then run it again")
}
