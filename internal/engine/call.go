package engine

import "io"

// Call is what one komando call runs with: the environment it sees and
// where it reads and writes. The CLI makes one from its process
// (os.LookupEnv, os.Stdin, os.Stdout ...). An app that runs a person's
// call and an agent's call at the same time makes one for each, so what
// one call reads, prints or is allowed never reaches the other.
type Call struct {
	// Program is the first word of the command line ("komando"), as the
	// audit log and the approval window show it.
	Program string
	// LookupEnv and Environ are the call's environment. The CLI passes
	// os.LookupEnv and os.Environ; nil is an empty environment, also for
	// the programs the call starts (a dump tool gets no PATH or HOME).
	// Some programs still get the process's environment, whatever the
	// call's: a kubeconfig's exec credential plugin (internal/kube), the
	// openconnect a VPN runs (internal/cli/vpn_session.go), and the ones
	// komando starts for itself (the approval window, the browser, a
	// credential helper, background komando processes).
	LookupEnv func(string) (string, bool)
	Environ   func() []string
	// Stdin, Stdout and Stderr are the call's input and output. Stdout
	// gets the JSON envelope (or the text); Stderr gets notes, warnings
	// and, in text mode, errors.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Terminal: a person can answer questions at the process's terminal
	// (stdin and stderr are one). An app's calls have no terminal. When
	// Terminal is true, Stderr must be safe for writes from several
	// goroutines at once: another call's goroutine may write a notice to
	// it (netx.LockBusy: a VPN is being connected elsewhere).
	Terminal bool
	// Ask opens the approval window for an agent's --yes,
	// --allow-dangerous or --reveal; nil opens komando's own window on
	// the screen.
	Ask func(text string) (allowed, shown bool)
}

// Lookup is LookupEnv, or nothing found when the call has no environment.
func (c Call) Lookup(key string) (string, bool) {
	if c.LookupEnv == nil {
		return "", false
	}
	return c.LookupEnv(key)
}

// Getenv is the value of key in the call's environment, or "".
func (c Call) Getenv(key string) string {
	v, _ := c.Lookup(key)
	return v
}

// Env is the call's whole environment as KEY=value lines, for a program
// the call starts.
func (c Call) Env() []string {
	if c.Environ == nil {
		return nil
	}
	return c.Environ()
}

// Caller is who makes the call, read from its environment.
func (c Call) Caller() Caller { return CallerFrom(c.Lookup, c.Terminal) }
