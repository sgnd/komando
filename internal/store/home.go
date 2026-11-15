package store

import (
	"errors"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"sync"

	"github.com/sgnd/komando/internal/engine"
)

// An AI agent sets its own environment: `HOME=/tmp/x komando list` would
// move komando's data folder to an empty /tmp/x/.komando, with none of the
// person's protected servers, deny rules, pinned host keys or approval
// code, and the audit log written there. So for an agent komando takes the
// home folder from the system's user database, which the agent's
// environment cannot change. A person (or a script) may set HOME, and
// komando follows it, as every other program does.

// AccountHome is the home folder of the account komando runs as, from the
// system's user database (getpwuid on Unix; the profile folder of the
// process's token on Windows), never from $HOME or $USERPROFILE. Tests
// replace it, so they never touch the real one.
var AccountHome = accountHome

var accountHomeOnce = sync.OnceValues(func() (string, error) {
	if runtime.GOOS == "windows" {
		// user.Current reads the process's token there, not the environment
		u, err := user.Current()
		if err != nil {
			return "", err
		}
		return nonEmpty(u.HomeDir)
	}
	// user.Current falls back to $HOME when the database has no entry;
	// LookupId does not
	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		return "", err
	}
	return nonEmpty(u.HomeDir)
})

func accountHome() (string, error) { return accountHomeOnce() }

func nonEmpty(d string) (string, error) {
	if d == "" {
		return "", errors.New("the user database gives this account no home folder")
	}
	return d, nil
}

// UserHome is the home folder komando's own paths start from. For an AI
// agent (its variables are in this process's environment) it is
// AccountHome; for anyone else $HOME (os.UserHomeDir). When the user
// database has no entry for the account (a container's made-up uid, a
// static build on a computer whose accounts come from a directory
// service), there is nothing to check $HOME against and the agent's HOME
// is used.
func UserHome() (string, error) {
	if engine.AgentName(os.LookupEnv) != "" {
		if d, err := AccountHome(); err == nil {
			return d, nil
		}
	}
	return os.UserHomeDir()
}
