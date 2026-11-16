package store

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

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

var accountHomeOnce = sync.OnceValues(lookupAccountHome)

func accountHome() (string, error) { return accountHomeOnce() }

// lookupAccountHome is AccountHome, looked up. komando is built without
// cgo, so on Linux os/user reads only /etc/passwd; an account that comes
// from a directory service (LDAP, sssd, NIS) is asked of getent, the
// system's own lookup, at its fixed path.
func lookupAccountHome() (string, error) {
	if runtime.GOOS == "windows" {
		// user.Current reads the process's token there, not the environment
		u, err := user.Current()
		if err != nil {
			return "", err
		}
		return nonEmpty(u.HomeDir)
	}
	uid := strconv.Itoa(os.Getuid())
	// user.Current falls back to $HOME when the database has no entry;
	// LookupId does not
	u, err := lookupID(uid)
	if err == nil {
		return nonEmpty(u.HomeDir)
	}
	if d, gerr := getentHome(uid); gerr == nil {
		return d, nil
	}
	return "", err
}

var lookupID = user.LookupId

// getentPaths are where getent lives; never looked up in PATH, which the
// caller's environment sets.
var getentPaths = []string{"/usr/bin/getent", "/bin/getent"}

// getentHome is the home folder getent passwd UID names.
func getentHome(uid string) (string, error) {
	for _, g := range getentPaths {
		if _, err := os.Stat(g); err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		c := exec.CommandContext(ctx, g, "passwd", uid)
		c.Env = []string{"PATH=/usr/bin:/bin"}
		b, err := c.Output()
		cancel()
		if err != nil {
			continue
		}
		f := strings.Split(strings.TrimSpace(string(b)), ":")
		if len(f) >= 7 && f[2] == uid && filepath.IsAbs(f[5]) {
			return f[5], nil
		}
	}
	return "", errors.New("getent knows no account with uid " + uid)
}

func nonEmpty(d string) (string, error) {
	if d == "" {
		return "", errors.New("the user database gives this account no home folder")
	}
	return d, nil
}

// UserHome is the home folder komando's own paths start from. For an AI
// agent (its variables are in this process's environment) it is
// AccountHome; for anyone else $HOME (os.UserHomeDir). When the user
// database and getent have no entry for the account (a container's
// made-up uid), there is nothing to check $HOME against: $HOME is used,
// and the cli stops an agent's commands until a person allows it
// (guardHome).
func UserHome() (string, error) {
	if engine.AgentName(os.LookupEnv) != "" {
		if d, err := AccountHome(); err == nil {
			return d, nil
		}
	}
	return os.UserHomeDir()
}
