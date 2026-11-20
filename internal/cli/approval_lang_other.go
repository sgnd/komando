//go:build !windows

package cli

import (
	"context"
	"os/exec"
	"runtime"
	"time"
)

// systemLanguage is the language the environment names; on a Mac where
// it names none, the first of the user's preferred languages.
var systemLanguage = func(getenv func(string) string) string {
	if l := envLang(getenv); l != "" || runtime.GOOS != "darwin" {
		return l
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "/usr/bin/defaults", "read", "-g", "AppleLanguages").Output()
	if err != nil {
		return ""
	}
	return firstAppleLanguage(b)
}
