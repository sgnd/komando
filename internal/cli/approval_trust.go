package cli

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// axTrustOutput runs the macOS Accessibility check; tests set another so
// they never run osascript. AXIsProcessTrusted never prompts. osascript
// inherits the TCC trust of the app that started komando (the terminal),
// which is what decides whether an agent there can click our window.
var axTrustOutput = func(ctx context.Context) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "/usr/bin/osascript", "-l", "JavaScript", "-e",
		"ObjC.import('ApplicationServices'); $.AXIsProcessTrusted()")
	cmd.WaitDelay = time.Second // a child holding the pipe open cannot outlast the timeout
	return cmd.Output()
}

var axTrust struct {
	once    sync.Once
	trusted bool
}

// accessibilityTrusted reports whether programs started like komando may
// drive other apps' windows through System Events (GUI scripting), so an
// agent could click "Allow once". Any answer but "false" counts as
// trusted. The result is kept for the rest of the run.
func accessibilityTrusted() bool {
	axTrust.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		b, err := axTrustOutput(ctx)
		axTrust.trusted = err != nil || strings.TrimSpace(string(b)) != "false"
	})
	return axTrust.trusted
}

// resetAccessibilityTrust forgets the kept answer (tests).
func resetAccessibilityTrust() { axTrust.once = sync.Once{} }
