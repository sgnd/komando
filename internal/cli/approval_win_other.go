//go:build !windows

package cli

// approvalWindow exists on Windows only; the other systems use their own
// dialog tools (askOnScreen).
func approvalWindow(string, bool) (code string, allowed, gaveUp, shown bool) {
	return "", false, false, false
}
