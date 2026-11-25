//go:build !windows

package term

// ConsoleVT: a Unix terminal reads escape sequences as they are.
func ConsoleVT(int) (ok bool, restore func()) { return true, func() {} }
