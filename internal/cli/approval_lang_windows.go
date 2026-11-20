package cli

import "golang.org/x/sys/windows"

var procGetUserDefaultUILanguage = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetUserDefaultUILanguage")

// systemLanguage on Windows is the user's display language
// (GetUserDefaultUILanguage): Indonesian is primary language 0x21.
var systemLanguage = func(func(string) string) string {
	if procGetUserDefaultUILanguage.Find() != nil {
		return ""
	}
	if r, _, _ := procGetUserDefaultUILanguage.Call(); r&0x3ff == 0x21 {
		return "id"
	}
	return "en"
}
