package policy

import (
	"regexp"
	"strings"
)

// Windows rules: the same destructive basics as the sh rules, written the
// way PowerShell and cmd.exe say them. PowerShell ignores case, so the
// rules do too. They are checked on every command, like the others: a
// Linux command does not use these words.

// winRecurse is a recursive delete option: -Recurse and its prefixes
// (-r, -rec ...) in PowerShell, /s in cmd.exe (rd /s, del /s).
const winRecurse = `(\s-r(e(c(u(r(s(e)?)?)?)?)?)?\b|\s/s\b)`

// winTop is the system drive, its root folder, or a system folder in it:
// C:\, C:\*, $env:SystemDrive, C:\Windows, C:\Windows\System32, C:\Program Files,
// C:\Users, ...
const winTop = `['"]?([a-z]:|\$env:(systemdrive|systemroot|windir|programfiles|userprofile|programdata))[\\/]*(\*|windows([\\/]+(system32|syswow64|winsxs))?|program\s?files(\s?\(x86\))?|programdata|users|system32)?[\\/]*\*?['"]?(\s|$|;|\||\))`

// winDelete is a delete command: Remove-Item and its aliases, and cmd's,
// where a command starts (also after = and return).
const winDelete = `(^|[;&|({=]\s*|\b(return|throw|exit)\s+|\bcmd(\.exe)?\s+/c\s+)` + winDeleteName

const winDeleteName = `(remove-item|ri|rm|rmdir|rd|del|erase)\b`

// winListDelete is a listing of the system drive or a system folder piped
// into a delete: Get-ChildItem C:\ | Remove-Item.
const winListDelete = `\b(get-childitem|gci|ls|dir|get-item|gi)\b[^;|\n]*\s` + winTop + `([^;\n]*\|)?\s*` + winDeleteName

var winRules = []struct{ id, pattern, reason string }{
	{"win-rm-root", `(?i)` + winDelete + `[^;|&\n]*` + winRecurse + `[^;|&\n]*\s` + winTop + `|(?i)` + winDelete + `[^;|&\n]*\s` + winTop + `([^;|&\n]*\s)?(-r(e(c(u(r(s(e)?)?)?)?)?)?|/s)\b|(?i)` + winListDelete,
		"deletes the system drive, a system folder or the users folder recursively"},
	{"win-format", `(?i)\b(format-volume|clear-disk|initialize-disk|remove-partition|set-disk\s[^;|]*-isoffline|diskpart)\b|(?i)(^|[;&|(]\s*)format(\.com)?\s+[a-z]:`,
		"formats or wipes a disk"},
	{"win-power", `(?i)\b(stop-computer|restart-computer)\b|(?i)\bshutdown(\.exe)?\s+[/-][srpgh]\b`, "powers off or restarts the server"},
	{"win-remote-access", `(?i)\b(stop-service|spsv|suspend-service)\b[^;|\n]*\b(sshd|winrm)\b|(?i)\bset-service\b[^;|\n]*\b(sshd|winrm)\b[^;|\n]*\b(disabled|stopped)\b|(?i)\bdisable-psremoting\b|(?i)\b(net|sc(\.exe)?)\s+(stop|config|delete)\s+['"]?(sshd|winrm)\b`,
		"stops remote access (SSH or WinRM), which locks you out"},
	{"win-firewall-block", `(?i)\bset-netfirewallprofile\b[^;|\n]*-defaultinboundaction\s+block\b|(?i)\bnetsh\s+advfirewall\s+(reset|set\s[^;|\n]*blockinbound)`,
		"blocks all incoming traffic (may lock you out)"},
	{"win-user-delete", `(?i)\b(remove-localuser|remove-aduser)\b|(?i)\bnet\s+user\s+\S+\s+/del(ete)?\b`, "deletes a user account"},
	{"win-encoded", `(?i)\b(powershell|pwsh)(\.exe)?\s[^;|\n]*-e(nc(odedcommand)?|c)?\s+[A-Za-z0-9+/=]{16,}`, "runs hidden (base64) text as a script"},
	{"win-download-run", `(?i)\b(iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring)\b[^;\n]*\|\s*(iex|invoke-expression)\b|(?i)\b(iex|invoke-expression)\b[^;\n]*\b(iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring)\b`,
		"runs a script downloaded from the network"},
	{"win-backups", `(?i)\bvssadmin(\.exe)?\s+(delete|resize)\s+shadow|(?i)\bwbadmin(\.exe)?\s+delete\b|(?i)\bbcdedit(\.exe)?\s+/(delete|set|deletevalue)\b`,
		"deletes backups (shadow copies) or changes how Windows boots"},
	{"win-registry-hive", `(?i)\b(remove-item|ri|rm|del|reg(\.exe)?\s+delete)\b[^;|\n]*\b(hklm|hkey_local_machine)(:)?\\(software|system|security|sam)\\?['"]?(\s|$|;|\|)`,
		"deletes a whole registry hive"},
}

// psPlain is a command with PowerShell's escape character (the backtick)
// taken out, so Re`move-Item reads as Remove-Item.
func psPlain(cmd string) string { return strings.ReplaceAll(cmd, "`", "") }

func init() {
	for _, b := range winRules {
		compiled = append(compiled, Rule{ID: b.id, Reason: b.reason, re: regexp.MustCompile(b.pattern)})
	}
}
