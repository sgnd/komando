package policy

import (
	"strings"
	"testing"
)

// psBypass checks scripts that change something and that the scanner once
// read as only reading: each must be refused under --read-only and must not
// count as known to only read.
func psBypass(t *testing.T, scripts ...string) {
	t.Helper()
	for _, s := range scripts {
		if PSReadOnly(s) == "" {
			t.Errorf("%q: want a read-only violation", s)
		}
		if PSOnlyReads(s) {
			t.Errorf("%q: want not known to only read", s)
		}
	}
}

func psReads(t *testing.T, scripts ...string) {
	t.Helper()
	for _, s := range scripts {
		if why := PSReadOnly(s); why != "" {
			t.Errorf("%q: want read-only, got %q", s, why)
		}
		if !PSOnlyReads(s) {
			t.Errorf("%q: want known reads", s)
		}
	}
}

func TestPSCommentStartsAToken(t *testing.T) {
	psBypass(t,
		`Get-Date a#; Remove-Item C:\data -Recurse -Force`,
		`Write-Output a#; Stop-Service Spooler`,
		`Write-Output a<#x; Remove-Item C:\data; #>`,
	)
	// the denylist read these as reads; the subset refuses every comment
	psBypass(t,
		"Get-Date # Remove-Item C:\\x",
		"Get-Date;# Remove-Item C:\\x",
		"Get-Date|#x\nOut-String",
		"Get-Date <# Remove-Item #> -Format o",
	)
	psReads(t, `Write-Output 'a#b'`, `Select-String -Path C:\app\web.config -Pattern '<add key='`)
}

func TestPSTypographicDoubleQuotes(t *testing.T) {
	psBypass(t,
		"Get-Date \u201c'\u201d; Remove-Item C:\\data -Recurse; \u201c'\u201d",
		"Write-Output \"x\u201d; Remove-Item C:\\data -Recurse; \u201cy\"",
		"Write-Output \u201ex\u201c; Remove-Item C:\\data",
		"Write-Output \u201c$(Remove-Item C:\\data)\u201d",
	)
	psBypass(t, "Write-Output \u201cRemove-Item C:\\data\u201d") // was a read; non-ASCII is refused now
}

func TestPSHereStrings(t *testing.T) {
	psBypass(t,
		"@\u201c\n\u201d\n\u201d@; Remove-Item C:\\x; \u201c\u201d",
		"@\" \nx\n\"@; Remove-Item C:\\x",
		"@\u2018\nx\n\u2019@; Remove-Item C:\\x",
		"@\"\n$(Remove-Item C:\\x)\n\"@",
	)
	psBypass(t, // were reads; every here-string is refused now
		"@'\nRemove-Item C:\\x\n'@ | Out-String",
		"@\"\r\nRemove-Item C:\\x\r\n\"@",
		"@\u201c\nRemove-Item \u201d C:\\x\n\u201d@",
	)
}

func TestPSSubexpressionQuotes(t *testing.T) {
	psBypass(t,
		`"$("a"; Remove-Item C:\data -Recurse)"`,
		`"$(')'; Remove-Item C:\data)"`,
		"\"$(# )\nRemove-Item C:\\data)\"",
		`"$("$("a") $(Remove-Item C:\data)")"`,
		"@\"\n$(\")\"; Remove-Item C:\\data)\n\"@",
		`"$(Get-Date) $(Remove-Item C:\data)"`,
	)
	psBypass(t, // were reads; $ in a string is refused now
		`"$("a") Remove-Item $((Get-Date).Year)"`,
		`"$("$("a"); Remove-Item C:\data")"`,
	)
}

func TestPSPipelineKeywords(t *testing.T) {
	psBypass(t,
		`return Remove-Item C:\data -Recurse`,
		`exit Stop-Service w32time`,
		`throw Stop-Service w32time`,
		`return & $x`,
		`foreach ($f in Remove-Item C:\x) { }`,
	)
	// were reads; keywords are refused now
	psBypass(t, `return Get-Date`, `exit 3`, `throw 'no'`, `foreach ($f in Get-ChildItem C:\x) { $f.Name }`,
		`foreach ($f in Get-ChildItem C:\x) { $f.Name }; exit 0`)
	psReads(t, `Get-ChildItem C:\x | ForEach-Object { $_.Name }`)
}

func TestPSDotNetMemberNames(t *testing.T) {
	psBypass(t,
		`(Get-Item C:\data\f.txt).'Delete'()`,
		`(Get-Item C:\data\f.txt)."Delete"()`,
		"(Get-Item C:\\f).\u2018Delete\u2019()",
		`$m='Delete'; (Get-Item C:\f).$m()`,
		`(Get-Item C:\f).${m}()`,
		`(Get-Item C:\f).('Del'+'ete')()`,
		`$t=[IO.File]; $t::WriteAllText('C:\f','x')`,
		`[IO.File]::'Delete'('C:\f')`,
		`[IO.File]::$m('C:\f')`,
		`(Get-Item C:\f).ForEach('Delete')`,
		`Get-Item C:\f | ForEach-Object Delete`,
		`Get-Item C:\f | % -MemberName 'Delete'`,
		`Get-Item C:\f | foreach Delete`,
		`net 'stop' w32time`,
	)
	psBypass(t, // were reads; .NET members and % NAME are refused now
		`(Get-Item C:\f).'Length'`,
		`Get-Service | % Name`,
		`$h.$key`,
		`[guid]::NewGuid().ToString()`,
		`'Delete'.Length`,
	)
}

func TestPSOpenForWrite(t *testing.T) {
	psBypass(t,
		`[IO.StreamWriter]::new('C:\app\config.json').Close()`,
		`[IO.File]::Open('C:\a','Create').Close()`,
		`[IO.File]::OpenWrite('C:\a').Close()`,
		`[IO.FileStream]::new('C:\a','Truncate')`,
	)
	psBypass(t, // were reads; .NET calls are refused now
		`[guid]::NewGuid()`,
		`[IO.File]::OpenText('C:\a').ReadToEnd()`,
		`[IO.File]::OpenRead('C:\a').Length`,
		`(Get-Item HKLM:\SOFTWARE).OpenSubKey('X')`,
	)
}

func TestPSRelativeCommands(t *testing.T) {
	for _, s := range []string{`.\deploy.ps1`, `..\tool.exe`, `./a.ps1 -x`, `/tools/a.exe`, `7z.exe a x.7z C:\data`, `Get-Date; .\deploy.ps1`} {
		if PSOnlyReads(s) {
			t.Errorf("%q: want not known to only read", s)
		}
	}
	psBypass(t, `.\x\Remove-Item.ps1; & .\stop.ps1; Stop-Service x`)
	// were reads (and the last two known reads); scripts by path and
	// statements that are values are refused now
	psBypass(t, `& .\report.ps1`, `. .\lib.ps1`, `1..10 | % { $_ }`, `1..10 | Sort-Object`, `5; 0x1F; 1.5e3; 2kb`)
}

// TestPSAdminReads: commands admins run every day stay in the subset.
func TestPSAdminReads(t *testing.T) {
	psReads(t,
		`Get-Service`,
		`Get-Service W3SVC, sshd`,
		`Get-Process | Sort-Object CPU -Descending | Select-Object -First 5`,
		`Get-ChildItem C:\inetpub -Recurse`,
		`Get-ChildItem -Path 'C:\Program Files' -Filter *.config -Recurse -Force`,
		`Get-Content C:\app\web.config -Tail 50`,
		`gc "C:\app\logs\app.log" -TotalCount 20`,
		`Get-EventLog -LogName System -Newest 20 -EntryType Error`,
		`Get-WinEvent -LogName Application -MaxEvents 50 | Format-List`,
		`Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, LastBootUpTime`,
		`Get-CimInstance -ClassName Win32_Service -Filter "State = 'Running'"`,
		`Test-Path C:\app\web.config`,
		`Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion`,
		`Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC' -Name Start`,
		`Get-Service | Where-Object { $_.Status -eq 'Running' -and $_.StartType -ne 'Disabled' }`,
		`Get-Process | ? { $_.WorkingSet -gt 104857600 } | % { $_.ProcessName }`,
		`Get-Service | Where-Object Status -eq Stopped | Format-Table -AutoSize`,
		`Get-NetTCPConnection -State Listen | Sort-Object LocalPort`,
		`Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10`,
		`Get-Volume | Format-Table DriveLetter, SizeRemaining, Size`,
		`Get-ScheduledTask -TaskPath \ | Get-ScheduledTaskInfo`,
		`Select-String -Path C:\inetpub\logs\*.log -Pattern ' 500 ' -SimpleMatch | Measure-Object`,
		`Get-LocalGroupMember Administrators`,
		`Get-FileHash C:\tools\agent.exe -Algorithm SHA256`,
		`Get-Date -Format o; hostname; whoami /groups`,
		`netstat -ano; ipconfig /all; tasklist /svc`,
		`Test-NetConnection db01 -Port 1433 -InformationLevel Quiet`,
		`Get-Service |`+"\n"+`  Sort-Object Status |`+"\r\n"+`  Format-Table Name, Status`,
		`Get-ChildItem C:\app | ConvertTo-Json -Depth 2 -Compress`,
		"Get-Service W3SVC\r\nGet-Process w3wp",
	)
}

// TestPSRefusedShapes: one harmless example of every shape the subset
// refuses (the rules in powershell.go), with the reason it gives.
func TestPSRefusedShapes(t *testing.T) {
	for in, why := range map[string]string{
		"Get-Service \u2013Name W3SVC":             "outside plain ASCII",
		"Get-Service\vW3SVC":                       "control character",
		"Get-Service\rW3SVC":                       "control character",
		`Get-Service $name`:                        "$ (variables",
		`Get-Item "$env:TEMP"`:                     "$ inside a string",
		"Get-Ser`vice":                             "backtick",
		`Get-Service @args`:                        "@ (",
		`& Get-Service`:                            "& (",
		`Get-Date && Get-Service`:                  "& (",
		`. .\lib.ps1`:                              "dot-sourcing",
		`.\report.ps1`:                             "by its path",
		`C:\tools\report.exe`:                      "by its path",
		`[Environment]::MachineName`:               "[ (",
		`(Get-Date).Year`:                          "( (",
		`Get-Item C:\x { }`:                        "script block",
		`Get-Service | Where-Object { $_.Stop() }`: "script block",
		`Get-Service | Where-Object -FilterScript { $_.Name }`: "-FilterScript is not a parameter",
		`Get-Service | ForEach-Object Name`:                    "accepted only as",
		`Get-Date > C:\out.txt`:                                "> (",
		`Get-Date >> C:\out.txt`:                               "> (",
		"@'\nx\n'@":                                            "@ (",
		`Get-Date # note`:                                      "# (comments)",
		`Get-Date <# note #>`:                                  "< (",
		`Get-Date; Remove-Item C:\x`:                           "Remove-Item is not on",
		`gsv; ri C:\x`:                                         "ri is not on",
		`Get-Certificate`:                                      "not on komando's list",
		`exit 0`:                                               "keyword",
		`Get-Service -ComputerName db01`:                       "-ComputerName is not a parameter",
		`Get-ChildItem -Rec C:\x`:                              "-Rec is not a parameter",
		`Get-Service -Name:W3SVC`:                              "value attached",
		`Get-Content \\fileserver\share\a.txt`:                 "another computer",
		`Get-Content '\/fileserver/share/a.txt'`:               "another computer",
		`Test-Connection db01 -Source app01`:                   "-Source is not a parameter",
		`Get-Item Microsoft.PowerShell.Core\FileSystem::C:\x`:  "provider paths",
		`Get-Date | | Out-String`:                              "| without a command",
		`Get-Date || Get-Service`:                              "||",
		`'Get-Date'`:                                           "does not start with a command",
		`Get-Item 'C:\x'.Length`:                               "right after",
		`hostname newname`:                                     "only with arguments that read",
		`ipconfig /release`:                                    "only with arguments that read",
		`Get-Service = 1`:                                      "= (",
		`Get-Date 'unclosed`:                                   "closing quote",
		`Get-Service ,W3SVC`:                                   "comma",
	} {
		got := PSReadOnly(in)
		if !strings.Contains(got, why) {
			t.Errorf("%q: want a refusal with %q, got %q", in, why, got)
		}
		if PSOnlyReads(in) {
			t.Errorf("%q: want not known to only read", in)
		}
	}
}
