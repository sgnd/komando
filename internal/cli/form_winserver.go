package cli

import (
	"net/url"
	"strconv"

	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// The Windows questions of the server form: what the server runs, then for
// Windows whether komando reaches it over OpenSSH (the same questions as
// Linux, plus --os windows) or WinRM (winrm://USER@HOST and a password the
// command asks hidden).

// serverOSQ asks what the server runs.
func serverOSQ() formQ {
	return formQ{key: "os", label: "System", ask: "What does the server run?",
		help: "Windows servers run commands in PowerShell; everything else is treated like Linux.",
		def:  func(*store.State, formAnswers) string { return "linux" },
		choices: func(*store.State, formAnswers) []menuRow {
			return []menuRow{{label: "Linux", detail: "or another Unix, like FreeBSD", value: "linux"},
				{label: "Windows", detail: "Windows Server, over OpenSSH or WinRM", value: "windows"}}
		}}
}

// serverTransportQ asks how komando reaches a Windows server.
func serverTransportQ() formQ {
	return formQ{key: "transport", label: "Connection", ask: "How does komando reach this Windows server?",
		help: "Not sure? Ask whoever runs it. WinRM is often on already, as Ansible uses it; OpenSSH also gives shell and tunnels.",
		show: func(a formAnswers) bool { return a["os"] == "windows" },
		def:  func(*store.State, formAnswers) string { return "ssh" },
		choices: func(*store.State, formAnswers) []menuRow {
			return []menuRow{{label: "OpenSSH", detail: "built into Windows Server 2019 and later; a key or a password", value: "ssh"},
				{label: "WinRM", detail: "HTTPS on port 5986, a user and a password", value: "winrm"}}
		}}
}

// serverWinRM: the answers add a Windows server over WinRM.
func serverWinRM(a formAnswers) bool { return a["os"] == "windows" && a["transport"] == "winrm" }

// serverWinRMTLSQ asks how WinRM encrypts: HTTPS with the certificate
// checked is the default; the other two say what they give up.
func serverWinRMTLSQ() formQ {
	return formQ{key: "winrmtls", label: "Encryption", ask: "How does WinRM encrypt the connection?",
		help: "Pick the first unless komando test says the certificate is not trusted. A certificate from your company's CA: keep the first and see " + releaseSite + "/blob/main/docs/features/windows.md.",
		show: serverWinRM,
		def:  func(*store.State, formAnswers) string { return "" },
		choices: func(*store.State, formAnswers) []menuRow {
			return []menuRow{{label: "HTTPS, checked", detail: "port 5986; winrm quickconfig -transport:https turns it on", value: ""},
				{label: "HTTPS, certificate not checked", detail: "for a certificate the server made itself", value: "skip-verify"},
				{label: "HTTP, unencrypted", detail: "port 5985; commands and output can be read on the way", value: "off"}}
		}}
}

// serverWinRMPortQ asks the WinRM port: 5986 for HTTPS, 5985 for HTTP,
// or the one typed after the address.
func serverWinRMPortQ() formQ {
	return formQ{key: "winrmport", label: "Port", ask: "Which WinRM port does it use?",
		help: "Almost always 5986 for HTTPS and 5985 for HTTP.", show: serverWinRM, check: formPortProblem,
		def: func(_ *store.State, a formAnswers) string {
			if h, err := sshx.ParseAdhoc(a["address"]); err == nil && h.Port != 0 {
				return strconv.Itoa(h.Port)
			}
			return serverWinRMUsualPort(a)
		}}
}

func serverWinRMUsualPort(a formAnswers) string {
	if a["winrmtls"] == "off" {
		return "5985"
	}
	return "5986"
}

// serverWinRMBuild is host add NAME winrm://USER@HOST: WinRM always logs
// in with a password, which the command asks for hidden.
func serverWinRMBuild(a formAnswers) [][]string {
	addr := a["address"]
	if h, err := sshx.ParseAdhoc(addr); err == nil {
		addr = h.Address
	}
	w := "winrm://" + a["user"] + "@" + formHostPort(addr, a["winrmport"], serverWinRMUsualPort(a))
	if a["winrmtls"] != "" {
		w += "?" + url.Values{"tls": {a["winrmtls"]}}.Encode()
	}
	args := []string{"host", "add", a["name"], w, "--ask-password"}
	return [][]string{formFlags(args, a), {"test", a["name"]}}
}
