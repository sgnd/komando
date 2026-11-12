package cli

import "strings"

// doctorLabels are the words a person reads for a check; -o json keeps
// the names (M-7).
var doctorLabels = map[string]string{
	"state": "komando folder", "audit_log": "audit log", "hosts": "servers", "keys": "SSH keys",
	"ssh_agent": "ssh-agent", "openssh_client": "OpenSSH client", "platform": "this computer",
	"agent_skill": "AI agent skill", "agent_guard": "Claude Code guard",
}

// doctorLabel is a check's name in plain words: "VPN office needs
// openconnect" for vpn:office:openconnect.
func doctorLabel(name string) string {
	if l, ok := doctorLabels[name]; ok {
		return l
	}
	if rest, ok := strings.CutPrefix(name, "vpn:"); ok {
		if vpn, bin, ok := strings.Cut(rest, ":"); ok {
			return "VPN " + vpn + " needs " + bin
		}
	}
	return name
}
