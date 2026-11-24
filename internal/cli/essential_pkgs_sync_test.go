package cli

import (
	"testing"

	"github.com/sgnd/komando/internal/policy"
)

// pkg rm and the exec rule pkg-remove-essential guard the same packages
// until the package area is removed.
func TestEssentialPackagesMatchPolicy(t *testing.T) {
	for _, name := range append(essentialSamples, "OpenSSH-Server", "openssh-server:amd64", "sudo=1.9.15", "sudo.x86_64", "openssh.server", "nginx", "httpd", "curl") {
		if essentialPkg(name) != policy.EssentialPackage(name) {
			t.Errorf("%s: pkg rm says %v, policy says %v", name, essentialPkg(name), policy.EssentialPackage(name))
		}
	}
}
