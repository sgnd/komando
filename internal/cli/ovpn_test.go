package cli

import (
	"os/exec"
	"strings"
	"testing"
)

// Every embedded shell script must at least parse: a broken entrypoint
// means no OpenVPN container ever starts.
func TestEmbeddedScriptsParse(t *testing.T) {
	entries, err := ovpnFiles.ReadDir("ovpn")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sh") {
			continue
		}
		b, _ := ovpnFiles.ReadFile("ovpn/" + e.Name())
		c := exec.Command("sh", "-n")
		c.Stdin = strings.NewReader(string(b))
		if out, err := c.CombinedOutput(); err != nil {
			t.Errorf("%s does not parse: %v %s", e.Name(), err, out)
		}
	}
}
