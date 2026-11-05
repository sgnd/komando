package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// vpn status explains how the last session ended: the reason with its
// time, and for the IPsec kinds the log's last lines.
func TestLastSessionEnd(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	dir, err := vpnDir()
	if err != nil {
		t.Fatal(err)
	}
	log := "2026/11/05 12:40:00 IKEv1: ESP up\nREADY 127.0.0.1:1\n" +
		"2026/11/05 13:20:07 ENDED the L2TP server ended the session (result 1) (after 1h28m6s)\n"
	if err := os.WriteFile(filepath.Join(dir, "duwit.log"), []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	end, lines := lastSessionEnd("duwit", true)
	if end != "2026/11/05 13:20:07: the L2TP server ended the session (result 1) (after 1h28m6s)" || len(lines) != 3 {
		t.Fatalf("got %q %q", end, lines)
	}
	if _, lines := lastSessionEnd("duwit", false); lines != nil {
		t.Fatal("log lines for a kind that does not want them")
	}
	// older logs: ENDED at the start of the line, and ERROR for a failed start
	os.WriteFile(filepath.Join(dir, "old.log"), []byte("ENDED closed\nERROR VPN_DOWN: no answer\n"), 0o600)
	if end, _ := lastSessionEnd("old", false); end != "VPN_DOWN: no answer" {
		t.Fatalf("got %q", end)
	}
}
