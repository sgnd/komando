package cli

import "testing"

// The typed question's first line reads "This <reason>." (S-7.2, M-11):
// a verb phrase follows "This", and anything else still reads as a
// sentence.
func TestDangerLine(t *testing.T) {
	for reason, want := range map[string]string{
		"deletes every message in orders-retry (it stays)": "This deletes every message in orders-retry (it stays).",
		"stops every copy of deployment/api (scale to 0)":  "This stops every copy of deployment/api (scale to 0).",
		"powers off or reboots the server":                 "This powers off or reboots the server.",
		"matches your deny rule kubectl":                   "This matches your deny rule kubectl.",
		"docker rm web":                                    "This is dangerous: docker rm web.",
		"komando logs in to web1 with this key":            "This is dangerous: komando logs in to web1 with this key.",
		"removes the user bob.":                            "This removes the user bob.",
	} {
		if got := dangerLine(reason); got != want {
			t.Errorf("dangerLine(%q) = %q, want %q", reason, got, want)
		}
	}
}
