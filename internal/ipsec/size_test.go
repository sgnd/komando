package ipsec

import "testing"

// The first messages must fit in one packet without IP fragmentation.
func TestFirstMessagesFitOnePacket(t *testing.T) {
	if n := 28 + 4 + len(p1SA(65001, 28800, 0)) + 7*20; n > 1200 {
		t.Fatalf("IKEv1 main mode message 1 is %d bytes", n)
	}
	if n := 28 + 4 + len(ikeProposals(14)) + 4 + 4 + 256 + 4 + 32 + 2*28 + 20; n > 1200 {
		t.Fatalf("IKE_SA_INIT is %d bytes", n)
	}
}
