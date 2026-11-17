package ipsec

import "testing"

// Once the keys exist, an unencrypted message is anyone's: a spoofed
// Delete or CREATE_CHILD_SA must never reach the handlers.
func TestIKEv2RefusesPlaintextAfterKeys(t *testing.T) {
	s := ikeSuite{aes256, integSHA256, hSHA256, 14}
	srv := &ikeV2{spiI: random(8), spiR: random(8), weInit: false, suite: s, frags: map[uint32]*fragSet{}}
	srv.derive(random(32), random(32), random(32), srv.spiI, srv.spiR)
	k := &ikeV2{spiI: srv.spiI, spiR: srv.spiR, weInit: true, suite: s, frags: map[uint32]*fragSet{},
		skD: srv.skD, skAi: srv.skAi, skAr: srv.skAr, skEi: srv.skEi, skEr: srv.skEr}
	del := []v1Payload{{typ: pDelete, body: []byte{1, 0, 0, 0}}}
	for _, exch := range []byte{exInfo2, exChild, exAuth} {
		if m, err := k.open(srv.plain(exch, 0, del)); err == nil || m != nil {
			t.Fatalf("exchange %d: a plaintext request was accepted", exch)
		}
	}
	// a late IKE_SA_INIT response is dropped quietly, not handled
	resp := srv.plain(exSAInit, 0, nil)
	resp[19] |= flagResp
	if m, err := k.open(resp); m != nil || err != nil {
		t.Fatalf("a late IKE_SA_INIT response: %v %v", m, err)
	}
	// a plaintext IKE_SA_INIT request would move the peer's message ids
	if m, err := k.open(srv.plain(exSAInit, 0, nil)); err == nil || m != nil {
		t.Fatal("a plaintext IKE_SA_INIT request was accepted")
	}
	// before the keys, only the IKE_SA_INIT response is read
	fresh := &ikeV2{spiI: k.spiI, frags: map[uint32]*fragSet{}}
	if m, err := fresh.open(resp); err != nil || m == nil {
		t.Fatalf("the IKE_SA_INIT response: %v", err)
	}
	if m, err := fresh.open(srv.plain(exInfo2, 0, del)); err == nil || m != nil {
		t.Fatal("a plaintext Delete before the keys was accepted")
	}
}
