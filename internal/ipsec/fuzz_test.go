package ipsec

import "testing"

// The parsers see what any host on the network sends: they must never
// panic.
func FuzzParsers(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 8, 1, 1, 0, 1})
	f.Add([]byte{2, 0, 0, 12, 1, 3, 4, 1, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		parseChain(plSA, b)
		parseAttrs(b)
		parseChosen(b)
		parseProposals(b)
		pickESP(b)
		pickIKE(b)
		chosenIKE(b)
		chosenESP(b)
		(&eapClient{user: "u", password: "p"}).answer(b)
		k := &ikeV1{ivs: map[uint32][]byte{}, lastIn: map[uint32][]byte{}, lastOut: map[uint32][]byte{}}
		k.parse(b)
		v := &ikeV2{frags: map[uint32]*fragSet{}}
		v.open(b)
	})
}
