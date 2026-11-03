package cloud

import "testing"

func FuzzSSMMessage(f *testing.F) {
	f.Add(encodeSSM(ssmMsg{typ: ssmOutput, seq: 1, payType: payOutput, payload: []byte("x")}))
	f.Add(make([]byte, 119))
	f.Fuzz(func(t *testing.T, b []byte) { decodeSSM(b) })
}

func FuzzBitwardenCipherString(f *testing.F) {
	key := make([]byte, 64)
	f.Add("2.AAAA|BBBB|CCCC")
	f.Add("4.xyz")
	f.Fuzz(func(t *testing.T, s string) { BitwardenDecrypt(s, key) })
}
