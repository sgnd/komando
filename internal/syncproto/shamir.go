package syncproto

import (
	"crypto/rand"
	"errors"
)

// Shamir secret sharing over GF(2^8) with the AES polynomial
// x^8 + x^4 + x^3 + x + 1, written here from the textbook definition
// (Shamir 1979). Multiplication runs without tables or branches on secret
// bytes.

func gfMul(a, b byte) byte {
	var p byte
	for range 8 {
		p ^= a & -(b & 1)
		hi := -(a >> 7)
		a = a<<1 ^ 0x1b&hi
		b >>= 1
	}
	return p
}

// gfInv is a^254, which is 1/a for a != 0.
func gfInv(a byte) byte {
	r := byte(1)
	for range 7 {
		a = gfMul(a, a)
		r = gfMul(r, a)
	}
	return r
}

// shamirSplit splits secret into n shares, any k of which give it back.
// Share i is evaluated at x = i+1.
func shamirSplit(secret []byte, n, k int) ([][]byte, error) {
	if k < 2 || k > n || n > 255 {
		return nil, errors.New("syncproto: bad share counts")
	}
	shares := make([][]byte, n)
	for i := range shares {
		shares[i] = make([]byte, len(secret))
	}
	coef := make([]byte, k)
	for pos, s := range secret {
		coef[0] = s
		if _, err := rand.Read(coef[1:]); err != nil {
			return nil, err
		}
		for i := range n {
			x := byte(i + 1)
			// Horner: c[k-1] x^(k-1) + ... + c[0]
			var y byte
			for j := k - 1; j >= 0; j-- {
				y = gfMul(y, x) ^ coef[j]
			}
			shares[i][pos] = y
		}
	}
	clear(coef)
	return shares, nil
}

// shamirCombine gives the secret back from shares at the given x values
// (Lagrange at 0).
func shamirCombine(xs []byte, shares [][]byte) ([]byte, error) {
	if len(xs) != len(shares) || len(xs) < 2 {
		return nil, errors.New("syncproto: need at least two parts")
	}
	for i := range xs {
		if xs[i] == 0 || len(shares[i]) != len(shares[0]) {
			return nil, errors.New("syncproto: bad part")
		}
		for j := range i {
			if xs[i] == xs[j] {
				return nil, errors.New("syncproto: the same part twice")
			}
		}
	}
	out := make([]byte, len(shares[0]))
	for i := range xs {
		// l_i(0) = prod_{j != i} x_j / (x_j - x_i); minus is xor here.
		l := byte(1)
		for j := range xs {
			if j != i {
				l = gfMul(l, gfMul(xs[j], gfInv(xs[j]^xs[i])))
			}
		}
		for pos := range out {
			out[pos] ^= gfMul(shares[i][pos], l)
		}
	}
	return out, nil
}
