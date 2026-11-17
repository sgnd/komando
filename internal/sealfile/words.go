package sealfile

import (
	"crypto/sha256"
	_ "embed"
	"strings"
)

// bip39English is the BIP-39 English word list, verbatim (2048 words, one
// per line, each line ending in a line feed; its SHA-256 is pinned in a
// test, and the iPhone app pins the same). The list is from
// github.com/bitcoin/bips, bip-0039/english.txt, under the MIT license.
//
//go:embed bip39_english.txt
var bip39English string

// Words is the word list, in order.
var Words = strings.Fields(bip39English)

// PhraseWords is how many words a check phrase has.
const PhraseWords = 6

// CheckPhrase is the check phrase of a whole sealed file: the first 66
// bits of its SHA-256, read 11 bits at a time from the most significant
// bit of the first byte, each a word of the list. The terminal prints it
// and the phone shows it for the file it received; the person compares
// them. It opens nothing.
func CheckPhrase(file []byte) []string {
	sum := sha256.Sum256(file)
	words := make([]string, PhraseWords)
	for i := range words {
		v := 0
		for b := i * 11; b < i*11+11; b++ {
			v = v<<1 | int(sum[b/8]>>(7-b%8)&1)
		}
		words[i] = Words[v]
	}
	return words
}
