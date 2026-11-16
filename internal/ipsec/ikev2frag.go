package ipsec

// reassemble keeps fragment num of total (RFC 7383) of m's message, with
// the first payload type first and its decrypted plain. Once all have
// come, it returns the whole message's first payload type and plaintext.
// k.mu is held.
func (k *ikeV2) reassemble(m *v2msg, num, total int, first byte, plain []byte) (byte, []byte, bool) {
	key := m.id
	if m.flags&flagResp == 0 {
		key |= 1 << 31 // requests and responses may share an id
	}
	f := k.frags[key]
	if f == nil || f.total != total {
		f = &fragSet{total: total, parts: map[int][]byte{}}
		k.frags[key] = f
	}
	if num == 1 {
		f.next = first
	}
	f.parts[num] = plain
	if len(f.parts) < f.total {
		return 0, nil, false
	}
	delete(k.frags, key)
	var whole []byte
	for i := 1; i <= f.total; i++ {
		whole = append(whole, f.parts[i]...)
	}
	return f.next, whole, true
}
