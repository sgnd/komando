// Package syncproto is a PROTOTYPE of the sync cryptography of the paid
// Komando apps (phase 1 of komando-notes/paid/phases.md). It is not used by
// the komando CLI: nothing in internal/cli imports it, it opens no network
// connection and it has no command. The CLI never syncs.
//
// It answers one question: does the design in the paid spec, section 6, and
// in sync-security.md sections 6 to 9 (called SS here) work as written? What
// was built and every place the design did not work as written are in
// docs/design/sync-prototype.md.
//
// The parts:
//
//   - Device keys (keys.go): a sync key and an authority key behind the
//     Signer interface, so the Secure Enclave can stand in later, and an
//     X-Wing unwrap key behind Unwrapper. SoftSigner is the software stand-in.
//   - Records (seal.go, write.go): AES-256-GCM under a key used once, derived
//     with HKDF-SHA256 together with a key commitment tag; every write is
//     signed by the device's sync key and chained to its previous write.
//   - Key transport (keys.go): HPKE with X-Wing (ML-KEM-768 + X25519) from
//     Go's crypto/hpke.
//   - The device list (list.go, listcheck.go): a signed hash chain checked
//     from entry 1, with pending changes that wait, can be cancelled and are
//     then applied.
//   - State summaries (write.go, sync.go): signed per-device summaries, so
//     the server cannot roll back, hide, reorder or replay writes unnoticed.
//   - Changes that wait for a person (merge.go): a change that moves a
//     secret, changes what runs, who is reached or what protects applies
//     only with an authority key's signed yes.
//   - Recovery kits (kit.go, shamir.go, recover.go): a 256-bit key as
//     letters, a 2-of-3 paper split, and the 24-hour wait.
//   - A hostile in-memory server (server.go) for the tests.
package syncproto
