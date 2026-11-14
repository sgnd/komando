// Package komandosync is a PROTOTYPE of the open sync format and
// cryptography used by the Komando apps (phase 1 of
// komando-notes/paid/phases.md). It is its own Go module,
// github.com/sgnd/komando/sync, and the komando CLI never imports it, so
// the CLI binary does not contain it. It opens no network connection and
// has no command. The CLI never syncs.
//
// The package is named komandosync, not sync, so that it does not hide the
// standard library's sync package in the files that import it.
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
//     only with an authority key's signed yes. Two records of one type
//     that took one name on two devices at once both wait as "name taken"
//     until a person picks one.
//   - Removed devices (removal.go): which of their writes count, from the
//     list and the signed summaries of listed devices.
//   - Snapshots (snapshot.go, state.go): the signed, sealed state at a
//     summary, after which older writes can go; a new device starts from
//     one.
//   - Recovery kits (kit.go, shamir.go, recover.go): a 256-bit key as
//     letters, a 2-of-3 paper split, and the 24-hour wait.
//   - A hostile in-memory server (server.go) for the tests.
package komandosync
