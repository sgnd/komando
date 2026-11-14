// crosscheck.swift recomputes testdata/vectors.json with Apple CryptoKit, an
// implementation separate from the Go prototype. It is the second, outside
// computation behind every vector. Run it on a Mac (macOS 26 or later, for
// X-Wing in CryptoKit):
//
//	swift sync/testdata/crosscheck.swift sync/testdata/vectors.json
//
// It prints one line per check and exits 1 if any value differs.

import CryptoKit
import Foundation

let v = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))) as! [String: Any]
var failed = false

func hex(_ s: String) -> Data {
    var d = Data()
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        d.append(UInt8(s[i..<j], radix: 16)!)
        i = j
    }
    return d
}

func hx(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

func check(_ name: String, _ ok: Bool) {
    print(ok ? "ok    " : "FAIL  ", name)
    if !ok { failed = true }
}

func u32(_ n: Int) -> Data { Data([UInt8(n >> 24 & 255), UInt8(n >> 16 & 255), UInt8(n >> 8 & 255), UInt8(n & 255)]) }

// sum: SHA-256(label || 0 || for each part: 4-byte length || part).
func sum(_ label: String, _ parts: [Data]) -> Data {
    var m = Data(label.utf8)
    m.append(0)
    for p in parts { m.append(u32(p.count)); m.append(p) }
    return Data(SHA256.hash(data: m))
}

func hkdf(_ ikm: Data, salt: Data, info: Data, _ n: Int) -> Data {
    HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: info, outputByteCount: n)
        .withUnsafeBytes { Data($0) }
}

func padme(_ l: Int) -> Int {
    if l < 2 { return l }
    let e = Int.bitWidth - l.leadingZeroBitCount - 1
    let s = Int.bitWidth - e.leadingZeroBitCount
    let mask = (1 << (e - s)) - 1
    return (l + mask) & ~mask
}

let crockford = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

func base32(_ b: Data) -> String {
    var out = ""
    var acc = 0, n = 0
    for c in b {
        acc = (acc << 8 | Int(c)) & 0xFFFF
        n += 8
        while n >= 5 { out.append(crockford[(acc >> (n - 5)) & 31]); n -= 5 }
    }
    if n > 0 { out.append(crockford[(acc << (5 - n)) & 31]) }
    return out
}

func unbase32(_ s: String) -> Data {
    var out = Data()
    var acc = 0, n = 0
    for ch in s where ch != " " {
        acc = (acc << 5 | crockford.firstIndex(of: ch)!) & 0xFFFF
        n += 5
        if n >= 8 { out.append(UInt8((acc >> (n - 8)) & 255)); n -= 8 }
    }
    return out
}

func groups(_ s: String) -> String {
    var parts: [String] = []
    var rest = Substring(s)
    while rest.count > 4 { parts.append(String(rest.prefix(4))); rest = rest.dropFirst(4) }
    parts.append(String(rest))
    return parts.joined(separator: " ")
}

func gfMul(_ a0: UInt8, _ b0: UInt8) -> UInt8 {
    var a = a0, b = b0, p: UInt8 = 0
    for _ in 0..<8 {
        if b & 1 != 0 { p ^= a }
        let hi = a & 0x80
        a <<= 1
        if hi != 0 { a ^= 0x1b }
        b >>= 1
    }
    return p
}

func gfInv(_ a: UInt8) -> UInt8 {
    var r: UInt8 = 1
    for _ in 0..<254 { r = gfMul(r, a) }
    return r
}

// Record sealing: HKDF-SHA256(vault key, seed, label || 0 || SHA-256(place))
// gives key || commit; AES-256-GCM with a zero nonce over the padded body.
let rs = v["record_seal"] as! [String: String]
let place = hex(rs["Place"]!)
var info = Data("komando-sync/1 record".utf8)
info.append(0)
info.append(Data(SHA256.hash(data: place)))
let okm = hkdf(hex(rs["VaultKey"]!), salt: hex(rs["Seed"]!), info: info, 64)
check("record commit", hx(okm.suffix(32)) == rs["Commit"]!)
let plain = hex(rs["Plaintext"]!)
var padded = u32(plain.count) + plain
padded.append(Data(count: padme(4 + plain.count) - padded.count))
let box = try AES.GCM.seal(padded, using: SymmetricKey(data: okm.prefix(32)), nonce: AES.GCM.Nonce(data: Data(count: 12)), authenticating: place)
check("record ciphertext", hx(box.ciphertext + box.tag) == rs["Ciphertext"]!)

for (k, want) in v["padme"] as! [String: Int] {
    let l = hex(k).reduce(0) { $0 << 8 | Int($1) }
    check("padme \(l)", padme(l) == want)
}

let kid = v["key_id"] as! [String: String]
check("key id", hx(sum("komando-sync/1 key id", [hex(kid["account_key"]!)]).prefix(16)) == kid["key_id"]!)

// The recovery kit: letters, challenge, and both derived public keys.
let kit = v["recovery_kit"] as! [String: Any]
let key = hex(kit["Key"] as! String)
let letters = groups(base32(key + sum("komando-sync/1 kit check", [key]).prefix(3)))
check("kit letters", letters == kit["Letters"] as! String)
let ch = sum("komando-sync/1 kit check", [Data("challenge".utf8), key])
let a = Int(ch[0]) % 14
var b = Int(ch[1]) % 13
if b >= a { b += 1 }
check("kit challenge", [a, b] == kit["Challenge"] as! [Int])
let scalar = hkdf(key, salt: Data(), info: Data("komando-sync/1 kit signing key 0".utf8), 32)
let signKey = try P256.Signing.PrivateKey(rawRepresentation: scalar)
check("kit signing key", hx(signKey.publicKey.x963Representation) == kit["SignPub"] as! String)
let sealKey = try XWingMLKEM768X25519.PrivateKey(seedRepresentation: hex(kit["SealSeed"] as! String), publicKey: nil)
check("kit sealing key (X-Wing from seed)", hx(sealKey.publicKey.rawRepresentation) == kit["SealPub"] as! String)

// Paper parts: number, kit ID, share, check; any two give the key back.
let paper = v["kit_paper_2_of_3"] as! [String: Any]
var xs: [UInt8] = [], shares: [Data] = []
for p in (paper["Parts"] as! [String]).prefix(2) {
    let raw = unbase32(p)
    let payload = raw.prefix(raw.count - 2)
    check("paper part check", sum("komando-sync/1 kit part check", [payload]).prefix(2) == raw.suffix(2))
    check("paper part kit id", payload.dropFirst().prefix(2) == sum("komando-sync/1 kit id", [key]).prefix(2))
    xs.append(payload.first!)
    shares.append(Data(payload.dropFirst(3)))
}
var secret = Data(count: 32)
for i in 0..<2 {
    let j = 1 - i
    let l = gfMul(xs[j], gfInv(xs[j] ^ xs[i]))
    for pos in 0..<32 { secret[pos] ^= gfMul(shares[i][pos], l) }
}
check("paper parts give the kit back", hx(secret) == paper["Secret"] as! String)

// HPKE with X-Wing, HKDF-SHA256, AES-256-GCM: the exact suite.
let hp = v["hpke_xwing"] as! [String: Any]
let xk = try XWingMLKEM768X25519.PrivateKey(seedRepresentation: hex(hp["Seed"] as! String), publicKey: nil)
check("hpke public key", hx(xk.publicKey.rawRepresentation) == hp["PublicKey"] as! String)
let sealed = hex(hp["Ciphertext"] as! String)
var rcpt = try HPKE.Recipient(privateKey: xk, ciphersuite: .XWingMLKEM768X25519_SHA256_AES_GCM_256,
                              info: hex(hp["Info"] as! String), encapsulatedKey: sealed.prefix(1120))
check("hpke opens", hx(try rcpt.open(sealed.dropFirst(1120))) == hp["Plaintext"] as! String)

// ECDSA P-256 in the fixed form: r || s, s in the lower half.
let sg = v["ecdsa_p256_fixed_form"] as! [String: String]
let sk = try P256.Signing.PrivateKey(rawRepresentation: hex(sg["Scalar"]!))
check("signature public key", hx(sk.publicKey.x963Representation) == sg["PublicKey"]!)
var msg = Data(sg["Label"]!.utf8)
msg.append(0)
msg.append(hex(sg["Body"]!))
let sig = try P256.Signing.ECDSASignature(rawRepresentation: hex(sg["Sig"]!))
check("signature verifies", sk.publicKey.isValidSignature(sig, for: msg))
// s must be at most n / 2 (big-endian bytes of equal length compare as numbers).
let order = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
var half = Data(count: 32), carry = 0
for (i, byte) in order.enumerated() {
    half[i] = UInt8((carry << 8 | Int(byte)) >> 1)
    carry = Int(byte) & 1
}
check("signature s in the lower half", !half.lexicographicallyPrecedes(hex(sg["Sig"]!).suffix(32)))

let en = v["list_entry"] as! [String: String]
check("list entry hash", hx(sum("komando-sync/1 list entry hash", [hex(en["SignedBytes"]!)])) == en["Hash"]!)

let pc = v["pairing_code"] as! [String: String]
// The 27th character is the check: each character's value times an odd
// weight (1, 3, 5, ...), summed mod 32.
let pc26 = base32(hex(pc["secret"]!))
var pcSum = 0
for (i, c) in pc26.enumerated() { pcSum += (2 * i + 1) * crockford.firstIndex(of: c)! }
check("pairing code", pc26 + String(crockford[pcSum & 31]) == pc["code"]!)

// Snapshot: the state's hash, the record seal with the header as its
// place, and the hash over the header and the sealed body.
let sn = v["snapshot"] as! [String: String]
let snHeader = hex(sn["Header"]!)
check("snapshot state hash", hx(sum("komando-sync/1 snapshot state", [hex(sn["State"]!)])) == sn["StateHash"]!)
// The header: version 1, suite 1, then its fields in order.
var snBuilt = Data([1, 0, 1])
for k in ["Account", "Signer", "Num", "ListNum", "ListHash", "KeyGen", "Heads", "StateHash"] { snBuilt += hex(sn[k]!) }
check("snapshot header", hx(snBuilt) == sn["Header"]!)
var snInfo = Data("komando-sync/1 record".utf8)
snInfo.append(0)
snInfo.append(Data(SHA256.hash(data: snHeader)))
let snOkm = hkdf(hex(sn["VaultKey"]!), salt: hex(sn["Seed"]!), info: snInfo, 64)
check("snapshot commit", hx(snOkm.suffix(32)) == sn["Commit"]!)
let snPlain = hex(sn["State"]!)
var snPadded = u32(snPlain.count) + snPlain
snPadded.append(Data(count: padme(4 + snPlain.count) - snPadded.count))
let snBox = try AES.GCM.seal(snPadded, using: SymmetricKey(data: snOkm.prefix(32)), nonce: AES.GCM.Nonce(data: Data(count: 12)), authenticating: snHeader)
let snCT = snBox.ciphertext + snBox.tag
check("snapshot ciphertext", hx(snCT) == sn["Ciphertext"]!)
check("snapshot hash", hx(sum("komando-sync/1 snapshot hash", [snHeader + hex(sn["Seed"]!) + hex(sn["Commit"]!) + u32(snCT.count) + snCT])) == sn["Hash"]!)

// A deny rule's ID: 12 bytes bound to the write that makes it, then the
// 4-byte tag of its type.
let dn = v["deny_rule_id"] as! [String: String]
let dnRnd = sum("komando-sync/1 deny rule id", [hex(dn["writer"]!), hex(dn["seq"]!)]).prefix(12)
check("deny rule id", hx(dnRnd + sum("komando-sync/1 record type", [Data("deny".utf8), dnRnd]).prefix(4)) == dn["id"]!)

// An approval signs the change it agrees to and its record, the old
// holders of its name that the same yes deletes, and the waiting changes
// for that name it sets aside.
let ap = v["approval_bytes"] as! [String: String]
let apParts: [Data] = [hex(ap["account"]!), hex(ap["writer"]!), hex(ap["seq"]!), hex(ap["hash"]!), hex(ap["record"]!),
                       u32(1), hex(ap["replaces"]!), u32(1), hex(ap["withdraw_writer"]!), hex(ap["withdraw_seq"]!), hex(ap["withdraw_hash"]!)]
let apBytes = apParts.reduce(Data(), +)
check("approval bytes", hx(apBytes) == ap["bytes"]!)

// Layouts, built from their fields: numbers big-endian, strings and byte
// strings with a 4-byte length, lists with a 4-byte count.
typealias Obj = [String: Any]
func cat(_ parts: [Data]) -> Data { parts.reduce(Data(), +) }
func H(_ o: Obj, _ k: String) -> Data { hex(o[k] as! String) }
func I(_ o: Obj, _ k: String) -> Int { o[k] as! Int }
func S(_ o: Obj, _ k: String) -> String { o[k] as! String }
func u8(_ n: Int) -> Data { Data([UInt8(n & 255)]) }
func u16(_ n: Int) -> Data { Data([UInt8(n >> 8 & 255), UInt8(n & 255)]) }
func u64(_ n: Int) -> Data { cat([u32(n >> 32), u32(n & 0xFFFF_FFFF)]) }
func str(_ s: String) -> Data { cat([u32(s.utf8.count), Data(s.utf8)]) }
func flag(_ o: Obj, _ k: String) -> Data { u8(o[k] as! Bool ? 1 : 0) }
func fieldPairs(_ o: Obj, _ k: String) -> Data {
    let fs = o[k] as! [[String]]
    return cat([u32(fs.count)] + fs.map { cat([str($0[0]), str($0[1])]) })
}
func idList(_ o: Obj, _ k: String) -> Data {
    let ids = o[k] as! [String]
    return cat([u32(ids.count)] + ids.map(hex))
}
func ref(_ o: Obj, _ w: String = "Writer", _ q: String = "Seq", _ h: String = "Hash") -> Data { cat([H(o, w), u64(I(o, q)), H(o, h)]) }
func heads(_ o: Obj, _ k: String) -> Data {
    let hs = o[k] as! [Obj]
    return cat([u32(hs.count)] + hs.map { ref($0, "Device") })
}
func refList(_ o: Obj, _ k: String) -> Data {
    let rs = o[k] as! [Obj]
    return cat([u32(rs.count)] + rs.map { ref($0) })
}
func clock(_ o: Obj) -> Data { cat([u64(I(o, "Wall")), u32(I(o, "Count")), H(o, "Dev")]) }
func byRef(_ a: Obj, _ b: Obj) -> Bool {
    let x = H(a, "Writer"), y = H(b, "Writer")
    return x != y ? x.lexicographicallyPrecedes(y) : I(a, "Seq") < I(b, "Seq")
}

// A summary: Prev after Num, Snap and Base after the heads (SS 9).
let sm = v["summary"] as! Obj
let smBytes = cat([H(sm, "Account"), H(sm, "Signer"), u64(I(sm, "Num")), H(sm, "Prev"), u32(I(sm, "KeyGen")),
                   u32(I(sm, "ListNum")), H(sm, "ListHash"), u32(I(sm, "MinClient")), heads(sm, "Heads"),
                   H(sm, "Snap"), H(sm, "Base")])
check("summary signed bytes", hx(smBytes) == S(sm, "SignedBytes"))
check("summary hash", hx(sum("komando-sync/1 summary hash", [smBytes])) == S(sm, "Hash"))

// A deny rule written again: its ID is bound to the dropped write and the
// rule's fields.
let da = v["deny_rule_written_again_id"] as! Obj
let daRnd = sum("komando-sync/1 deny rule written again", [cat([ref(da), fieldPairs(da, "Fields")])]).prefix(12)
let daTag = sum("komando-sync/1 record type", [Data("deny".utf8), daRnd]).prefix(4)
check("deny rule written again id", hx(daRnd + daTag) == S(da, "ID"))

// A sealed body's plaintext, with Target after the fields.
let cv = v["change_deny_written_again"] as! Obj
let cvBytes = cat([u8(I(cv, "Kind")), H(cv, "Record"), str(S(cv, "Type")), flag(cv, "Create"), flag(cv, "Delete"),
                   fieldPairs(cv, "Fields"), ref(cv, "TargetWriter", "TargetSeq", "TargetHash"),
                   idList(cv, "Replaces"), refList(cv, "Withdraws"), H(cv, "Approval")])
check("change bytes", hx(cvBytes) == S(cv, "Bytes"))
check("change names the deny rule written again", S(cv, "Record") == S(da, "ID"))

// A write: the header is the seal's place; the change above is its body.
let wv = v["write"] as! Obj
let wvHeader = cat([u8(1), u16(1), H(wv, "Account"), H(wv, "Vault"), H(wv, "Writer"), u64(I(wv, "Seq")), H(wv, "Prev"),
                    u32(I(wv, "ListNum")), H(wv, "ListHash"), u32(I(wv, "KeyGen")), u64(I(wv, "Wall")), u32(I(wv, "Count"))])
check("write header", hx(wvHeader) == S(wv, "Header"))
var wvInfo = Data("komando-sync/1 record".utf8)
wvInfo.append(0)
wvInfo.append(Data(SHA256.hash(data: wvHeader)))
let wvOkm = hkdf(hex(rs["VaultKey"]!), salt: H(wv, "Seed"), info: wvInfo, 64)
check("write commit", hx(wvOkm.suffix(32)) == S(wv, "Commit"))
var wvPadded = u32(cvBytes.count) + cvBytes
wvPadded.append(Data(count: padme(4 + cvBytes.count) - wvPadded.count))
let wvBox = try AES.GCM.seal(wvPadded, using: SymmetricKey(data: wvOkm.prefix(32)), nonce: AES.GCM.Nonce(data: Data(count: 12)), authenticating: wvHeader)
let wvCT = wvBox.ciphertext + wvBox.tag
check("write ciphertext", hx(wvCT) == S(wv, "Ciphertext"))
let wvSigned = cat([wvHeader, H(wv, "Seed"), wvOkm.suffix(32), u32(wvCT.count), wvCT])
check("write signed bytes", hx(wvSigned) == S(wv, "SignedBytes"))
check("write hash", hx(sum("komando-sync/1 write hash", [wvSigned])) == S(wv, "Hash"))

// A snapshot's state: records sorted by ID, a deleted one keeps only its
// name; waiting changes by write; yeses only past the heads, by write and
// record, each with its type, the holders it deletes (sorted) and the
// waiting changes it sets aside (by write); then waiting changes a yes
// set aside, while they wait or are past the heads, by write and type.
let st = v["snapshot_state"] as! Obj
var stHeads: [String: Int] = [:]
for h in st["Heads"] as! [Obj] { stHeads[S(h, "Device")] = I(h, "Seq") }
let recs = (st["Records"] as! [Obj]).sorted { H($0, "ID").lexicographicallyPrecedes(H($1, "ID")) }
var stBytes = u32(recs.count)
for r in recs {
    let deleted = r["Deleted"] as! Bool
    let fs = (r["Fields"] as! [Obj]).filter { !deleted || S($0, "Name") == "name" }
        .sorted { S($0, "Name").utf8.lexicographicallyPrecedes(S($1, "Name").utf8) }
    stBytes += cat([H(r, "ID"), str(S(r, "Type")), flag(r, "Exists"), flag(r, "Deleted"), u32(fs.count)])
    for f in fs { stBytes += cat([str(S(f, "Name")), str(S(f, "Value")), clock(f)]) }
}
let wts = (st["Waiting"] as! [Obj]).sorted(by: byRef)
stBytes += u32(wts.count)
for w in wts {
    stBytes += cat([ref(w), H(w, "Record"), str(S(w, "Type")), flag(w, "Create"), flag(w, "Delete"), fieldPairs(w, "Fields"), clock(w)])
}
func pastHeads(_ o: Obj) -> Bool { I(o, "Seq") > (stHeads[S(o, "Writer")] ?? 0) }
let aps = (st["Approved"] as! [Obj]).filter(pastHeads).sorted {
    byRef($0, $1) || (!byRef($1, $0) && H($0, "Record").lexicographicallyPrecedes(H($1, "Record")))
}
stBytes += u32(aps.count)
for a in aps {
    let reps = (a["Replaces"] as! [String]).map(hex).sorted { $0.lexicographicallyPrecedes($1) }
    let wds = (a["Withdraws"] as! [Obj]).sorted(by: byRef)
    stBytes += cat([ref(a), H(a, "Record"), str(S(a, "Type")), u32(reps.count)] + reps + [u32(wds.count)] + wds.map { ref($0) })
}
let waits = Set(wts.map { hx(ref($0)) })
let wds = (st["Withdrawn"] as! [Obj]).filter { pastHeads($0) || waits.contains(hx(ref($0))) }.sorted {
    byRef($0, $1) || (!byRef($1, $0) && S($0, "Type").utf8.lexicographicallyPrecedes(S($1, "Type").utf8))
}
stBytes += u32(wds.count)
for d in wds { stBytes += cat([ref(d), str(S(d, "Type"))]) }
check("snapshot state bytes", hx(stBytes) == S(st, "Bytes"))

exit(failed ? 1 : 0)
