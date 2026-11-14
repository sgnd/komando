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

exit(failed ? 1 : 0)
