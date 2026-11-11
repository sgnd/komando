# Secure sync: komando CLI, desktop and mobile

Status: **proposal, not built**. Written 2026-11-10, second version the same
day after the owner set the product rules below. Needs the owner's yes on
[section 19](#19-decisions-the-owner-must-make) before any code.

This document designs how komando keeps data safe on one device, how the
desktop app (macOS) and the mobile app (iOS) sync through a server that can
read none of it, how the phone works alone when the laptop is off, and how a
team shares servers with roles and approvals. It covers the security design.
Screens, command words and error texts get their own UX document.

How it was made: fifteen research passes (the current code, password
managers, device-key systems, comparable tools, sync protocols, Apple and Go
building blocks, backend, teams, approvals, import, the engine on iPhone, App
Store rules, built-in AI), and a review of the first version by five
attackers whose 47 confirmed findings are folded in. This version was
reviewed again by four attackers; its 22 confirmed findings are folded in
too. A third pass before development (consistency, new holes from the
fixes, the published attack catalogue, proofs on the development Mac, and
readiness to build) confirmed 37 more points, also folded in. Further review
rounds were run after that and their confirmed findings are folded in,
together with ways to close or narrow the limits this document used to
accept. Where such a way needs the owner's yes, the text marks it with
"(decision N)" and section 19 holds the question. No review round has come
back clean yet, so the text as it stands is again unreviewed.

## 1. The product rules this design follows

Set by the owner on 2026-11-10:

1. **The CLI is open source, runs on Windows, Linux and macOS, and never
   talks to a cloud.** No sync, no account.
2. **The desktop app is free** without paid features.
3. **The paid plan** adds cloud sync between Mac and iPhone, the built-in AI,
   and teams. The apps come for Mac and iPhone first.
4. **Usable anywhere, with the same features.** Laptop off: the iPhone
   reaches the servers by itself, with the AI agent helping, through several
   VPNs at once.
5. **What is added in the desktop app can be seen in the CLI** on that Mac.
6. **A paying user brings their CLI data in** without typing it again.
7. **Teams**: roles, and approvals by another person.
8. **Built-in AI is part of the plan**, and a person may use their own AI key.

## 2. The short version

- **The sync server is treated as an attacker.** It stores sealed boxes and
  passes them along. It never holds a key, a password, a host name or a
  command. Stealing it gives no secrets and no server list.
- **The sync service processes nothing readable.** Import, encryption,
  connecting to servers, VPNs and cloud accounts, and running the agent's
  tools all happen on the Mac or the iPhone. The sync service is a blind
  post office. The separate AI gateway does see AI requests, in passing
  (section 13).
- **Keys live on each device, not in a password.** Signing keys are in the
  Secure Enclave. The key that opens your data is in that device's Keychain,
  usable only while the device is unlocked. No master password, so a stolen
  server database cannot be cracked offline.
- **A new device or team member is let in by a person, with Face ID or Touch
  ID**, or with the printed recovery kit. The server cannot add anyone.
- **Everything synced is encrypted, names included.** Every change is signed,
  and devices remember the newest state they have seen, so the server cannot
  quietly change or roll back data.
- **The phone runs the same engine and the same rules**, with the iPhone
  limits listed in section 11. It works while the app is open. Long work
  runs as a job on your own server.
- **SSH private keys do not sync by default.** Each device gets its own key.
  The exceptions are optional: a spare login key that only the recovery kit
  can open, and, if the owner agrees, a signing key for logins that last a
  few minutes (section 8.2).
- **A risky change waits for one person's yes** before it applies anywhere.
- **In the terminal on a Mac, a password that lives in the app is used
  through the app and is not copied** unless the person chooses the copy
  (section 10).
- **Team approval is a real wall only where the server itself checks the
  signed yes** (server-enforced mode, section 12). On other servers it is a
  rule the apps keep, and the app says which is which.
- **The built-in AI is the one part that is not end-to-end encrypted**, and
  the app says so before first use. With your own AI key, komando's servers
  see nothing. Protected servers and team vaults start with the AI switched
  off (section 13, decision 17).
- **First, fix the local folder** (phase 0): today most of `~/.komando` is
  plain text.

"100% secure" does not exist. Section 4 lists exactly what is promised and
what is not.

## 3. Where komando stands today

Read from the code on 2026-11-10 (`internal/vault`, `internal/store`).

| Data | File | Today |
|---|---|---|
| Secret values (passwords, tokens, kubeconfigs, VPN keys, `.ovpn` profiles) | `vault.json` | AES-256-GCM per secret. Good when the key is in the OS keychain or comes from a passphrase. On a computer with no keychain the key is a file in the same folder, so a copy of the folder opens it (`komando doctor` warns) |
| Secret **names**, count, change times | `vault.json` | Plain text |
| Inventory: servers, addresses, users, conns, VPN settings, recipes, rules | `state.json` | Plain text |
| Live session values (SOCKS password, login socket token) | `state.json` | Plain text |
| SSH private keys komando made | `keys/NAME` | Plain text (unencrypted PEM, mode 0600) |
| Known host keys | `known_hosts` | Plain text |
| Audit log (commands, full SQL text) | `audit.jsonl` | Plain text, hash chain without a key |

Other gaps: one key with no hierarchy, tied to one device; no protection
against an old copy of a file; records have no stable ID, version or deletion
marker and point at each other by name; runtime data shares a file with the
inventory; `komando export` carries no secrets; the CLI does not build for
native Windows yet, only under WSL: file locks, stopping background
processes, terminal input, file ownership checks, the OS key store and the
"Allow once" window all have Unix-only code (41 compile errors in 14 files).

## 4. What we defend against

| Attacker | Can | Must not be able to |
|---|---|---|
| **The sync server**, its host, an insider, or a thief of its database and backups | Read, keep, drop, delay, replay, reorder everything it stores | Read content or names. Add a device or a team member. Hand a device a key it made itself. Change or roll back a record unnoticed. Weaken settings. |
| **Network attacker** | Watch and change traffic | More than the server can |
| **Thief of a locked device** | Hold it | Use the keys |
| **Thief of an unlocked phone who knows the passcode** | Read what that phone holds | Add or remove devices or members, approve commands. These need the face or finger, and adding their own face or finger does not help (section 6.1) |
| **A removed device or teammate** | Keep what it already downloaded | Read or write anything after removal |
| **A program on the Mac running as you, including an AI agent that ignores the rules** | Read and change what the open-source CLI can reach on that Mac, including every password the person chose to copy to the terminal, whichever device it was typed on. While the app is open, ask the komando CLI to use a server whose password stays in the app: reads come back hidden as for an agent, and a change needs Touch ID on the app's screen | Read a password that stayed in the app. Add a device, approve a command, or make other devices accept a change without a person's yes |
| **The AI gateway, the AI provider, or anyone who takes either over** | Read every AI request. Return any reply, so choose which commands the agent proposes | Make a change (needs Face ID). Get a secret value or key from the device. Read a server the person did not put in that chat |
| **Someone with your email inbox** | Read login codes | Get data or keys. Empty the account without a 7-day warning on every device |
| **A bad update** | Ship a client that leaks keys | Reach a Mac without komando's offline signature and an entry in the public log. Be sent to one person only. Limits below |

What we do **not** claim:

- A program running as you on an unlocked Mac can do there what you can do.
  No design removes this. We narrow it three ways: a password that lives in
  the app is used from the terminal through the app and is not copied unless
  you choose the copy (section 10); a protected server can be set so that
  the server itself asks for a phone-signed yes and the Mac holds no lasting
  login (section 12, server-enforced mode, also for one person); and an AI
  agent can be run as a second macOS user that cannot read the komando
  folder (section 10). What you chose to copy to the terminal's folder is
  protected by neither the Secure Enclave nor the app's sealed store.
- What is added in the app shows in the terminal once the app has been open
  to write it there. Passwords stay in the app unless you choose the copy,
  and team data reaches the terminal only if the team allows it (section 10).
- The server can refuse service or hold back changes. We cannot prevent
  that. We detect it (section 9). With decision 14, two devices on one
  network also compare directly and keep syncing without the server.
- The server sees: your email and plan; each device's public sync keys; how
  many devices, team members and records exist and their rough sizes; each
  team's member list with its roles, so which account is Owner, Admin or
  Approver; when each device syncs or asks for an approval; and from which
  IP address. This can be narrowed where it is cheap (decision 15): sign-up
  offers Apple's hidden email address; record counts are rounded up with
  empty sealed records; sync times are spread out. Hiding the IP address
  needs a relay run by another company (Oblivious HTTP) and would come after
  launch. Approval times, device public keys and the member list stay
  visible: the service and the server-enforced mode need them to work.
- **The built-in AI is not end-to-end encrypted** (section 13). A secret or
  production data that lives on a server can reach the AI provider when the
  AI is used on that server; hiding is best effort. A server marked "never
  use AI here" sends nothing to any AI.
- Removing a device or a person does not take back what they already saw.
  komando lists every password and key they could read and changes them on
  the servers as one job where it can (section 12); the rest stay as a
  checklist until done. In server-enforced mode a member never holds a
  lasting login, so there is nothing to change on those servers.
- A role cannot stop a teammate from reading a password their own device
  must use. On servers not set to server-enforced mode (section 12), team
  approvals and the Read-only and Operator limits are rules the komando apps
  keep and record. A member whose device holds the login can go around them
  with another tool.
- The public log shows that a release exists and that everyone got the same
  one, not what it does. On the Mac, the engine and encryption inside the
  app can be rebuilt from public source and compared, and the code that
  touches keys can be read; the rest of the app is checked only by komando
  and the outside reviewer (decision 13 asks whether to publish more). On
  the iPhone nobody can compare what the App Store delivers with the source,
  so there the protection is two-person release, the lock on the Apple
  developer account, Apple's review and the reviewer's check of each release.
- On a Mac without Touch ID, "Allow once" is only as strong as the Mac's
  login password, and everything that reaches other devices is agreed on the
  iPhone. On an Apple-silicon Mac a Magic Keyboard with Touch ID removes
  this limit (section 6.1). A hardware security key as the approval key
  could follow after launch (decision 12).
- A program already running as you on a Mac at the moment you give the
  recovery key there can capture it if it has been allowed to watch the
  keyboard or screen, or shows you a fake window. So the Mac asks for the
  key only when no iPhone can do it, reads it by camera or a protected
  field, and a recovery-key step that adds a device waits 24 hours while
  another device is alive and can cancel it (section 6.4).
- A recovery from the kit when no other device is left cannot prove it got
  the newest state: that device remembers nothing to compare with. The
  server could hand it an older state. The only check is the date and counts
  shown to the person (section 6.4).
- If every device and every kit are lost, the private synced copy is lost
  (section 6.4).
- The phone is not a laptop: iOS stops an app about 30 seconds after it
  leaves the screen, and a few features do not exist on iPhone (section 11).

## 5. The parts

```
 +----------------+   local only   +-------------------+        +----------------+
 | komando CLI    | <------------> | komando desktop   |        | komando iOS    |
 | open source    |  same Mac, no  | Swift app + the   |        | Swift app + the|
 | no cloud, ever |  network       | komando engine    |        | komando engine |
 +----------------+                +---------+---------+        +--------+-------+
                                             | each app: own keys in the Secure Enclave and Keychain,
                                             | own sealed store, encrypts and signs
                                             | BEFORE anything leaves
                                             +-------------+-------------+
                                                           | HTTPS, every request signed
                         +---------------------------------v----------------+
                         | komando service (Go + Postgres)                  |
                         | accounts, plan, sealed records, relay, wake-ups  |
                         | sees: email, plan, public keys, sizes, times     |
                         +--------------------------------------------------+

                         +--------------------------------------------------+
   built-in AI only ---> | komando AI gateway (separate, keeps nothing)     | ---> AI provider
                         | sees AI requests pass through                    |
                         +--------------------------------------------------+

   Mac and iPhone connect to your servers, VPNs, databases and cloud accounts
   directly. The komando service is never in that path.
```

- **Sync devices are only the Mac app and the iPhone app.** Both keep their
  signing keys in the Secure Enclave and the key that opens data in the
  Keychain of that device (section 6.1). The weaker "CLI device" of the first version of
  this design is gone, and with it a whole class of attacks.
- **The engine is the same Go code as the CLI.** Both apps have it linked
  in, inside the app's own process (section 11). Neither app starts a komando
  program to do its work, so who is calling, the opened keys and the
  question to the person never pass through arguments, the environment or a
  pipe. The record encryption therefore exists once, in Go. Swift does only
  what needs the Secure Enclave or the Keychain: sign bytes, fetch the
  device's unwrap key from the Keychain for the engine, ask the person. The
  Mac app also ships the komando CLI for the terminal.
- **What keeps other programs out of the app's store on a Mac.** Only the
  signed app can reach its Keychain items. The app is built with the
  hardened runtime, so another program running as you cannot attach to it or
  load code into it. The komando CLI started by anything else sees
  `~/.komando` and nothing of the app's store.
- **The Mac app needs a Secure Enclave**: Apple silicon, or an Intel Mac with
  a T2 chip. On an older Mac the app says "Sync is not available on this
  Mac" and the CLI works as before. Whether the free app runs at all on
  such a Mac is decision 24.
- **No web app holds keys.** The website is for sign-up, docs and the web
  checkout (section 18).
- **The Mac app is distributed with Developer ID outside the Mac App Store.**
  The store's sandbox would stop it from reading the CLI's folder.

## 6. Identity: devices, not passwords

### 6.1 Device keys

Each app install makes its own keys. They never leave the device.

| Key | Use | Protection |
|---|---|---|
| **Sync key** | Signs requests, its own record changes, state summaries | P-256 in the Secure Enclave, usable after the first unlock, no prompt, so sync can run in the background |
| **Authority key** | Signs device-list and member-list entries, approvals, "a person agreed" | P-256 in the Secure Enclave, **Face ID or Touch ID every time, no passcode fallback**, tied to the faces and fingers enrolled when the key was made |
| **Unwrap key** | Opens the account key sent to this device | X-Wing private key in the Keychain, this device only, never iCloud-synced, usable only while unlocked |

**Adding or removing a face or finger ends the authority key.** Someone who
knows the passcode can enrol their own face, so the Secure Enclave refuses
the key after any such change. Sync and reading keep working on that device;
approving and changing lists do not. The app says "Face ID changed on this
device. Confirm it from another device, or with your recovery kit." The new
authority key counts only once another device's authority key or the
recovery key has signed it in, and it then counts as a device added today
for the 7-day rule. A device can never sign this for itself.

**A Mac without Touch ID** (Mac mini, Mac Studio, a MacBook used with the
lid closed) has no authority key. It gets a weaker "local approval key": in
the Secure Enclave, unlocked by the Mac's login password. It may only answer
"Allow once" for commands run on that Mac. Its signatures never sync and are
refused by every other device and every team check. So on such a Mac:

- **Sync is turned on from the iPhone**, which creates the account and the
  recovery kit. The Mac then joins by showing its QR code to the iPhone.
- **A change made on that Mac** (an edit in the app, or "changes from your
  terminal") waits until the iPhone gives the one yes (section 8.1).
- Wherever this document says "Touch ID" for a step that reaches other
  devices, this Mac shows the request on the iPhone instead (section 14).
- Without an iPhone or a Mac with Touch ID on the account, sync cannot be
  turned on from this Mac. The free app and the CLI work as before.

A Magic Keyboard with Touch ID gives an Apple-silicon Mac a real Touch ID.
The app then makes a normal authority key and none of the limits above
apply. The app says so on such a Mac. This does not help an Intel Mac, and
it is checked on real hardware in the phase 1 prototype (section 18).

### 6.2 The device list

Each account has a **device list**: a chain of signed entries. The account's
ID is the hash of entry 1, so a different first entry is a different account.

```
entry 1  first device creates the account, account key 1 (key ID k1)
entry 2  add recovery kit              signed by A's authority key, and by the kit
entry 3  add device B                  signed by A's authority key, and by B
entry 4  remove device A at its write number 57, account key 2 (key ID k2)
```

- An entry holds, in the clear: its number, the hash of the entry before, the
  action, public keys, a **key ID** and the public **account sealing key**
  (section 7.1) for any new account key, and signatures.
  Device names and SSH public keys sit in a sealed record the entry points to.
- An entry is valid only when signed by an **authority key** already on the
  list, or by the recovery key. Every client checks this itself from entry 1.
- An entry that adds or replaces a recovery kit must also be signed by that
  new kit's own key, over the hash of the entry before. So a kit belongs to
  exactly one account, and nobody without the recovery key can put it on
  another list.
- A client remembers the account ID and the newest entry it has seen, and
  refuses a chain that is shorter, that splits, or that starts differently.
- **Removing** a device records that device's last accepted write. Anything it
  signs after that is dropped by everyone, whatever date it claims.
- A device added less than 7 days ago cannot remove older devices or replace
  the recovery kit, unless the recovery key is typed.
- **Who counts the days.** List entries carry no time anyone must believe.
  Each device counts a wait from the moment it first received the entry
  itself, and keeps that moment locally. It never uses a time claimed by the
  signer or given by the server. This holds for every wait in this document:
  the 7 days here, the kit waits in section 6.4 and the member wait in
  section 12.

This is the pattern of Keybase's sigchain and Tailscale's tailnet lock. It
closes the hole most password managers admit to: trusting the server to hand
out public keys.

### 6.3 Adding a device

**From a device you have:**

1. The new device shows a QR code, or 26 characters to type. It holds only a
   one-time 128-bit secret, good for a few minutes and one try.
2. The new device sends its public keys and name through the server, with a
   check code made from the secret. The server never sees the secret, so it
   cannot swap the keys.
3. The existing device verifies the check code, shows "Add *Budi's
   iPhone*?", and after Face ID signs the "add device" entry and seals the
   account key for the new device.
4. It sends back, under the same secret: the account ID, the newest list
   entry, its current state summary (section 9) and the sealed key.
5. The new device checks all of it before trusting anything: the reply
   matches the secret, the chain leads from that account ID to that entry, and
   the opened account key matches the key ID in the signed list.
6. Every other device shows "A new device was added".

Steps 4 and 5 stop the server from enrolling the new device into an account
the server made up, or handing it a key the server knows.

**From the recovery kit** (the "I have no other device" path): section 6.4.

### 6.4 Recovery kit

Turning sync on makes a **recovery key**: 256 random bits, shown once as
groups of letters and digits plus a QR code on a printable page.

- The page offers: print, save as a file outside this device, or save to a
  password manager. It says plainly that a note or screenshot on this same
  device is lost with the device, and that a phone backup does not bring the
  keys back. Sync does not start until a few characters are typed back.
- While an account has one device, the app keeps one line visible: "Only this
  device and your recovery kit can open your data", with "Add a second
  device" and "Check my recovery kit".
- Replacing the kit needs the current recovery key. If the kit is lost, a
  device can replace it after a 7-day wait that every device shows and any
  device can cancel.
- Using it on a new device: the device first checks the chain from entry 1
  and refuses unless it holds an "add recovery kit" entry signed by this
  very recovery key, the kit was not replaced later, and the opened account
  key matches a key ID in that signed list. The server also asks for a fresh
  email code. The device then shows what it was given, from signed data
  ("Last change by *MacBook* on 3 Nov, 4 devices, 212 records. Is this
  right?"). Its first act removes every other device, makes a new account
  key for itself alone, and makes a **new** kit. Devices that are still
  alive come back by QR, and each of them shows "the recovery key was used".
  The server therefore cannot enrol the device into an account it made up,
  and an old copy of the list cannot let a removed or stolen device back in.
  What this device cannot check alone is whether the state is the newest:
  it remembers nothing, so the date and counts on that screen are the only
  check. When an old device comes back by QR, the summary it remembers is
  compared with the recovered state, and newer writes it holds are shown to
  the person to merge.
  If another listed device has synced recently, this recovery waits 24
  hours first, as described in the next point.

- Using it on a device already on the list (the iPhone is lost and the Mac
  has no Touch ID): the recovery key signs **one** entry that holds the step
  the person chose, such as "remove the lost iPhone", together with the new
  account key and the new kit. It does not remove other devices. The old
  recovery key stops working the moment that entry is accepted. The key is
  typed into a protected field or read from the kit's QR code by the camera;
  paste is refused, because any program can read the clipboard. When an
  iPhone is on the list or at hand, the Mac does not ask for the key at all:
  the iPhone scans the kit and signs the entry, and the Mac receives only
  the result.
- **A recovery-key step that adds a device waits 24 hours** when another
  listed device has synced recently (the exact number of days is fixed with
  the list format). It is announced on every device and by email, and any
  device can cancel it with Face ID or Touch ID. A step that only removes a
  device applies at once, and so does everything when no other device is
  alive. The wait stops a captured recovery key from quietly adding a
  device.

If every device **and** every kit are lost, nobody can open the synced copy.
No recovery by email, and no PIN recovery (a guess-limited PIN needs hardware
a small team cannot run). This loss can be made unlikely (decision 6): an
account can have up to three kits kept in different places, and using one of
them ends all of them and makes new ones; a kit can be printed as three
parts of which any two are enough, so one part can be left with another
person; and, opt-in, the recovery key can be saved in iCloud Keychain, which
then depends on Apple and on the person's Apple account. More paper is more
paper that can be found, and the app says so. "Trusted person" recovery
inside komando (half the key with a person you choose, half released by the
service after an email code and a 7-day wait everyone sees) would follow
after the outside review. For team data, a team admin can let the person
back in (section 12).

### 6.5 Why no master password

- A password puts a blob on the server that can be guessed offline unless a
  device-held secret is mixed in. Once that secret exists, the password adds
  little.
- It needs a slow password function and a login protocol, with memory limits
  on iPhone. More code, more to get wrong.
- The honest answer to "I forgot my password" would still be "use your
  recovery kit".

Sign-up says in one line: "No password. Your devices are the key."

### 6.6 Reset, deleting the account, changing email

- Signed by an authority key or the recovery key: applies at once.
- With only an email code: starts a 7-day wait, announced by email and on
  every listed device. Any listed device or the kit can cancel it. It can
  only empty or delete the server copy. It never adds a device.
- A reset makes a **new account** with a new ID. A device that remembers the
  old account never follows the new one by itself.

## 7. Keys and encryption

### 7.1 Key hierarchy

```
device unwrap key  (one per device, never leaves it)
      |  opens
account key, generation N     random 256 bits. On the server only as sealed
      |                       copies: one per device, one for the recovery kit.
      |                       Its key ID is in the signed device list.
      |  wraps
vault key  (one for the personal vault, one per team vault)
      |  derives, per record and per write
record key + commitment tag
```

- A device that opens a sealed account key compares it with the key ID in the
  signed list and refuses a mismatch. The sealed copy is also bound to the
  account, the generation and the receiving device, through the HPKE `info`
  value (the one-shot sealing call takes no other bound data).
- Each account key generation also has an **account sealing key**: an X-Wing
  key pair. Its public half is in the signed device list. Its private half
  exists only sealed under the account key, so every device of that account
  can use it and nobody else. Anything sealed "to a member" or "to an
  approver" (team vault keys, invites, approval requests) is sealed to this
  public key, taken from that member's checked device list.
- Removing a device makes account key N+1 and new vault keys, sealed to the
  devices that remain. Records are re-encrypted right away. Old keys are
  kept, sealed under the new ones, only to open what cannot be rewritten
  (audit chunks, writes from an honest device that was offline).
- Removal shows as "not yet confirmed" for each remaining device until that
  device has signed a summary naming the new list entry.
- Removing a device also makes a new key for every team vault that device
  could open, in the same Face ID step (section 12).

### 7.2 Algorithms (suite 1)

All of it is Go's standard library plus `golang.org/x/crypto`, on Mac and on
iPhone alike. Five small pieces are our own code on top and are what a
reviewer should read first: the padding rule, the commitment tag, the exact
byte layout of signed and bound data, the clock, and a small writer and
reader for the age file format (age is in neither library).

| Job | Choice |
|---|---|
| Seal a key to a device or a team member | HPKE (RFC 9180) with the X-Wing KEM (ML-KEM-768 + X25519), HKDF-SHA256, AES-256-GCM. X-Wing is not part of RFC 9180: it comes from the IETF draft `draft-ietf-hpke-pq` (KEM ID 0x647a), as in Go's `crypto/hpke`. Test vectors follow that draft, and the format description names the lowest Go version. Safe against "store now, break later with a quantum computer". |
| Record encryption | AES-256-GCM under a key used **once**: `HKDF-SHA256(vault key, 32 random bytes, record context)` gives a fresh key and a commitment tag for every write. |
| Signatures | ECDSA P-256 (Secure Enclave), in one fixed form |
| Hashes | SHA-256 |
| Size hiding | Each record is padded before sealing (Padmé rule) |
| Sealed file for moving data by hand | age file format, sealed to an X-Wing key as above |

Rules that keep it honest:

- **One suite number names the whole set.** No "legacy mode". The lowest
  suite an account accepts is stored inside signed data.
- **Every record is tied to its place**: format version, suite, account,
  vault, record ID, record type, version counter, clock and writer device.
- **Every signature is tied to its use**: signed bytes start with a fixed
  purpose label, and a key is accepted only for the uses it is meant for.
- **Signatures never feed a hash.** Chain hashes cover the signed content only.
- **Check first, open second.** A record's signature and its place are
  checked before it is opened.
- **One failure answer.** A record that fails is never reported to the
  server with a reason.
- **Nothing is compressed before sealing.**
- **The format and this code are public** (section 15), with test vectors.

## 8. What syncs and what never does

| Data | Syncs? | How |
|---|---|---|
| Servers, conns, VPN settings, groups, recipes, notes | Yes | One sealed record each |
| Secret values and their names | Yes | One sealed record each |
| Device names, each device's SSH **public** key | Yes | One sealed record per device |
| SSH **private** keys | **No by default** | Each device has its own (section 8.2). Opt-in per key for places you cannot change (Git hosts, shared hosting) |
| Spare login key (optional, section 8.2) | Yes, if the person accepts the offer | One record sealed to the recovery key only. No device can open it without the kit |
| VPN device keys (WireGuard) | **No by default** | The phone makes its own key and shows "Send this to your VPN admin" with a Test button. Where komando can reach the VPN server, the approving device offers to add the phone's key there as a job. Where a VPN gives one key only, the person may choose "use the same key on both devices" for that VPN, warned that only one device can be connected at a time |
| Known host keys | Yes, with care | Signed only by a device whose own engine saw that key in a live connection to that server. A key merely read from the terminal's folder is never signed or synced: it is kept as a hint and compared on the app's first own connection. A different key for the same server shows as `HOSTKEY_MISMATCH`, never merged. A device with no signed entry asks the normal first-connection question |
| Safety rules, protected marks, deny patterns | Yes | Stricter applies at once. Looser waits (section 8.1) |
| Audit log | Yes | One signed chain per device, sealed in chunks, never editable |
| AI conversations | Device only by default | They contain command output. Opt-in to sync, sealed |
| Live sessions, tunnels, tokens, Tailscale node state, approval TOTP seed, cloud login caches | **Never** | Each device has its own |

### 8.1 Changes that wait for a person

The main attack on sync is not reading data. It is one tricked or stolen
device pushing a small edit, such as a new address for `prod-db`, so that
every other device sends the production password to the attacker.

- **Applies by itself:** notes and descriptions; a stricter rule.
- **Waits:** everything that changes **where a secret goes** (address, port,
  user, jump host, conn URL, VPN endpoint or certificate, which secret a
  record uses), **what runs** (a recipe's command, sudo, environment, proxy
  command, plugins), **who is reached** (a new server or conn, a rename, a
  group, tag or label, because commands pick their targets by these), or
  **what protects** (a looser rule, removing a protected mark or a deny
  rule, deleting a protected record). Anything not on the "applies by
  itself" list waits.
- A name held by a record, a waiting change or a deletion marker cannot be
  taken by another record. The newcomer waits and is shown as "replaces
  prod-db".
- In a team vault, the yes must come from a member whose role allows that
  change, and "what protects" changes follow the two-person rule (section 12).
- **One yes for all devices.** A waiting change applies everywhere once it
  carries "a person agreed": a signature by an authority key over that exact
  change. An edit made in the app collects it while editing. The screen shows
  old and new: "prod-db: address 10.0.0.5 → 203.0.113.9, uses secret
  prod-db-pass".
- There is no agreement for one device alone: a device without an authority
  key keeps the last agreed value until the signed yes arrives.
- **While a change waits,** the last agreed value stays in force.
- **Records point at each other by ID where the link is a field** (jump
  host, key, which secret a record uses), so a rename or a
  delete-and-recreate cannot slip a swap past these rules. A name typed
  inside text (`{{secret:NAME}}` in a recipe or a file) stays a name and is
  looked up when the command runs. It is covered by the rules above: a
  rename and a new record both wait, and a held name cannot be taken.

### 8.2 Server access for each device

- Each device's SSH public key sits in a sealed record. The hash of that
  record is fixed in the device's list entry, so the key cannot be swapped.
- When a device is added, the approving device offers "Give *iPhone* access
  to your 14 servers?" and puts the key on them as a job. Sync never writes
  to a server by itself. Protected servers ask as usual. **This must happen
  while a device with access is still alive**, so the app reminds until done.
- One synced record per device and per server or VPN tracks the state:
  wanted, on the server, **phone logged in**, skipped. "Phone logged in" is
  written by the phone after its own test. Until every item is tested or
  skipped by the person, both apps keep the line "iPhone cannot reach 3
  servers and 1 VPN yet".
- A server added later on one device offers the same job for the other
  devices. Until then it shows "waiting for access" there.
- **One line instead of one key per device (optional, decision 19).** A
  server can be told once to trust the account's own signing key. Every
  device on the account then logs in with a certificate (a signed pass)
  valid for a few minutes, made after Face ID for a key on the signed device
  list, and a new device needs nothing put on that server. The signing key
  syncs sealed like a password, which is an exception to "SSH private keys
  do not sync". It is replaced on the servers, as a job, whenever a device
  is removed. Servers that take only plain keys (Git hosts, some shared
  hosting) keep the per-device way.
- On the Mac, the app's SSH key stays in the app's sealed store. The
  terminal cannot read it and uses it only through the app (section 10).
  "Also let the terminal log in" follows the same
  choice and limits as copying passwords (section 10): it puts the
  terminal's own public key on the chosen servers, and is never offered for
  servers under an approval rule or in a protected vault.
- Removing a device lists the servers that still carry its key and removes
  the line where it can.
- **Recovery:** turning sync on offers one optional **spare login key**, put
  on each server by the same job. Its private half is made on the device,
  sealed **to the recovery key only**, and wiped from the device. No device
  can open it without the kit; Face ID alone does not. "The Mac died before
  the phone had access" is solved by typing the kit on the phone. Each use
  is written to the audit chain and shown on every device. After any use,
  and whenever the kit is replaced, the app makes a new spare key and swaps
  it on every server as a job, showing "spare key not yet replaced on 3
  servers" until done.

## 9. How sync works

- **Offline first.** Reads and writes go to the app's local sealed store.
  Sync is a push and pull of changed records, safe to repeat and to resume.
- **Merging.** The newer change wins field by field, ordered by a hybrid
  clock (time, counter, device). Exceptions: deleting wins over a
  simultaneous edit (except protected records); known host keys never merge;
  rules merge toward stricter.
- **Clocks.** A device checks its clock against the server before pushing. A
  change stamped far in the future is stored but not applied until its time.
- **Signed changes.** Each write carries the device's signature, its running
  number, the hash of its previous write, and the newest device list entry it
  knows.
- **Signed state.** After syncing, a device signs a short summary: the key
  generation, the newest list entry, the lowest client version allowed, and
  each device's newest write number and hash. A device uses downloaded data
  only when it holds every write up to a summary at least as new as the one
  it remembers. A newly paired device gets its first summary from the device
  that paired it. This stops the server from serving an old state, or from
  leaving out the host keys and rules while delivering servers and secrets.
- **Deleting** leaves a signed marker, dropped only after every current
  device has signed a summary that covers it. A Mac that copies to the
  terminal keeps its markers for as long as that copy is on.
- **Teams.** The summary also carries, per team: the newest member list
  entry, the team vault key generation and its key ID, the hash of the
  team's rules, and each member's newest device list entry. A device uses
  team data only when it holds everything up to the newest summary it has
  seen from any member. So
  the server cannot hide a removal, a demotion or a new rule from some
  members.
- **A device offline for more than 90 days** saves a local backup, downloads
  the fresh state, then shows its own changes that never synced.
- **Catching a server that holds changes back, and working without it.** The
  apps show "last heard from *MacBook*: 2 days ago" and warn when an active
  device goes quiet. Two devices side by side can compare summaries with a
  QR code. In a team, any member's summary already counts. Two more checks
  need the owner's yes (decision 14). First, two devices on the same local
  network find each other and compare their signed summaries directly,
  without the server and without a person; if the service refuses or is
  down, they also sync their sealed records to each other this way. Second,
  with "second witness" on, each device writes the hash of its newest
  summary to the person's own iCloud private database, which the komando
  service cannot change. A mismatch from any of these stops sync and asks
  the person. Holding back is still only detected, never prevented.
- **What a device remembers, and where.** The newest list entry, the hash
  of the newest summary and the device's own write number are kept in the
  Keychain, on this device only. The sealed store is left out of device
  backups. A store that is older than those Keychain values (a restore from
  a backup) is treated like the 90-day case above: fresh download, then the
  local changes are shown. So a restore cannot make a device forget newer
  state or reuse old write numbers.
- **A locked phone** woken by a push only fetches and stores sealed data.

## 10. The CLI and the desktop app on one Mac

The CLI never talks to the cloud. The desktop app is the bridge, and all of
it happens on the Mac, while the app is open (komando has no background
program).

- **Two stores.** The app has its own sealed store, with keys held by the
  Secure Enclave and the app's Keychain, which a command-line program cannot
  use. The CLI keeps `~/.komando`. The app's engine copies between them
  inside the same database write step the CLI itself uses, with no second
  lock file (section 16). This needs the phase 0 store (section 16), which the app offers
  to set up.
- **"Show my servers in the terminal"** (on by default): what is added or
  changed in the app, or arrives by sync, is written into `~/.komando` with
  names and addresses, so `komando list` shows it. Passwords are not copied.
- **Passwords in the terminal: used, not copied (the default, decision
  10).** When the terminal needs a password or a login key that lives in
  the app, the komando CLI asks the app. The app runs the command itself
  with its own login and gives back the output. Nothing is written to the
  terminal's folder. Reads come back hidden as for an agent, and a change
  asks for Touch ID on the app's screen. The app must be open; when it is
  closed the CLI stops with the hint "open the Komando app".
- **"Also copy passwords to the terminal"** remains a separate choice for
  scripts that run while the app is closed, turned on with Touch ID. The
  screen says: "Passwords copied to the terminal leave the app's sealed
  store. Any program running as you can read them." Each secret can carry a
  "keep out of the terminal" mark, which syncs, so it can be set on the
  iPhone. Turning the copy off removes the copied passwords on the next
  run. The copied file is marked to be left out of Time Machine. Other
  backup tools may still hold it, so turning the copy off puts every copied
  password on the "change these" list.
- **From the terminal into the app.** The app notices changes in
  `~/.komando`. Only notes and descriptions come in directly. Everything
  else waits (section 8.1), because a change in the terminal may have been
  made by an AI agent. It is shown in two parts:
  **New records that use nothing existing** (a new server with its own new
  secret or none, and no jump host, proxy command, recipe or environment)
  come as one list, "40 new servers from your terminal", each with name,
  address and user. One Touch ID covers the list, after scrolling to its end.
  **Everything else** (any change to an existing record, a new record that
  uses an existing secret, jump host or VPN, anything that runs or protects)
  is shown one at a time with old and new values, each with its own Touch
  ID. The touch signs the changes exactly as shown. If the folder changes
  while the list is on screen, the list is drawn again.
- **What the app compares against.** For every copied record the app
  remembers what it last wrote or read. Only a difference from that counts
  as a terminal change. A record that is older than that, or that was
  deleted in the app, never comes back by itself: it waits as "deleted on
  iPhone on 3 Nov, bring back?". If the folder looks like an old copy,
  copying pauses and the app asks.
- **Team servers under an approval rule** are written to the terminal as
  "managed by the Komando app": name and address, no password and no SSH
  key. When the CLI is asked to use one, it hands the run to the app, which
  applies the team's rule, asks the approver and writes the audit. If the
  app is closed, the CLI stops with "open the Komando app". A key the
  terminal already had on such a server before the rule existed still
  works; when the rule is saved the app lists those keys and offers to
  remove them. Other team data reaches the terminal only if the team allows
  it (section 12).
- **How the CLI reaches the app, and what that call is worth.** A local
  socket in the app's own folder, on this Mac only. The app cannot tell who
  is driving the caller, a person or a hostile program, so every call that
  arrives this way is treated as an outside agent, whatever it says about
  itself: output is hidden as for an agent, and every change is shown on the
  app's own screen with the exact command and needs Touch ID there. The app
  runs the command itself with its own login. No password or key goes back
  over the socket. The CLI cannot prove the app is real either, so an
  answer from the socket is worth no more than the local window.
  One thing may change after the phase 1 Mac prototype: macOS can tell the
  app which program is on the other end of the socket and whether it is the
  komando CLI the app itself shipped, signed and protected from other
  programs. If that check is proven, the app may lend one password to that
  one process for one connection, in memory only and never printed. A CLI
  the person built from source is not signed by komando and never gets
  this. Until it is proven, the app lends nothing.
- **What this is worth.** A password that stays in the app is never on disk
  in the terminal's folder, so a copied folder, a backup or a later
  infection finds nothing, and every use is in the audit. A hostile program
  can still ask the CLI to read on your servers while the app is open; it
  gets hidden output and cannot make a change without your touch.
- **An AI agent with less than your rights.** The docs and `komando doctor`
  explain how to run an AI agent as a second macOS user that cannot read
  `~/.komando` and reaches servers only through the komando CLI and the
  app. Such an agent cannot go around komando's rules by reading the folder
  itself.
- **Approvals for the CLI.** An agent using the CLI on a Mac with the app can
  have "Allow once" answered by the app with Touch ID, or sent on to the
  phone (section 14). Without the app, the local window and the TOTP code
  work as today, for the person's own servers.
- The app writes the time of its last copy into `~/.komando`, so the CLI can
  say "waiting for access: open the Komando app" instead of a login error.

### 10.1 Bringing CLI data in ("import from the CLI")

On a Mac, free or paid:

1. "We found komando on this Mac: 14 servers, 6 databases, 2 VPNs, 9
   passwords. Bring them in?"
2. "Reading on this Mac only. Nothing has left this computer." A vault with a
   passphrase asks for it here. macOS may ask to allow reading the vault key;
   the app explains that dialog first.
3. A review with three lists. **Comes in:** each server with address, user
   and the password it uses. **Stays on this Mac only:** SSH key files, proxy
   commands, VPNs that use the Mac's own VPN, passwords that point at a file.
   **Left out:** live sessions, tunnels, jobs, history. Server fingerprints
   are not trusted from the folder: each is checked the first time the app
   connects to that server.
4. Paid: "Turn on sync" with Touch ID, the recovery kit, then "Sealing 31
   items... sent". The server only ever receives sealed records.
5. "Add your iPhone": scan the QR code. "Give iPhone access to your 14
   servers?"
6. "Your terminal still works as before."

The app does not parse the CLI's files in Swift. Its engine already knows
every format.

On a Mac without Touch ID, steps 1 to 3 are the same. Step 4 becomes "Turn
on sync on your iPhone" and step 5 "Scan this code with your iPhone". The
import is sealed and uploaded after the Mac has joined.

From Linux or Windows, with only an iPhone:

1. The iPhone app makes a fresh key pair for this one export. The full
   public key is too long to type, so the phone shows its hash as about 60
   characters in groups. It says: "Run `komando export --for-phone` in the
   terminal of that computer." (The command name is not final.)
2. The CLI asks a person, never an agent. This uses the same check as
   `secret get --reveal`, and the store's passphrase or the OS keychain
   prompt is asked for at that moment, so an agent that hides what it is
   still cannot finish the export alone. The CLI fetches the phone's public
   key over the local network, or reads it from a file moved by hand, and
   refuses it unless it matches the typed characters. It then writes one
   file sealed to that key, with servers, passwords and chosen keys, and
   prints a check phrase of at least six words made from the finished file.
   Nothing on the terminal, in a log or in the file can open it. Only that
   phone can.
3. The phone takes the file over the local network, or it is moved any other
   way. Sealing keeps the content secret whatever the way. It does not prove
   who made the file, so the phone shows the check phrase of the file it
   received and the person compares it with the terminal. A mismatch is
   refused.
4. The phone opens it, treats the content as coming from an untrusted
   computer, shows the same review with every address, and only then seals
   and uploads. It then offers to put its own key on the servers.

Later, one command in that terminal shows a code (decision 9). The phone
scans it, each side checks the other's key, and the two exchange sealed
files directly over the local network, both ways. What changed in the
terminal goes to the phone, where every change to an existing record waits
for a yes with old and new values (section 8.1). What was added on the phone
comes back to the terminal, with passwords only if the person chose that.
Each exchange uses fresh keys. No cloud is involved, a person must start it
at the terminal, and an agent cannot. The CLI still never talks to a cloud.
Where the network keeps devices apart, the sealed file is moved by hand as
above.

## 11. The phone works alone

**The engine runs inside the iPhone app.** The whole komando engine, with
every VPN client and database driver, already compiles for iPhone. It has not
yet run on a real phone; that is the first prototype (section 18).

- **Several VPNs at once.** iOS allows one system VPN. komando's VPNs
  (WireGuard, OpenVPN, IPsec, L2TP, AnyConnect and the rest) run inside the
  app, not as a system VPN, so VPN A and VPN B work together with no clash,
  as on the laptop. If Apple does not accept this, the fallback in section
  18 carries all of komando's VPNs inside one system VPN (decision 23).
- **Direct connections.** The phone connects to servers, databases and cloud
  accounts itself. No komando server is in between and none holds access.
- **Cloud accounts.** AWS sign-in works on a phone today. Azure needs the
  app registration that is already planned. Google needs its own iPhone
  sign-in registration and Google's review.

What iOS does not allow, said plainly in the app:

- **About 30 seconds after the app leaves the screen, iOS stops it**, and
  VPN and SSH connections drop. So the phone works while komando is open.
- **A change never depends on the app staying open.** On iPhone every
  approved shell change is sent as a `komando job` on the server and picked
  up again when the app returns. One-step changes (one file edit with a
  backup, one SQL statement) run directly. Where neither is possible, the
  approval says "keep komando open until this finishes". The app asks iOS
  for the short extra time to finish the last write and its audit entry.
- **Long reads are jobs too.** Following a log or a slow query runs on your
  server and the app picks up where it left off.
- **Leaving the app for a moment.** On iOS 26 and later, work you started
  can keep running for a while with the system's progress display. iOS may
  still end it, so this is measured in the phase 1 prototype and nothing
  depends on it.
- **Knowing when it is done.** A running job shows on the lock screen. If
  you run the small open-source komando watcher on one of your servers
  (section 15, decision 20), it tells your phone the moment a job ends, in a
  sealed message only your devices can read. The lock-screen progress line
  itself carries no names ("Job 2 of 3 done"), because Apple delivers it
  readable. Without the watcher you see the result when you reopen the app.
- **VPNs reconnect by themselves** with a key, a certificate or the session
  the VPN gave at login (kept on this device, never synced). For a VPN that
  wants a 6-digit code, the person may store the code's seed in komando
  (decision 21); komando then fills the code after Face ID. The screen says:
  "Both parts of this login will be on this phone." In a team vault this
  needs an Owner's yes. A web sign-in opens in the system's sign-in sheet,
  so a saved company session or passkey applies. A VPN that wants a push or
  a web sign-in still asks the person again each time; that is the VPN
  owner's rule.
- **A server that only takes a key** works from the phone only after the
  phone's key was put on it (section 8.2), unless that server was told to
  trust the account's signing key (section 8.2, decision 19).
- **Not on iPhone as they are:** the Mac's own system VPNs, SSH proxy
  commands, sign-in helpers that are separate programs, local database dump
  tools, and local tunnels for other apps. What komando does instead: a
  proxy command that is a jump host or a plain proxy is turned into
  komando's own at import; AWS Session Manager, Google IAP and Cloudflare
  Access are to be spoken by komando itself, and so is cluster sign-in for
  EKS, GKE and AKS (planned, in the open-source engine); a Mac system VPN of
  a kind komando speaks can be added as a komando VPN, asking for its
  password again; internal web pages open in komando's own browser through
  the tunnel. Anything else shows as "not available on iPhone" and never
  fails silently.
- Four VPN kinds (Fortinet, GlobalProtect, F5, Pulse) are experimental
  today. Each is promised on the phone once it passes the tests against the
  vendor's own virtual appliance, rented by the hour, and against at least
  one volunteer's real equipment (decision 22 is the budget).

What must change in the CLI code for this (all open source):

- Move the logic, the safety rules above all, out of the command layer into
  an engine package that the CLI, the Mac app and the iPhone app all call.
  This is the largest piece of work, and it is what guarantees the same
  rules everywhere.
- In the engine, everything that belongs to one call is given with that
  call: who is calling (a person, the built-in agent, an outside agent), dry
  run or real run, where output goes and what is hidden in it, the approval
  answer, and the opened vault. None of it is read from the environment or
  kept in a shared variable. Today these are process-wide in the CLI, which
  is not safe in an app where a person and an agent act side by side. The
  CLI fills the call from its flags, terminal and environment exactly as
  today, so its behaviour does not change.
- VPN sessions become objects inside one process on iPhone. On the CLI and
  in the Mac app they stay helper processes; such a helper only carries the
  tunnel, never gets the account key, and never decides who is calling.
- iOS lets an app start no other program, and "it compiles" does not show
  where the code does that. So on iPhone the holder of an SSH login for
  two-factor servers and the tunnel holder also become objects inside the
  one process. Sign-in helpers named in a kubeconfig, other than the built-in
  ones above, join the "not on iPhone" list.
- Small seams for the platform: where keys are kept, how a person is asked,
  file locking, the data folder, the OS keychain, opening a browser for a
  sign-in, and route lookup.
- The CLI stays pure Go. The app build may use cgo only to connect Go and
  Swift, built from source. No C library is linked, and every change is
  tested to build the CLI with cgo off. This needs one line in
  `built-in.md`.

## 12. Teams

- **A team vault** has its own random key, the **team vault key**. Each
  generation of that key is a
  signed member-list entry that carries its **key ID**. The key is sealed to
  each member's account sealing key (section 7.1), never to a single device.
  A device that opens it compares it with the key ID in the signed list and
  refuses a mismatch. A person's private vault stays private.
- **A signed member list** per team, the same chain idea as the device list.
  Every app checks it from its first entry. The server cannot add a member,
  change a role or undo a removal. Roles in this list are readable by the
  komando service, because a server in server-enforced mode must be able to
  check them without holding any team vault key. So the service can see which
  account is Owner, Admin or Approver (listed in section 4).
- **Inviting works like adding a device** (section 6.3). The admin's app
  makes a one-time invite (a link, a QR code or 26 characters) that the admin
  gives to the person directly. It never passes through the komando service:
  the link opens the app by the app's own address form and is not a page on
  komando's website. Like a device code it works once, and it ends after a
  short time that the invite screen shows.
  The admin's app refuses to show "Add Budi?" unless the invitee's reply
  carries a check code made from that invite, and the invitee checks the
  team's reply the same way. So the server cannot swap in another account or
  enrol someone into a team it made up. A later change of a teammate's
  identity is a loud, blocking warning.

**Roles**, written in the signed member list and checked by every app:

| Role | Can |
|---|---|
| Owner | Everything. Only an Owner can add, remove or change an Owner or an Admin. A team always has at least one |
| Admin | Add and remove Operators and Read-only members, set rules |
| Operator | Use servers in the vaults they were given, and change them, except anything that protects |
| Read-only | See servers, and run only what changes nothing and sends nothing to a new place |
| Approver | A mark on any role: may answer approval requests. An Owner or Admin needs the mark too |

- **Loosening needs two people.** Removing or loosening an approval rule or
  a protected mark, giving the Approver mark, making someone an Owner or an
  Admin, or allowing "copy to terminal" on a protected vault needs the
  signatures of two different Owners or Admins. A team with only one Owner
  or Admin is told so when it saves such a rule; there the second signature
  comes from any other member past the 7-day wait, never from the person
  asking alone. A team with no other member cannot set a rule that needs
  another person. Stricter changes apply at once. Every member sees the
  change. A "protected vault" in this document is a team vault that holds a
  protected server.
- **New members and newly raised members wait 7 days** before they can be
  the second signer or approve for protected servers. The wait starts again
  when a member becomes Owner or Admin or gets the Approver mark. Everyone
  sees "Budi was added", "Budi is now an Admin" and "Budi can now approve".

**Approval by another person.** A team rule can say: "on *production*, a
change needs a yes from an approver who is not the person asking". The
request is signed and sealed to the approvers (section 14). One of them
reads it on their phone and allows it with Face ID. A rule can ask for two
yeses.

- **The rule follows the server, not the record.** The engine compares the
  target with every record in every vault on the device, the private one
  included, and applies the strictest rule. Either match is enough: the same
  address and port before connecting, or, for SSH, the host key the server
  shows (checked before login). Databases, caches, clusters and storage
  match by address and port. So a copy of a production server in a private
  vault inherits the rule. This catches copies and mistakes. On a server in
  server-enforced mode the address or path does not matter: the server
  refuses every login without a valid approval. On other servers a member
  who uses an address komando has never seen, or goes through another
  server, is not caught; those servers are shown as "approval kept by the
  apps only". A team secret can be used only by records in its own vault.
- **When nobody can be reached.** When a rule is saved and fewer than two
  other people can approve, the app says: "Only Budi can approve. If Budi
  cannot be reached, production changes wait." The asker can never skip the
  rule alone. Loosening it follows the two-person rule above, as a signed
  change everyone sees.

What roles can and cannot enforce, said honestly:

- **Enforced by encryption:** who can open a vault at all.
- **Enforced by every komando app:** who may change what, which commands
  need an approval, and that writes signed by a Read-only member are refused
  by everyone else.
- **Not enforced in the terminal.** The CLI knows no roles and no team
  rules. A member who can read a password can type it into the plain CLI or
  any other tool. On a server that is not in the mode below, team approval
  is a rule the komando apps keep and record, not a wall against a member
  who wants to go around it. The app shows such a server as "approval kept
  by the apps only".
- **Enforced by the managed server itself (server-enforced mode, ships with
  teams if decision 11 is yes).** On such a server the only login a
  member's device has is one that starts `komando ssh-gate` in team mode.
  The gate is the open-source CLI on that server; it exists today as a
  forced command that runs one komando command, as an agent, with audit,
  and it talks to no cloud. With every run the device sends the signed
  request and the signed yes. The gate checks them against the team's
  signed member list, which it verifies itself from the team's ID: the
  asker and the approver are different people with the right roles, the
  command is exactly the approved one, the yes is fresh and was not used
  before. Then it runs that one komando command and nothing else. No
  member's device holds a password or a lasting login, so the plain CLI or
  another tool has nothing to use. This is where "may run this, cannot do
  more" and "use but not see" become real. Setup removes the logins that
  existed before, after two Owners agree, and keeps one emergency key that
  two Owners must open together. A short-lived SSH certificate (a signed
  pass that ends by itself) carries the login where the team prefers not to
  add a line per device. What it costs: komando must be installed on each
  such server, and every change there waits for an approver's phone.
  What it does not stop: a command that was approved and runs as root can
  add a new login, so approvers read what they approve; the gate lists the
  server's logins on each run and warns when one appears that komando did
  not put there. Access that does not go through SSH, such as the hosting
  company's console, is outside komando.
- **The same mode for one person.** A person can put their own protected
  servers in server-enforced mode. The gate then checks the phone's signed
  yes against that person's device list (section 14). The spare login key
  from the recovery kit is the way in if the phone is lost.
- **Databases, caches, clusters, storage and cloud accounts** can get the
  same wall through a **gate host** (decision 18): one of the team's own
  servers holds those logins, and members run the komando command there
  through the gate, so the exact approved statement is enforced and nobody
  sees the password. This is a wall only when the database or service
  refuses connections that do not come from the gate host; setup checks
  that and says so. The gate host becomes the most valuable machine the
  team has and must be protected as such. Without a gate host, an approval
  can instead create a login that ends by itself (a database user that is
  dropped, a Kubernetes token, cloud session keys that expire in 15
  minutes): that limits who, which rights and for how long, not the exact
  statement, and the approver's phone must be able to reach the database at
  that moment. Anything set up neither way stays under the app-kept rule
  and is shown as such.
- Two people who are really one (an admin with a second account) cannot be
  told apart by any system. What komando adds: each member is a paid seat,
  each approving iPhone is proven to be a separate real Apple device
  (Apple's App Attest; whether the Mac can do the same is checked in phase
  1), new approvers wait 7 days, and the team's history flags a pair where
  one always approves the other within seconds.

Other rules:

- **Removing a member** writes the signed removal with that member's last
  accepted write, makes a new vault key, and lists every credential that
  person could read, flagging those that were copied to a terminal, with
  the steps to change each on the servers and a "Change them now" button
  that runs the changes as jobs, each protected target asking as usual. A
  progress line shows "changed 9 of 12; 3 need you". What komando cannot
  change itself, such as a token from another company, stays on the
  checklist. Every copied value counts as seen. Until every member's device has
  confirmed the removal it shows as "not yet confirmed by Alice".
- **A member removing one of their own devices** makes a new team vault key
  in the same step, and teammates see "Budi removed a device". A new team
  vault key is a
  member-list entry that any current member may sign, whatever their role,
  because it changes no content, role or rule. Two members who do this at
  the same moment collide in the chain: one wins and the other retries.
- **Re-encrypting is not a change.** A record sealed again under a new key
  keeps its content, version, clock and original writer's signature, and
  every app refuses it if any of these differ from the copy it holds.
- **A member who lost everything** is let back in by a fresh invite, written
  as one step that removes the old identity and adds the new one. Every
  member sees it. It never opens anyone's private vault.
- **"Copy to terminal"** is a setting per vault, off by default, and turning
  it on is a loosening. It is never possible for a Read-only member, for a
  protected vault's passwords, or for servers under an approval rule (those
  are "managed by the Komando app", section 10). Copies are removed when the
  setting goes off or the member leaves, as far as the app can reach them.
  The copied file is left out of Time Machine, and because other backups
  cannot be reached, every copied value then goes on the "change these"
  list.
- **Team members on Linux or Windows** have no app yet. They are members
  through their iPhone. On servers in server-enforced mode they can work
  from the plain terminal through the gate, with a key that can do nothing
  else, and ask for approval from the iPhone. Where the team runs the
  watcher on that server (decision 20), the request can start from the
  terminal; the yes still comes from an approver's phone. A small "komando
  bridge" for Linux and Windows could follow after teams: a separate
  program, not the CLI, that syncs and shows servers in the terminal. Like
  a Mac without Touch ID it could not approve or change lists; that is done
  on a phone. It would be a third program that syncs, so it needs the
  owner's yes. See decision 3.
- Teams must not ship before the signed member list exists and an outside
  review of the design is done.

## 13. The built-in AI

The AI agent runs **on the device**. It uses the engine as its tools, under
the rules agents already have: secrets hidden, a person allows changes,
server output is data and never an instruction.

| | Built-in AI (in the plan) | Your own AI key | Your own endpoint (decision 16) |
|---|---|---|---|
| Path | Device → komando AI gateway → AI provider | Device → AI provider directly | Device → an address you give (a model on your own server or Mac) |
| Who can see the request | The gateway while it passes through, and the provider | The provider only. komando's servers see nothing | Nobody but you |
| End-to-end encrypted | **No** | No (the provider reads it), but komando is out of it | Yes, in effect: nothing leaves your machines |

Rules for every mode:

- **Agent mode is fixed in the code** for everything the built-in AI runs.
  It is not a setting or an environment variable. The person's own taps are
  not agent calls.
- **Without Face ID or Touch ID the agent may only run what changes nothing
  and sends nothing to a new place.** Everything else asks, shown from the
  exact command, one at a time. This is stricter than the CLI today, and it
  applies to every server, protected or not.
- **What counts as a free read.** Only commands on a known list. An unknown
  command asks. A command that names a network destination (curl, wget, dig,
  ping, nc, ssh, a database client with a host and the like) always asks,
  and the screen shows the destination. The one exception is the server's
  own loopback address. Being in the inventory does not make a destination
  free: a shared storage or Git host can carry data out to someone else's
  account. If the destination is another record, the command counts as
  touching that record: it must already be in the chat, and its protected
  mark and team rule apply. This closes the easy way to carry data out
  through a "read".
- **The person chooses which servers a chat may touch.** The chat starts
  with the server that was open; others are added by a tap. A request for
  another server stops and asks, whether the agent names it as the target
  or a command on a chosen server reaches out to it. On a protected server
  where the AI is allowed at all (see the mark below), the first read asks
  once: "Let the AI read on prod-db in this chat?". The model's reply is not
  trusted either: a taken-over gateway or provider cannot widen this.
- **Hidden before it leaves the device:** passwords, keys and tokens become
  `[hidden]`, also in simple re-encoded forms; personal data (emails, phone
  numbers, card numbers) is masked on every server. An option hides server
  addresses too.
- **Files known to hold secrets** (env files, key files, password files)
  are not read by the agent without a yes that names the file.
- **Never sent, whatever is approved:** any secret value read from the
  device's own store, private keys, the recovery key, account and vault keys, VPN
  profiles, kubeconfigs, login tokens, the device list. The engine has no
  tool that hands one of these to the model.
- **Sending a secret to a server gets its own Face ID screen** that names the
  secret and the place, and says: "After this, the AI may be able to read
  this value from that server."
- **Against tricks in server output** (a log line that says "run this"):
  results are passed to the model marked as data with their source, and the
  person is shown which output led to a proposed change. After the agent
  has read output from one server, a later request that names another
  server or a network destination says so on the approval screen: "this
  follows output read from prod-web". No AI agent can be made fully safe
  against such text. What limits the damage here is that the agent can read
  only on servers the person chose, can send nothing to a new place and can
  change nothing without a person's yes.
- **A consent screen before first use**, per mode. For the built-in AI it
  says: "Komando AI is not end-to-end encrypted. To answer, it sends your
  question, the commands it runs and what your servers reply through
  Komando's AI service to *provider name*. Passwords, keys and tokens are
  hidden on this device first."

The gateway is a separate service from sync. It keeps no request text,
checks the device's signature and the plan, refuses removed devices, counts
usage from numbers only, and enforces a monthly budget per account. The
consent screen names the AI provider and what it keeps. The aim at launch
is to reach the provider through a service whose standard terms say
requests are not stored and not used for training (decision 5). If that
cannot be had, the promise is "does not train on it, deletes it within 30
days" and the screen says exactly that.

After launch the gateway could move into an attested enclave (decision 16):
a sealed part of a server whose running program the app can check. The app
would check, before each session, that the gateway is running the exact
published build, so komando's staff and its hosting company could not read
requests. The provider can always read what it is asked to answer; no
design changes that.

**Hiding is best effort and is not a wall.** A secret that lives on a server
(an env file, a config) can reach the provider if a command prints it in
another form, and text in server output can ask the agent to do that.
Production data in a query result can too. The consent screen says so.

So every server and vault has a mark, **"never use AI here"** (decision 17).
It is on by default for protected servers and team vaults, it syncs, and
taking it off is a loosening that waits for a person (two people in a
team). On a marked server the agent has no tools, so nothing from that
server reaches any AI provider. This closes the limit for marked servers
and for no others. Where AI is allowed on a protected server, each output
is shown first with "Send this to the AI?". A **private mode** uses only
the model built into the device, or your own endpoint: enough to explain an
error or a log, not for long tasks, and only on newer devices.

## 14. Approving on the phone

For an agent on the Mac (through the desktop app) and for teammates:

1. The asking side builds a request: who asks, the target as it resolves
   (name, address, pinned host key, protected mark), the exact command, the
   text and hash of every recipe or file the run will read, each secret and
   where it goes, which block is being lifted and why, a one-time number, an
   expiry, and **who may answer**. It signs it and seals it. The expiry is
   two minutes when the answer comes from the asker's own phone. For
   approval by a teammate it is a wait the team sets (15 minutes by default,
   one hour at most).
2. The server and Apple's push service pass along sealed bytes. The push
   shows only "komando needs your answer". An approver may let these sound
   during a Focus.
3. The phone shows the request **from the signed bytes**. Too long or not
   safely showable: it refuses with "run this at the computer". Allow needs
   scrolling to the end and Face ID, and cannot be given from the lock screen
   or a watch.
4. The phone signs the hash of the request plus the answer with its
   authority key, together with the newest member-list and device-list
   entries it knows. The asking side accepts only an answer from someone
   named in the request. If the answer names a list entry newer than its
   own, it syncs first, and refuses if it cannot. Just before the run it
   checks again, against the lists and rules it holds now: the answerer may
   still approve, the asker may still run this, the target and what it is
   about to run still match the request, and the strictest rule that applies
   now is satisfied. The run must start before the request expires and
   within two minutes of the last yes it needed. Otherwise nothing runs and
   the asker asks again. It runs once.
5. Request, answer and result go into the audit chains of both sides.

Against approval fatigue: one open request per computer, a rate limit, and a
signed "Deny" blocks the same request for a while. No "allow for 3 hours" on
protected targets. The asker can cancel an open request. A request to
teammates goes to all approvers at once. With a one-yes rule the first valid
Allow is enough; a two-yes rule needs Allow from two different members,
neither of them the asker. A signed Deny from any of them stops the request.

Stated honestly: when the asking side is the CLI on a Mac and the server is
not in server-enforced mode, the final check runs on that Mac, and a hostile
program running as the same user could skip it. There, phone approval is a
strong check on an agent that follows the rules and a second pair of eyes
away from the laptop. A person can put their own protected servers in
server-enforced mode (section 12): the Mac then holds no lasting login, the
server checks the phone's signed yes itself, and a hostile program on the
Mac can run nothing the phone did not sign. The app shows which servers are
which.

## 15. The backend

Two services, plus static files.

**A. komando service** (one Go binary plus Postgres):

1. Accounts: an email address, proven by a typed 6-digit code.
2. Plan: what was bought and until when, from Apple's and the payment
   provider's notices. One row per account.
3. The device lists and team member lists (clients check them themselves).
4. Sealed records by opaque ID, with a change cursor. The record type and
   the vault name are inside the sealed part; the service stores neither.
5. Relay for pairing and approval messages, all sealed.
6. Wake-ups through Apple's push service. One fixed text, no names, no
   counts.
7. Limits: size, count, request rate.

It accepts requests **only when signed by a listed device key**. No
long-lived tokens, so a stolen token is useless. The few calls that cannot
carry such a signature are each limited to one thing and rate-limited:
sign-up and the email code; the pairing message of a device not yet listed,
which only the one-time secret can use; recovery on a new device, which
needs a fresh email code and is checked by the device itself; the
email-code reset with its 7-day wait (section 6.6); purchase notices from
Apple, checked by their own signatures; and the
watcher, which has its own send-only key and can open nothing.

**B. komando AI gateway** (separate, section 13). The only service that sees
readable text, in passing. It has no access to the sealed records.

**Static files on another provider:** the Mac app's signed update feed, the
status page.

| A breach of | Yields |
|---|---|
| Service A, database and backups | Emails, plan state, public keys, team member lists with their roles, sealed records nobody can open, sizes and times |
| Gateway B | AI requests passing through during the breach. An attacker who controls the replies can also make the agent run read-only commands on servers a person put in an open chat, and see that output after hiding. No changes, no secrets from the device, nothing stored |
| The update feed | Nothing usable: the Mac app refuses an update that is not signed and publicly logged. The iPhone app does not use this feed |

Running it:

- Provider disk encryption, emails and push tokens encrypted with a KMS key,
  nightly backup to a second provider, a restore test every day.
- Logs hold no request bodies and drop IP addresses after 72 hours. Each
  account has a security history its owner can read.
- Hardware-key two-factor on the cloud provider, domain registrar, Apple
  developer account, GitHub and CI. No standing shell access to production.
  A written incident plan that meets the 3x24-hour (Indonesia, UU PDP) and
  72-hour (GDPR) notice deadlines.
- Cost at a small launch: roughly USD 40 to 150 a month plus Apple's USD 99 a
  year. The AI is the only cost that grows with use, hence the budget. The
  outside review (section 17) is a one-time cost that is not in this figure
  (decision 27).

**What is open and what is not.** The CLI is fully open. The sync format,
the encryption code and its test vectors are published, so anyone can check
the claim "the server cannot read it". The engine inside the apps is the
CLI's open code, shipped as a separate part of the Mac app that anyone can
rebuild from the public source and compare byte for byte. The Swift code
that touches keys and asks the person is published to read (decision 13).
The rest of the apps and the backend are commercial. Self-hosting the
backend is not offered at launch.

**When a plan ends:** a grace period, then the server copy becomes read-only
(devices can still download, and can still remove a lost device or a team
member; the built-in AI stops; your own AI key and everything local keep
working, which makes the AI with your own key free: decision 25), then the
sealed copy is deleted after an announced wait with
warnings on every device. The device list and member lists are kept, so on
renewal the account is the same and any device uploads its local data again.
Exact lengths are a business choice. Local data is never touched.

**No always-on access on our side.** If alerts are wanted while both devices
sleep, the answer is a small open-source watcher the person runs on one of
their own servers, sending sealed alerts through the relay. The watcher is
a separate open-source program, not the komando CLI, which still talks to
no cloud. It can send sealed alerts and can open nothing. Because it does
talk to komando's relay, it needs the owner's explicit yes (decision 20).
komando's backend never holds a way into anyone's servers.

## 16. Safety on each device (phase 0, in the open-source CLI)

Useful for every CLI user, with or without the apps.

- **One local database.** `state.json`, `vault.json`, `known_hosts` and
  `audit.jsonl` become one SQLite file. komando already contains SQLite in
  pure Go. Each row is a record komando sealed itself (names included); the
  only readable columns are a random ID, type, version and time. No
  SQLCipher, which would need cgo.
- **The key of the local store** is the key the vault has today, kept the
  same three ways. No new password and no new question.

  | Where the key is | What a copy of the folder gives | When komando cannot get the key |
  |---|---|---|
  | OS keychain (macOS, Linux with Secret Service, Windows key store) | Nothing readable | Stops with a clear "unlock the keychain" error |
  | A key file in the folder (no keychain) | Everything: the key is in the same folder | Stops with the existing "restore the key file" error |
  | Passphrase | Nothing without the passphrase | Stops as "locked" unless the passphrase is given |

  With a key file, sealing protects against a copy of the database file
  alone, not a copy of the folder. `komando doctor` and the move screen say
  so and offer the keychain or a passphrase.
- **One row format, with a number.** Each row starts with a format number
  and a suite number, and its sealing is tied to that row's ID, type and
  version, so a row cannot be moved or swapped inside the file. The app's
  own store uses this same row format through the same Go code. What only
  sync needs (account, vault, writer device, clock, signatures) is added by
  the app later as a new format number in the app's store. The CLI's store
  never carries these. Type, version and change time stay readable: someone
  who copies the file learns how many records of each type exist and when
  they changed, not their names or content.
- **Still no lock-in.** `komando export` keeps writing the inventory as
  plain JSON a person can read, and `komando import` reads it back. Only the
  folder on disk is sealed.
- **One writer at a time.** The CLI, komando's background processes and the
  desktop app share the file through SQLite's own write step: a writer
  takes the write lock at the start, waits a fixed time when it is busy,
  and every write is flushed fully to disk (the full flush macOS offers).
  The database uses the rollback journal, not the write-ahead log, so it
  stays one file. There is no second lock file. Names stay unique across
  servers, conns and VPNs by a read, check and write inside that one write
  step, because SQLite cannot compare sealed names. A backup is made only
  by a komando command that copies inside a read step; a plain file copy
  taken during a write may be broken.
- **Runtime data** (sessions, tunnels, tokens) moves to a separate local
  file, sealed with the store key. Background processes get the key the way
  they get the passphrase today. This closes the plain-text row in section 3.
- **The OS keychain** is reached through the platform seam (section 11):
  the OS tool on the CLI, Swift in the apps.
- **SSH private keys** komando made are sealed too.
- Every record gets a random ID, a version, a change time and a deletion
  marker. Fields that name another record (each jump host, the key, and a
  secret used as password, sudo, key or VPN config) store its ID. Kept as
  written: names inside text (conn URLs, recipe commands, file text), and
  references that are not records (`env:`, `file:`, `op://` and the like). A
  reference to a secret that is not set yet points at an empty secret record
  with its own ID. Groups and tags stay plain words on each record.
- **Old-copy protection.** A sealed generation number in the database and the
  same number in the OS keychain. It moves only when servers, rules,
  secrets, keys or known host keys change, never for audit rows or runtime
  data. The database is written first, then the keychain. Database higher
  than keychain is normal after a crash: komando raises the keychain and
  continues. Database lower than keychain is an old copy: commands that use
  that data stop with their own error (exit 6); `komando doctor` and dry
  runs still work. Only a person at a terminal, or the desktop app with
  Touch ID, can accept an old copy on purpose (a restore from backup); an
  agent cannot. Without an OS keychain there is no such protection, and
  `komando doctor` says so.
- **Native Windows build**, so "cross-platform" is true: Windows versions of
  file locks, stopping background processes, terminal input and file
  ownership checks; the vault key in the Windows key store; a native "Allow
  once" window; a Windows release. Until the key store and the window exist
  there, komando on Windows behaves as on a machine without a keychain or a
  screen, and `komando doctor` says so. Windows is built and tested on every
  change.

How the code meets this (settled while building phase 0, 2026-11-10):

- **Lock files stay.** "No second lock file" is about the database. The
  small lock files that keep komando processes apart (one per VPN, the
  known_hosts lock) hold no data and stay as they are.
- **`vpn/<name>.auth`** held a VPN's login in plain text while openvpn
  (run as root) started. openvpn must read it plain, so it cannot be
  sealed; it is now a named pipe that openvpn reads once, and the login is
  never written to disk (step S7). `runtime.json` is sealed with the
  store's key on a sealed home.
- **Audit rows** are written inside the database's write step. Only
  commands that act write one; reading commands do not, so the write lock
  is not taken for every command.
- **Background processes get the key one way.** Today `tunnel` and
  `vpn serve` read it with the passphrase-on-stdin helper, and the server
  login holder has its own `PASS` line. Both move to the one helper before
  the runtime file is sealed.
- **Host key checks** go through one interface in `sshx` (done in S5c), so
  the sealed store answers them without the known_hosts file. The system
  `ssh` that `host ssh-command` prints still needs a file: it gets a
  temporary private copy, for a person only.
- **Unique names** are checked by opening every server, conn and VPN row
  inside the write step. That is fast for hundreds of records, which is
  the expected size.
- **The generation number in the keychain** is written only when servers,
  rules, secrets, keys or pins change, and the keychain tools take about
  0.1 second. A keychain that is locked at that moment leaves the database
  ahead of the keychain, which is the normal state after a crash: the next
  command raises the keychain.
- **"Only a person" checks** for the move, the undo and accepting an old
  copy use the CLI's existing person-or-agent test. The desktop app's way
  in (Touch ID) needs the per-call identity of the engine work (track E),
  which comes before the apps.
- **New error codes**, the only ones phase 0 adds for agents: `STORE_OLD_COPY`
  (exit 6: the store is older than the keychain says; a person accepts it
  on purpose), `STORE_NEWER` (exit 1: made by a newer komando; update
  komando) and `SEAL_UNFINISHED` (exit 1: `komando seal` moved
  everything but could not replace some old files; running it again
  finishes it). An older komando meeting a moved folder reads the note
  in place of its files and stops with its own `STATE_CORRUPT`, so no
  `STORE_MOVED` code was needed.
- **The vault and the inventory need no new layer** for the swap: the
  vault already reads and writes disk in one place, and every inventory
  change goes through one function. The sealed store replaces those
  insides.

Moving existing users:

- Only a person at a terminal, or the desktop app, moves the folder to the
  new format. Until then the new komando keeps using the old files, so agents
  and scheduled jobs keep working.
- The move covers `state.json`, `vault.json`, `vault.key`, `known_hosts`,
  `audit.jsonl`, the `keys/` folder and the state under `vpn/`.
- The move first writes one sealed archive of the old folder and can be
  undone from it. The archive is sealed with the store key, so it can be
  opened whenever the store can, and it is kept until a person deletes it.
  Undo is for a person only. It puts the old plain files back, so it goes
  through the same "accept an old copy" step as a restore from backup. An
  agent can neither move nor undo.
- An older komando must never see an empty folder: it would start fresh,
  with no protected servers, no deny rules and no pinned host keys. So the
  move does not delete the old files. It replaces each with a short plain
  note ("this folder was moved to komando's new format; update komando").
  The note is not valid data, so every komando already released stops with
  an error and does not start fresh.
- The new database carries a format number. A komando that meets a newer
  number than it knows stops with "update komando". The desktop app does not
  move the folder while the `komando` in the terminal is older than its own
  engine.
- Everything is read back and compared before the old files are replaced.
- Replacing a file does not clean older backups. The result screen says
  that Time Machine and disk snapshots made before the move still hold the
  old plain files, and names the SSH keys to change if that matters.

What changes for CLI users (the list is decision 26):

- `komando host ssh-command` prints a command that points at the key file
  and the `known_hosts` file. With both sealed, it writes temporary private
  copies for a person only, or stops for a sealed key with a hint to use
  `komando shell`.
- `komando config show` keeps its `files` keys, with the new values.
- The audit log can no longer be followed or searched as a plain file.
  `komando audit --follow` and an export take that place; sending to syslog
  stays.
- File and folder names under `vpn/`, `keys/` and `tunnels/` use record IDs,
  so names do not leak through the folder.
- The agent guard and `komando doctor` cover the new database, the runtime
  file and the sealed archive.
- The hint of `STATE_CORRUPT` no longer says "restore the file from a
  backup" without naming the old-copy step that a restore then needs.
- A fresh install uses the new format at once. The old format is read for a
  stated number of releases and then needs the move; agents see a notice in
  JSON until then.
- No new field or exit code for agents beyond those named in this document.
- `docs/features/settings.md` and rule 9 of `AGENTS.md` are updated to the
  new files.

## 17. Trusting the software itself

- The CLI, the sync format and the encryption code are open.
- Releases are signed with a key kept offline. Their checksums go into a
  public transparency log. The Mac app's updater and `komando update` refuse a
  release without a valid proof. The iPhone app is updated only by the App
  Store.
- The Go parts build reproducibly. The engine ships inside the Mac app as a
  separate part built from a public tag, and its hash goes into the
  transparency log, so anyone can rebuild it and compare it with the file
  inside the app they downloaded. The Swift code that touches keys is
  published to read (decision 13).
- The iPhone app cannot be compared this way, because the App Store changes
  the file it delivers. What narrows the gap: the hash of the exact archive
  sent to Apple goes into the log, a release needs two people with hardware
  keys on the Apple account, releases go out in steps, and the outside
  reviewer compares each release with the one before.
- On the Mac, a setting "install updates after 3 days" gives others time to
  find a bad release.
- No remote configuration and no server-driven screens in the apps.
- A public security paper. One outside cryptography review, assuming a fully
  hostile server, before sync leaves beta and before teams ship.

## 18. Build order and what can stop the plan

| Phase | What | Result |
|---|---|---|
| 0 | Local sealed store, engine package with per-call identity, native Windows with key store and approval window (open-source CLI). Gate before phase 2, because most of the code and all safety state sit in the command layer today: a test runs a person and an agent at the same time in one process and checks that the agent's output is hidden and a second change asks again; and a check proves the engine package reads no environment variable and no process-wide state | Safer CLI for everyone; the base for the apps |
| 1 | **Prototypes**: the engine linked into a blank app on a real iPhone with two VPNs at once, opening, writing and reopening the sealed SQLite store there; the tunnels-only part of the engine inside a system-VPN extension, with memory measured for each VPN kind; the Mac app with the engine linked in reading the CLI's vault key (pass: the engine opens a keychain-mode and a passphrase-mode vault and the person types a secret into the app at most once), checking who calls its socket, and making an authority key with a Magic Keyboard; an early TestFlight build to hear Apple on the VPN rule | The three biggest unknowns settled |
| 2 | Free desktop app with import and "show my servers in the terminal"; free iPhone app, local only, with the sealed export from Linux or Windows and "Save a sealed copy" (if decision 8 is yes) | First apps |
| 3 | Service A, device list, pairing, recovery kit, sync Mac and iPhone **with signed changes, signed summaries and waiting changes** (these are part of the record format and are never added later), in-app purchase through Apple on Mac and iPhone (decision 4: no web checkout). Gate before the first purchase: PSE, UU PDP, VAT and export paperwork done for PT Efolusi Dunia Teknologi; until then unpaid test accounts only | Paid plan, private beta |
| 4 | Per-device SSH keys and server access job, spare login key | Public beta |
| 5 | Built-in AI with gateway and own-key mode. Gate: a test runs a person and the agent at the same time in one process and checks that the agent's output is hidden and a second change asks again | AI on Mac and iPhone |
| 6 | Approval on the phone | "Allow once" with Face ID |
| 7 | Teams: member list, roles, approval by another person, server-enforced mode (ssh-gate), the gate host (decision 18), the watcher (decision 20), Linux and Windows members through an iPhone (decision 3) | Teams, private beta |
| 8 | Outside review of sync and teams together (quotes from two or three reviewers asked before phase 3, decision 27), security paper, transparency log | Launch: sync and teams leave beta together |

Teams are part of the launch (decision 11), so the launch waits for phase 7
and its 6 to 10 weeks. Phases 4 to 6 can run as a public beta of the
personal plan meanwhile. The VPN test lab (decision 22, up to $50 a month)
is scripted during phase 1 and runs before every release from phase 2 on.

No phase ships sync without signed summaries and waiting changes: pairing
needs the summary, and section 8.1 is the main attack on sync.

Work that hangs on an open decision in section 19 gets its phase once the
owner has answered.

Go or no-go: phase 1 (the iPhone prototype and Apple's answer) and the
lawyer's answer on the company must pass before phase 2 and later work
starts.

Open until proven, and who settles it:

| What | Who | Before |
|---|---|---|
| The engine really runs on an iPhone: two VPNs at once, memory, size, what happens when iOS stops the app, Face ID key behaviour | A developer with a real iPhone | Any app code |
| The Mac app reads the CLI's vault key; behaviour on Macs without Touch ID and with a Magic Keyboard with Touch ID; whether the app can prove that the caller of its socket is the komando CLI it shipped | A developer with a real Mac | Any app code |
| Apple's reading of the VPN rule (5.4), in-app purchase for a plan also used on a Mac app outside the store, the AI consent rule, organisation enrolment, letting approval pushes sound during a Focus | Apple | Any app code |
| The system-VPN fallback: memory for each VPN kind inside the extension, and two VPNs with the same private addresses | A developer with a real iPhone | Relying on the fallback |
| The operating company, PSE, UU PDP, VAT, hosting region, export paperwork, and whether the open-source CLI code may be linked into closed apps for every contributor (CLA) | Lawyer and accountant | The first purchase; the company before Apple enrolment |
| Sign-in registrations for Google and Azure on iPhone | Google, Microsoft | Cloud accounts on the phone |
| What the AI provider, or the service the gateway reaches it through, keeps; and the price for the monthly allowance | The AI provider | Phase 5 |
| Selling team seats through Apple (volume purchase, invoices) | Apple | Phase 7 |
| The whole protocol against a hostile server, the own-code pieces in section 7.2, the server-enforced mode and its gate, the AI read list as a boundary | Outside cryptographer | Sync leaves beta; teams |
| Fortinet, GlobalProtect, F5, Pulse on the phone | Tests against rented vendor appliances and volunteers' equipment | Promising them |

Proven on the development Mac on 2026-11-10: every package compiles for
iPhone (about 61 MB, and only with cgo for linking); the standard library
has the X-Wing sealing used in section 7.2 and it round-trips; the Windows
build fails in 14 files as listed in section 3.

Things that can stop or reshape the plan:

- **Apple's VPN rule (guideline 5.4)** is written for apps that offer a VPN
  service. Tunnels opened inside an app only for its own connections are not
  clearly covered, and at least one App Store app does this. Apple has not
  said so in writing. If a reviewer disagrees, the fallback (decision 23) is
  one system VPN made with Apple's own VPN interface that carries all of
  komando's VPNs inside it and sends each connection to the right one. It
  keeps "several VPNs at once", keeps them alive when the app leaves the
  screen and lets other apps use them. Its costs: no other VPN app can be on
  at the same time, the part that runs the tunnels must fit in a small
  memory limit, and two VPNs that use the same private addresses need extra
  handling or take turns. The phase 1 prototype measures this fallback as
  well, so it is measured and not assumed. Ask Apple early. Enrol as an
  organisation, not an individual.
- **In-app purchase is required** for buying the plan inside the iPhone
  app. Apply for Apple's Small Business Program (15% instead of 30%), and
  set prices to carry the fee.
- **The plan is sold only through Apple** (decision 4), in the Mac and
  iPhone apps, so Stripe and a web reseller are not needed. The cost: a
  company that wants an invoice for seats must buy through Apple's own
  business channels, and Apple's fee applies to every sale.
- **Rules live in the apps, not in the CLI.** A teammate who can read a
  password can type it into the plain CLI, which knows no team rules. Team
  approval is a wall only on servers in server-enforced mode, and for
  databases and the like only behind a gate host (section 12). Everywhere
  else it is a rule the komando apps keep.
- **The engine on iPhone is compiled but not run.** The size (about 61 MB)
  is within what the App Store allows. Memory and behaviour when iOS stops
  the app are unproven until the phase 1 prototype, which is the first code
  written. If size becomes a problem, rarely used VPN kinds and database
  drivers can be left out of the iPhone build.
- **Export paperwork** for encryption: the yearly US self-classification
  report and the French declaration. If the French paper is late, launch
  without the French store and add it after. **AI consent** (Apple
  guideline 5.1.2): the consent screen names the AI provider (section 13).
- **Indonesia:** the company is PT Efolusi Dunia Teknologi (decision 7);
  enrol it with Apple as an organisation, then PSE registration, UU PDP duties and VAT with a lawyer and
  an accountant, all before taking money. Apple is the seller of record
  and collects VAT on its sales. The service holds
  only an email address, a plan and sealed data, which keeps these duties
  small.

## 19. Decisions the owner must make

### Answers given 2026-11-10

The owner answered the business questions; the technical ones take the
recommended answer below, as the owner leaves those to the design.

- **7:** the operating company is PT Efolusi Dunia Teknologi. Region:
  chosen for speed, with the lawyer's reading of UU PDP still to come.
- **4:** the paid plan is for Apple users only, so billing is Apple's
  in-app purchase on Mac and iPhone. No web reseller.
- **5 and 25:** Anthropic for the built-in AI, a mid-size model by default.
  AI with your own key or endpoint is free.
- **13:** publish to read only the key-handling Swift code and the
  rebuildable engine part. The rest of the apps stays closed.
- **8:** yes, the iPhone app is usable free and local only.
- **11:** teams ship at launch, together with server-enforced mode. This
  makes the launch longer by the 6 to 10 weeks of section 12, and makes
  3, 18 and 20 launch work too (recommended answers).
- **22:** a test lab budget of up to $50 a month.
- **27:** ask two or three reviewers for a price before phase 3.
- **All other decisions:** the recommended answer.

Already decided (section 1): the CLI never syncs; sync, AI and teams are
paid; Mac and iPhone first; built-in AI plus own key; free desktop app.

Decided by this design unless the owner objects:

- The sync format and encryption code are public; the backend is not. How
  much of the apps is published to read is decision 13.
- No master password; devices plus recovery kit.
- SSH private keys do not sync by default. Optional exception, if decision
  19 is yes: the account's signing key for short-lived certificates
  (section 8.2).

Still open. Where the body describes something marked "(decision N)", that
is the recommended answer and it is not final until the owner says yes.
Times are rough developer time.

1. **"Same features on the phone" (rule 4) has one limit that cannot be
   removed:** iOS stops an app that is not on screen, so the phone works
   while komando is open and long work runs as a job on your own server,
   with the lock screen showing progress. With the watcher (decision 20),
   the phone is told when server jobs finish; without it, the person looks
   when they reopen the app. The other gaps are narrowed in section 11:
   common proxy commands and cluster sign-ins are to be built in, a VPN
   code can be filled by komando (decision 21), a new phone can get server
   access
   without a step per server (decision 19), WireGuard access is added by a
   job where komando can reach the VPN server, and the four untested VPN
   kinds are promised only after tests (decision 22). Tailscale still needs
   a one-time sign-in on the phone. Accept this as the meaning of rule 4 at
   launch?
2. **Allow cgo for the app build only**, to connect Go and Swift. No C
   library is linked, everything is built from source, and every change is
   tested to build the CLI with cgo off. Recommended: yes; there is no
   other way onto an iPhone.
3. **Team members on Linux and Windows.** Recommended: at launch they are
   members through an iPhone and work through server-enforced mode from the
   plain terminal. A "komando bridge" program for Linux and Windows could
   follow (8 to 12 weeks, needs the native Windows work, refuses a computer
   without a TPM, the key chip in a PC). It would be a third program that
   syncs, beside the Mac and iPhone apps, so it is the owner's call. Full
   desktop apps only if asked for.
4. **Billing.** Recommended: Apple in the iPhone app and a web reseller for
   everyone else, both at launch, so Mac-only users and companies can pay.
   Cost: 1 to 2 weeks, and a reseller fee of around 5% plus payment costs.
   Depends on decision 7: the reseller and Apple's organisation enrolment
   both need the company to exist.
5. **Which AI provider and model** the plan includes, and the monthly
   allowance. Recommended: Anthropic first, a mid-size model by default.
   Choose the route that gives "not stored" in its standard terms before
   price, and build the gateway so the provider can be changed (about 1
   week). A change of provider comes with an app update and asks for
   consent again, because the consent screen names the provider and the
   apps take no remote configuration. When the monthly allowance is used
   up, the app offers "continue with your own key" instead of stopping.
   Depends on the provider's terms and on decision 7 (sending server output
   abroad under UU PDP).
6. **Losing every device and every kit means losing the private synced
   copy.** Recommended: say it plainly; ship several kits and the
   two-of-three paper kit at launch (days, plus about 1 week and a review of
   the new own-code piece); decide on the iCloud Keychain option (days, but
   it trusts Apple and the Apple account); trusted-person recovery after
   the outside review (3 to 4 weeks).
7. **Hosting region and operating company**, with the lawyer. The company
   comes first: Apple enrolment, the reseller and PSE registration all wait
   for it. Since the service can read nothing, choose the region for speed
   and for the lawyer's reading of the transfer rules.
8. **Is the iPhone app usable without a plan**, local only, including the
   import from Linux or Windows? Recommended: yes, like the Mac app.
   Without a plan the app contacts no komando service. Because a phone
   backup does not bring the keys back, the free app offers "Save a sealed
   copy" to a file the person keeps elsewhere (about 1 week). A yes here is
   what makes rule 6 and decision 9 work for Linux and Windows users.
9. **On Linux and Windows the terminal and the phone are brought in step by
   one command and one scan**, directly over the local network, both ways
   (2 to 3 weeks). It is not automatic until the bridge program exists.
   Accept, and confirm that one device talking to another on the same
   network, started by a person, is within rule 1?
10. **Passwords in the terminal.** By default the terminal uses a password
    through the app and never holds it (2 to 3 weeks). The app must be
    open, reads come back hidden and each change from the terminal asks for
    Touch ID; a window of "this terminal for 10 minutes on unprotected
    servers" can soften that if the owner wants it. Copying passwords into
    the terminal's folder is a separate choice for scripts that run with
    the app closed. Team data reaches the terminal only if the team allows
    it. These narrow rule 5: servers always show in the terminal, passwords
    and team data do not by default. Accept?
11. **Team approval is a wall only on servers set to server-enforced mode**
    (section 12). Recommended: build that mode together with teams (6 to 10
    weeks; komando must be installed on each such server; every change
    there waits for an approver's phone), show every other team server as
    "approval kept by the apps only", let an Owner require the mode for a
    vault, and offer the same mode to one person for their own protected
    servers (1 to 2 weeks more). The alternative is to ship teams with
    app-kept approval only and say so.
12. **A Mac without Touch ID needs the iPhone** to turn sync on and to agree
    to changes (section 6.1). Accept? A Magic Keyboard with Touch ID removes
    the need on Apple-silicon Macs. A hardware security key as the approval
    key can follow later (3 to 4 weeks, and a second kind of authority key
    that every device must check, so it belongs in the outside review).
13. **Publish the apps' source to read** (not to reuse), so the whole Mac
    app can be rebuilt and compared. Recommended: yes for the key-handling
    Swift code and the rebuildable engine part at launch (1 to 2 weeks);
    decide the rest before sync leaves beta (3 to 6 weeks of build work,
    and a business choice, because it changes "the apps are not public").
14. **Checking the server without the server.** Recommended: yes to devices
    on one local network comparing summaries and syncing directly (2 to 3
    weeks; iOS asks once for the "find devices on your local network"
    permission). The iCloud "second witness" is optional and off by default
    (about 1 week; needs the person signed in to iCloud, and some companies
    forbid it).
15. **Showing the service less.** Recommended: Apple's hidden email address
    at sign-up (days), and empty sealed records plus spread-out sync times
    (about 1 week, more storage). Hiding the IP address through a relay run
    by another company: after launch (2 to 3 weeks, a monthly bill and a
    second company to depend on). None of these is needed for the security
    promises.
16. **More ways to keep AI requests from komando.** Recommended: "your own
    endpoint" at launch (about 1 week). The attested gateway after launch
    (4 to 8 weeks, and care at every gateway release).
17. **"Never use AI here."** Recommended: the mark is on by default for
    protected servers and team vaults (about 1 week), so those have no AI
    until someone lifts it; output preview on protected servers and the
    yes for secret files (1 to 2 weeks, one more tap per output); private
    mode with the device's own model later (2 to 3 weeks, newer devices
    only).
18. **A wall for databases and the like.** Recommended: the gate host after
    the SSH wall (3 to 4 weeks; one more server for the team to protect);
    logins that end by themselves per kind where no gate host is wanted (1
    to 2 weeks per kind).
19. **An account signing key so a new device needs no step per server**
    (section 8.2; 3 to 4 weeks). It is a synced secret that can sign
    logins, which bends "SSH private keys do not sync". Recommended: offer
    it as an option, off by default, never for team vaults at first.
20. **The watcher.** A small open-source program on the person's own server
    that tells the phone when a job ends (3 to 4 weeks). It is not the CLI,
    but it does talk to komando's relay, and in a team it can pass a
    request from the gate on that server to the relay. Is that within rule
    1? Recommended: yes, as a separate program the person installs on
    purpose.
21. **Let komando hold a VPN's code seed**, so it can fill the 6-digit code
    after Face ID (about 1 week). Both parts of that login are then on one
    phone. Recommended: a choice per VPN with that warning, and in a team
    vault only with an Owner's yes.
22. **A test lab for Fortinet, GlobalProtect, F5 and Pulse**: rented vendor
    appliances by the hour, plus volunteers (a few dollars per run and 1 to
    2 weeks to script; Pulse images are the hardest to get). The owner sets
    the budget.
23. **The system-VPN fallback** if Apple refuses VPNs inside the app (6 to
    10 weeks; while it is on, no other VPN app can be). Recommended: build
    only the tunnels-only part in the phase 1 prototype, and the rest only
    if Apple says no.
24. **Does the free Mac app run on a Mac without a Secure Enclave** (before
    2018, no T2 chip)? Section 5 says only that sync is not available
    there, and the app's own store needs the Secure Enclave. Recommended:
    the app does not run on such a Mac and says so; the CLI works as
    before. This narrows rule 2 for old Macs.
25. **Is the AI with your own key free, or part of the plan?** Section 15
    lets it keep working when a plan ends, which makes it free, while rule
    3 lists the built-in AI as paid. Recommended: free with your own key or
    endpoint; the plan pays for the built-in one.
26. **Phase 0 changes a few things CLI users and agents see** (the list in
    section 16), and the old file format is read only for a stated number
    of releases. Accept the list, and say how many releases?
27. **The outside review** is a gate before sync leaves beta and before
    teams, and now also covers the server-enforced mode. Its price is not
    known and not in the running cost in section 15. Recommended: ask two
    or three reviewers for a price before phase 3 starts.

How the decisions hang together: 7 comes first, because 4 and Apple's
enrolment wait for the company. 1, 2 and 23 depend on Apple's answer and
the iPhone prototype in phase 1, which is why phase 1 is a gate (section
18). 3, 18 and the Linux and Windows part of 20 only make sense if 11 is
yes. 8 decides whether 9 works at all.

Earlier approved decisions this design changes. Each needs the owner's yes,
and then the old sentence is updated:

- `vision.md` goal 4, "state is plain JSON that can be exported" becomes
  "state is sealed on disk and can always be exported as plain JSON".
- `built-in.md` decision 2 and `vision.md` decision 7, "fully open source,
  no closed components" applies to the open-source CLI; the apps and the
  backend are commercial.
- `vision.md` non-goal "GUI or daemon/server; komando stays a pure CLI"
  applies to the open-source CLI; the Mac and iPhone apps are separate
  products.
- `built-in.md` "a library that needs cgo is not allowed" stays for the
  CLI; the app build may use cgo to connect Go and Swift (decision 2).

## 20. Prior art this is built on

- Device lists signed by devices: Keybase sigchain, Tailscale tailnet lock,
  Apple iCloud Keychain circle, Matrix cross-signing.
- Recovery key on the device list: Apple Advanced Data Protection.
- Per-item encryption with bound context: Standard Notes 004, Ente, Bitwarden.
- Rollback and fork detection: Secsync, Jazz, Anytype any-sync.
- Team keys with signed membership: Keybase teams.
- Signed approval of exact content: Krypton, WebAuthn hybrid transport.
- A Go engine inside an iPhone app: Tailscale's iOS app.
- Lessons from failures: LastPass 2022 (plain-text URLs, weak old settings,
  backup keys on a home computer); the 2026 ETH Zurich study of
  malicious-server attacks on password managers; Infisical and Doppler
  (encryption on the server, sold as zero-knowledge).
