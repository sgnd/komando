# VPNs

Reach servers and databases that sit behind a VPN, even several VPNs at the
same time, without switching between them. [All docs](README.md)

## Quick start

```bash
komando vpn add office wireguard --config ~/Downloads/office.conf --check 10.0.0.5:22
komando host add db1 admin@10.0.0.5 --via office    # a server inside the VPN
komando exec db1 -- uptime                          # connects the VPN by itself
komando test kind:vpn                               # do all VPNs work?
komando vpn status                                  # which VPNs are up, and what uses them
```

## Supported VPNs

| Kind | What it is | Runs | Changes your computer's network? |
|------|------------|------|----------------------------------|
| `wireguard` | WireGuard | inside komando | no |
| `openvpn` (also `pritunl`) | OpenVPN and Pritunl profiles | inside komando | no |
| `anyconnect` | Cisco AnyConnect and ocserv | inside komando | no |
| `tailscale` | Tailscale, or your own Headscale server (`--server URL`) | inside komando | no |
| `fortinet` | Fortinet SSL VPN (FortiClient) | inside komando, experimental (see below) | no |
| `globalprotect` | Palo Alto GlobalProtect | inside komando, experimental | no |
| `f5` | F5 BIG-IP SSL VPN | inside komando, experimental | no |
| `pulse` | Pulse Secure / Ivanti Connect Secure | inside komando, experimental | no |
| `l2tp` | L2TP/IPsec with a pre-shared key (Windows Server, MikroTik, strongSwan + xl2tpd, many routers) | inside komando | no |
| `ipsec` (also `cisco`) | Cisco-style IPsec: group name and password, then your login (XAUTH): Cisco ASA/IOS, MikroTik, strongSwan; the "IPSec" type of macOS and iOS | inside komando | no |
| `ikev2` | IKEv2/IPsec, with a pre-shared key or a user login (EAP-MSCHAPv2) checked against the server's certificate | inside komando | no |
| `socks` | a SOCKS5 proxy that is already running (`komando tunnel start bastion -D 1080`, a company proxy) | already running | no |
| `proxy` | an HTTP proxy that tunnels connections (CONNECT), such as a company proxy: `--address proxy.corp:3128` or `https://proxy.corp`, its login with `--user` and `--password-ref` | already running | no |
| `system` | a VPN set up in your computer's own settings | by your computer | yes |

"Inside komando" means: no extra program, no Docker, no admin rights. The
VPN is opened inside komando for that command only. Your computer's routes
and DNS stay the same, so two VPNs that use the same addresses (both
`10.0.0.0/8`) do not get in each other's way.

## Add a VPN

A VPN that logs in with a password, pre-shared key or auth key reads it
from the vault: store it first with `komando secret set NAME` (it asks for
it, hidden), then name it in `--password-ref` or `--psk-ref`. The names
below (`kantor`, `ts-authkey` ...) are such secrets. Or type it when you
add the VPN: `--ask-password` stores it as `secret:NAME-pass`, and
`--ask-psk` stores a pre-shared key as `secret:NAME-psk`.

```bash
komando secret set kantor                     # the VPN password, typed once (hidden)
komando vpn add office wireguard --config ~/Downloads/office.conf --check 10.0.0.5:22
komando vpn add kantor openvpn --config kantor.ovpn --user budi --password-ref secret:kantor --check 10.8.0.1:22
komando vpn add client-x globalprotect --portal vpn.client.com --user budi --password-ref secret:client-x --mfa
komando vpn add client-y globalprotect --portal vpn.client.com   # signs in through a browser window at `vpn up`
komando vpn add tailnet tailscale --password-ref secret:ts-authkey
komando vpn add kantor l2tp --server vpn.kantor.id --psk-ref secret:kantor-psk --user budi --password-ref secret:kantor --check 10.1.0.5:22
komando vpn add asa ipsec --server asa.client.com --id staff --psk-ref secret:asa-group --user budi --password-ref secret:asa
komando vpn add cloud ikev2 --server vpn.example.com --user budi --password-ref secret:cloud --check 10.2.0.5:22
komando vpn add corp system --service "Corp VPN" --check 10.20.0.1:443
komando vpn add lab socks --address 127.0.0.1:1080
komando vpn add office proxy --address proxy.corp.example:3128
```

- `--check host:port` is an address that answers only through the VPN.
  `komando test` and `komando vpn up` connect to it to prove the VPN works.
  Always add one; `system` and `openvpn` VPNs need it.
- `--config` takes the WireGuard `.conf` or OpenVPN `.ovpn` file. komando
  stores it in the vault, together with its keys. The original file
  still holds the private key, so delete it if you no longer need it.
  The vault secrets are named after the VPN: `NAME-key` and `NAME-psk`
  (WireGuard) or `NAME-config` (OpenVPN). If a secret of that name exists
  already, `vpn add` stops with `SECRET_EXISTS` and saves nothing, so it
  never replaces a secret that a server or a file uses. Pick another VPN
  name, or move the secret away first (`komando secret mv`, or `komando
  secret rm` if an earlier VPN of that name left it). `--overwrite` may
  reuse the secrets of the VPN it replaces, when nothing else uses them,
  and a secret that nothing uses and that holds the same key already (the
  same file added again after `vpn rm`) is reused too.
- `--password-ref` works like everywhere else in komando:
  `secret:NAME`, `env:VAR`, a password manager, and so on (see
  [Servers](servers.md)). For Tailscale it is an auth key. The VPN sends
  it (and `--psk-ref`) to its server each time it connects, so when an AI
  agent adds a VPN with one, or points a VPN at another server or address,
  a person allows it: `--yes` and a click in komando's window, which names
  the references and the server (`SECRET_DESTINATION`).
- `--portal` is the VPN server for `anyconnect`, `fortinet`,
  `globalprotect`, `f5` and `pulse`.
- `--server` is the VPN server for `l2tp`, `ipsec` and `ikev2`, and
  `--psk-ref` its pre-shared key ("shared secret"; for `ipsec` the group
  password), as a reference like `--password-ref`. See
  [L2TP/IPsec, IPsec and IKEv2 details](#l2tpipsec-ipsec-and-ikev2-details).
- `--service` (`system` only) is the VPN's name in your computer's
  settings. With it, `komando vpn up` connects the VPN for you (macOS:
  `scutil`; Linux: NetworkManager). Without it, connect the VPN yourself;
  komando checks it with `--check`.

## Use a VPN

Put the VPN first in `--via`. A command that needs it connects it by itself:

```bash
komando host add db1 admin@10.0.0.5 --via office                         # a server inside the VPN
komando conn add app-db postgres://app@10.0.0.9/app --via office,bastion # VPN, then a bastion
komando exec db1 -- uptime
komando tunnel start app-db                                              # open it in TablePlus, psql, ...
komando tunnel start office -D 1080                                      # a SOCKS proxy on port 1080 that goes through the VPN
```

When a command connects a VPN by itself, it says so on one line:

```text
komando: vpn office connected; it stays up until unused for 30m (`komando vpn down office` stops it)
```

A VPN session that is unused for 30 minutes is closed (only connections
that log in to its local proxy count as use). To change that:
`komando config set vpn_idle 1h` (`0` keeps it up until you stop it).

## VPNs that need a person (MFA, SSO)

Add `--mfa` when the login needs a person: a one-time code, a push
notification, a browser sign-in. Then a person connects it once:

```bash
komando vpn up client-x       # log in here, MFA included
komando exec app1 -- uptime   # later commands (and agents) reuse the session
komando vpn down client-x     # or: komando vpn down --all
```

komando never answers MFA by itself. Tailscale without an auth key works the
same way: `komando vpn up tailnet` shows the login page once, and the node
stays logged in after that.

## Manage VPNs

```bash
komando list kind:vpn                         # all VPNs
komando vpn show office                       # its settings and what uses it
komando vpn edit office --check 10.0.0.6:22   # change a setting (see the list below)
komando vpn status                            # which are up, since when, what uses them
komando vpn mv office office-jkt              # rename; every --via path follows
komando vpn rm office                         # remove (several names allowed)
```

- `vpn status`: a session VPN is up while its session runs, a SOCKS VPN when
  its address answers, a `system` VPN when its `--check` address answers.
  WireGuard connects for each command, so nothing stays running.
- `vpn rm` refuses a VPN that is still on a `--via` path (`VPN_IN_USE`, also
  with `--dry-run`). Change those `--via` paths first. Its keys stay in the
  vault until `komando secret rm`; a new WireGuard or OpenVPN VPN of the
  same name needs them gone first, unless it is added from the same file.
- `vpn edit` changes `--check`, `--address`, `--user`, `--password-ref`,
  `--portal`, `--server`, `--psk-ref`, `--id`, `--remote-id`, `--ca`,
  `--service`, `--mfa`, `--notes`, and groups and tags: `-g` and `-t` add
  one, as in `host edit`; `--rm-group` and `--rm-tag` take one away.
- To give a WireGuard or OpenVPN VPN a new config file, add it again with
  `--overwrite`.
- `vpn mv` refuses a VPN that is up: run `komando vpn down NAME` first.
  The vault secrets `vpn add` made under its name (`OLD-key`, `OLD-psk`,
  `OLD-config`, `OLD-pass`) move to the new name when only this VPN uses
  them, so a new VPN can take the old name.

## OpenVPN details

komando has its own OpenVPN client. It supports UDP and TCP, `tls-auth` and
`tls-crypt`, AES-GCM, ChaCha20-Poly1305 and AES-CBC, and logging in with
certificates, a user name and password, or both.

- The profile is checked when you add it. An option the client does not
  understand is refused by name (`OVPN_UNSUPPORTED`), and what a person
  should know about it (no check of the server's certificate, below) is in
  the answer's `warnings`.
- The server's certificate must come from the profile's `<ca>`. The client
  also checks what the profile asks for, the way OpenVPN does:
  `remote-cert-tls server` (the certificate must say serverAuth),
  `ns-cert-type server`, `remote-cert-eku`, `remote-cert-ku`, and
  `verify-x509-name` (by default the whole subject must match exactly,
  attribute by attribute and in order, such as
  `"C=US, O=Corp, CN=vpn.corp.com"`).
- A profile that asks for none of these still gets one check: the server's
  certificate must be marked for a server (serverAuth, or the older
  nsCertType server). Otherwise another user's certificate from the same
  CA could pretend to be the server; OpenVPN itself only warns there. If
  your server's certificate is marked for neither, the error shows the
  name in it. Check that name with the VPN's admin, then add
  `verify-x509-name NAME name` to the profile (or have the certificate
  issued again with serverAuth).
- When the server pushes an `auth-token`, komando logs in with it when the
  keys are renewed, so a one-time code is not asked for again. The token is
  never logged.
- Compression (`comp-lzo yes`, `compress lz4`) is refused too: compressing
  before encrypting leaks data (the VORACLE attack). `comp-lzo no` and
  `compress stub-v2` are fine.
- With `auth-user-pass` in the profile, give `--user` and either
  `--password-ref`, or `--mfa` to type the password (with a PIN or one-time
  code, for Pritunl) at `komando vpn up`.
- Each session's local port needs a login only komando knows, so other users
  of your computer cannot use it.
- `--os-mode` is deprecated. It runs the `openvpn` program on your computer
  with sudo, which changes your computer's network. Because that `openvpn`
  runs as root, komando passes it only client settings it understands: it
  reads the `.ovpn`, refuses anything it and OpenVPN could read differently
  (backslash escapes, stray quotes, over-long lines, odd inline tags) and
  hands OpenVPN a freshly written copy on its input, with scripts turned
  off (`--script-security 1`). A profile that leans on one of those tricks
  is refused; write it in plain form instead.

## AnyConnect and the experimental SSL VPNs

`anyconnect` runs inside komando. Traffic goes over DTLS (UDP, faster) when
the server offers it, and falls back to TLS when UDP is blocked.

`fortinet`, `globalprotect`, `f5` and `pulse` also have their own clients in
komando. They are experimental: written to the vendors' protocols, but
not yet tried against the vendors' own servers. komando uses them:

- when the `openconnect` program is not installed, or
- always, when `KOMANDO_EXPERIMENTAL_VPN` names them
  (`KOMANDO_EXPERIMENTAL_VPN=fortinet,pulse`, or `all`).

Otherwise, if `openconnect` is installed, komando runs it together with
`ocproxy`. That also leaves your computer's network unchanged.

### GlobalProtect with a browser sign-in

Many GlobalProtect portals log in through a web page: your company's
sign-in (Microsoft, Okta, Google ...) with a one-time code, also when the
portal uses Palo Alto's Cloud Authentication Service. Add such a VPN with
only its portal, no user and no password:

```bash
komando vpn add client-y globalprotect --portal vpn.client.com
komando vpn up client-y
```

`komando vpn up` asks the portal how it logs in. For a browser sign-in it
opens a window of Chrome, Edge, Brave or Chromium (whichever is on your
computer) with an empty, temporary profile: it shares nothing with your own
browser and is removed afterwards. Sign in there, with your password and
code. The window closes by itself and the VPN connects. Later commands, and
AI agents, use that session; komando never types a password or a code into
the page.

- The portal lists its gateways. komando takes the one the portal ranks
  first for your region, and the next one when that gateway cannot be
  reached.
- A gateway that does not take the portal's login has a sign-in of its
  own. komando says so and shows it in the same window; whether you type
  your password again there is up to your company's sign-in.
- To sign in only once, give a gateway's own address as `--portal`
  (`komando vpn edit client-y --portal gw1.client.com`): komando then
  skips the portal.
- Not built yet: Prisma Access gateways behind a load balancer. Such a
  gateway is refused with an error that names the portal's other
  gateways; add one of those as the VPN's `--portal`.
- With none of those browsers, the sign-in opens in your own browser. The
  last page has a link or button that opens GlobalProtect: copy that
  link's address (it starts with `globalprotectcallback:`) and paste it
  into the terminal.
- Not built yet: the device report (HIP) some companies ask for. A VPN
  that needs it connects but may let no traffic through.

## L2TP/IPsec, IPsec and IKEv2 details

All three run inside komando: IPsec (IKE and ESP) and, for `l2tp`, L2TP
and PPP are komando's own code. ESP always travels in UDP (port 4500), so no
admin rights are needed; the server must allow UDP 500 and 4500 and NAT
traversal (nearly all do).

What you need from the VPN's administrator, or from the VPN settings on a
computer where it already works:

| Kind | Settings | komando flags |
|------|----------|---------------|
| `l2tp` | server, pre-shared key ("shared secret"), user name, password | `--server`, `--psk-ref`, `--user`, `--password-ref` |
| `ipsec` | server, group name, group password, user name, password | `--server`, `--id`, `--psk-ref`, `--user`, `--password-ref` |
| `ikev2`, user login | server, remote ID (if not the server's name), user name, password; the CA certificate if the server's certificate is not a public one | `--server`, `--remote-id`, `--user`, `--password-ref`, `--ca FILE` |
| `ikev2`, pre-shared key | server, local ID, pre-shared key | `--server`, `--id`, `--psk-ref` |

```bash
komando secret set kantor-psk          # type the pre-shared key
komando secret set kantor              # type your password
komando vpn add kantor l2tp --server vpn.kantor.id --psk-ref secret:kantor-psk \
  --user budi --password-ref secret:kantor --check 10.1.0.5:22
komando test kantor
```

- Without `--password-ref`, a person types the password at
  `komando vpn up NAME` (a password with a one-time code works too).
- `l2tp` logs in to PPP with MS-CHAPv2 (it checks the server's proof too)
  or CHAP, whichever the server asks for. A server that asks for PAP is
  asked for MS-CHAPv2 instead: PAP hands the server your password itself,
  and with a shared pre-shared key anyone who knows that key can pretend to
  be the server. A server that insists on PAP stops with an error that says
  so. If the server cannot do better and you accept that it gets your
  password, allow PAP for that VPN only: `komando vpn edit kantor --allow-pap`.
  A tunnel secret on the L2TP layer ("L2TP secret" or "challenge") is not
  supported.
- `ipsec` with a group name (`--id`) logs in with IKEv1 aggressive mode,
  like Cisco's own clients. Anyone who sees that login can guess the group
  password offline, and with it pretend to be the server. The session log
  and `komando doctor` warn about it; use `ikev2` if the server offers it.
- `ikev2` with a user login checks the server's certificate against your
  computer's trusted CAs, or against `--ca`, and that it is made out to the
  server's name (or `--remote-id`). komando never skips that check.
- Sessions stay up: komando answers the server's liveness checks and
  rekeys, makes new keys itself before old ones expire, and notices when the
  server goes away.
- Ciphers for IKEv1 (`l2tp`, `ipsec`): AES with SHA-256 or SHA-1 and DH
  group 14 (2048-bit) or 19; ESP with AES-GCM or AES-CBC. The server can
  only pick one of those, nothing weaker. 3DES and DH groups 2 and 5 are
  weak (a well-funded attacker can break them) and are not offered: a
  server that wants them stops with an error that says so. If its admin
  cannot change that, allow them for that VPN only:
  `komando vpn edit kantor --legacy-crypto`. They then come after the
  strong ones, and the session log warns when the server picks one. IKEv2:
  AES-GCM and AES-CBC with SHA-2 or SHA-1, DH groups 14, 19, 20, 31 (and 2
  for old servers). Single DES and MD5 are never used.
- `--legacy-crypto` and `--allow-pap` make the login weaker, so turning
  one on needs a person's yes: `--yes` from a person, and for an AI agent
  also the person's click in komando's window. Turn them on when you add
  the VPN (`komando vpn add old-office l2tp ... --legacy-crypto`) or later
  with `komando vpn edit`; `--legacy-crypto=false` and `--allow-pap=false`
  turn them off again. `komando doctor` lists every VPN that has one on.
- When a session ends by itself, `komando vpn status` shows why in
  `last_end`.
- If the server does not answer, run `KOMANDO_IPSEC_DEBUG=1 komando vpn up
  NAME`: the session log then lists every IKE message sent and received
  (sizes and types, never keys). Only sends and nothing received means UDP
  500 does not get through, or the server ignores komando's offer.

## Troubleshooting

- `VPN_DOWN` means the VPN does not answer. The hint depends on the kind:
  connect the `system` VPN, start the SOCKS proxy
  (`komando tunnel start HOST -D ADDRESS`), or check a WireGuard endpoint
  that sends no handshake.
- `komando vpn up` on WireGuard connects to `--check` and fails if nothing
  answers through the tunnel.
- `komando vpn down` on a SOCKS VPN tells you which tunnel to stop.
- A `system` or `--os-mode` VPN changes your computer's routes. `vpn up`
  compares the routes before and after, and warns when two networks claim
  the same addresses.
