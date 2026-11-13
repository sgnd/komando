# VPNs

Reach servers and databases that sit behind a VPN, even several VPNs at the
same time, without switching between them. [All docs](README.md)

## Reach a server through a VPN

```bash
komando vpn add office wireguard --config ~/Downloads/office.conf --check 10.0.0.5:22
komando host add db1 admin@10.0.0.5 --via office    # a server inside the VPN
komando exec db1 -- uptime                          # connects the VPN by itself
komando test kind:vpn                               # do all VPNs work?
komando vpn status                                  # which VPNs are up, and what uses them
```

At a terminal, `komando vpn add` typed alone asks step by step, starting
with the VPN app your company uses.

```text
$ komando vpn status
NAME     KIND           UP    SINCE   USED BY   DETAIL
corp     globalprotect  yes   2h      web1      session running
office   wireguard      -     -       db1       connects for each command
```

## Supported VPNs

| Kind | What it is | Runs | Changes your computer's network? |
|------|------------|------|----------------------------------|
| `wireguard` | WireGuard | inside komando | no |
| `openvpn` (also `pritunl`) | OpenVPN and Pritunl profiles | inside komando | no |
| `anyconnect` | Cisco AnyConnect and ocserv | inside komando | no |
| `tailscale` | Tailscale, or your own Headscale server (`--server URL`) | inside komando | no |
| `fortinet` | Fortinet SSL VPN (FortiClient) | inside komando, experimental (see below) | no |
| `globalprotect` | Palo Alto GlobalProtect | inside komando; tried on Prisma Access (see below) | no |
| `f5` | F5 BIG-IP SSL VPN | inside komando, experimental | no |
| `pulse` | Pulse Secure / Ivanti Connect Secure | inside komando, experimental | no |
| `l2tp` | L2TP/IPsec with a pre-shared key (Windows Server, MikroTik, strongSwan + xl2tpd, many routers) | inside komando | no |
| `ipsec` (also `cisco`, `xauth`) | Cisco-style IPsec: group name and password, then your login (XAUTH): Cisco ASA/IOS, MikroTik, strongSwan; the "IPSec" type of macOS and iOS | inside komando | no |
| `ikev2` | IKEv2/IPsec, with a pre-shared key or a user login (EAP-MSCHAPv2) checked against the server's certificate | inside komando | no |
| `socks` | a SOCKS5 proxy that is already running (`komando tunnel start bastion -D 1080`, a company proxy); with a login: `--user` and `--password-ref` | already running | no |
| `proxy` | an HTTP proxy that tunnels connections (CONNECT), such as a company proxy: `--proxy-address proxy.corp:3128` or `https://proxy.corp`, its login with `--user` and `--password-ref` | already running | no |
| `system` | a VPN set up in your computer's own settings | by your computer | yes |

"Inside komando" means: no extra program, no Docker, no admin rights.
Your computer's routes and DNS stay the same, so two VPNs that use the
same addresses (both `10.0.0.0/8`) do not get in each other's way. Names
inside the VPN (`db.internal`) are looked up with the DNS servers the
VPN's own configuration gives.

## Add a VPN

A VPN that logs in with a password, pre-shared key or auth key reads it
from the vault: store it first with `komando secret set NAME` (it asks for
it, hidden), then name it in `--password-ref` or `--psk-ref`. Or type it
when you add the VPN: `--ask-password` stores it as `secret:NAME-pass`, and
`--ask-psk` stores a pre-shared key as `secret:NAME-psk`.

Pick the line for your kind of VPN:

```bash
komando vpn add office wireguard --config ~/Downloads/office.conf --check 10.0.0.5:22
komando vpn add office openvpn --config office.ovpn --user alice --password-ref secret:office-pass --check 10.8.0.1:22
komando vpn add office globalprotect --portal vpn.example.com --user alice --password-ref secret:office-pass --mfa
komando vpn add office globalprotect --portal vpn.example.com     # signs in through a browser window at `vpn up`
komando vpn add office tailscale --password-ref secret:ts-authkey
komando vpn add office l2tp --server vpn.example.com --psk-ref secret:office-psk --user alice --password-ref secret:office-pass --check 10.1.0.5:22
komando vpn add office ipsec --server asa.example.com --id staff --psk-ref secret:office-group --user alice --password-ref secret:office-pass
komando vpn add office ikev2 --server vpn.example.com --user alice --password-ref secret:office-pass --check 10.2.0.5:22
komando vpn add office system --service "Corp VPN" --check 10.20.0.1:443
komando vpn add office socks --proxy-address 127.0.0.1:1080
komando vpn add office proxy --proxy-address proxy.corp.example:3128
```

- `--check host:port` is an address that answers only through the VPN.
  `komando test` and `komando vpn up` connect to it to prove the VPN works.
  Always add one; `system` and `openvpn` VPNs need it. Without one, a SOCKS
  or HTTP proxy VPN is checked by connecting to the proxy itself.
- `--config` takes the WireGuard `.conf` or OpenVPN `.ovpn` file. komando
  stores it in the vault, together with its keys. The original file
  still holds the private key, so delete it if you no longer need it.
  The vault secrets are named after the VPN: `NAME-key` and `NAME-psk`
  (WireGuard) or `NAME-config` (OpenVPN). If a secret of that name exists
  already, `vpn add` stops with `SECRET_EXISTS` and saves nothing, so it
  never replaces a secret that a server or a file uses. Pick another VPN
  name, or move the secret away first (`komando secret rename`, or `komando
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
- `vpn add` takes `--label` and `--protected` too.

## Use a VPN

Put the VPN first in `--via`. A command that needs it connects it by itself:

```bash
komando host add db1 admin@10.0.0.5 --via office                        # a server inside the VPN
komando conn add prod-db postgres://app@10.0.0.9/app --via office,bastion # VPN, then a bastion
komando exec db1 -- uptime
komando tunnel start prod-db                                            # open it in TablePlus, psql, ...
komando tunnel start office -D 1080                                     # a SOCKS proxy on port 1080 that goes through the VPN
```

How long a VPN stays up depends on its kind:

- **Session VPNs** (OpenVPN, AnyConnect and the other SSL VPNs, L2TP,
  IPsec, IKEv2, Tailscale) run in the background once connected, and
  later commands reuse the session. When a command connects one by
  itself, it says so on one line:

  ```text
  komando: vpn corp connected; it stays up until unused for 30m (`komando vpn down corp` stops it)
  ```

- **WireGuard** connects for each command, so nothing stays running.
  After `komando vpn up office`, a WireGuard VPN is kept up and reused
  like a session, which saves a handshake on every command.
- **SOCKS, HTTP proxy and `system`** VPNs are already running; komando
  only uses them.

A session that is unused for 30 minutes is closed. Use means a
connection through it: one that stays open (a `shell`, `logs --follow`, a
tunnel) counts for as long as it is open. To change that:
`komando config set vpn_idle 1h` (`0` keeps it up until you stop it).

## VPNs that need a person (MFA, SSO)

Add `--mfa` when the login needs a person: a one-time code, a push
notification, a browser sign-in. komando sets this by itself for an SSL
VPN (`anyconnect`, `globalprotect`, `fortinet`, `f5`, `pulse`) without
`--password-ref`, a Tailscale VPN without an auth key, and an `openvpn`,
`l2tp`, `ipsec` or `ikev2` VPN with `--user` but no `--password-ref`.
Then a person connects it once:

```bash
komando vpn up corp           # log in here, MFA included
komando exec web1 -- uptime   # later commands (and agents) reuse the session
komando vpn down corp         # or: komando vpn down --all
```

Typed alone at a terminal, `komando vpn up` asks which VPN, with a list of
yours to pick from.

An AI agent never logs in. Without a session it gets `VPN_LOGIN_REQUIRED`
(exit 4); the hint names `komando vpn up corp` for the person.
`komando vpn up corp --dry-run` shows `would_connect: false` and
`meta.would_be_blocked`. komando never answers MFA by itself.

Tailscale without an auth key works the same way: `komando vpn up office`
shows the login page once, and the node stays logged in after that.

`vpn down` says what the disconnect does to the servers and conns that use
the VPN:

```text
disconnected corp
  web1 stop answering until a person runs `komando vpn up corp`
```

A VPN without a person's login is connected again by the next command that
needs it (`--dry-run` shows the same list first; in JSON it is `affects`).

## Manage VPNs

```bash
komando vpn list                              # all VPNs
komando vpn test office                       # does it connect? (same as komando test office)
komando vpn show office                       # its settings and what uses it
komando vpn edit office --check 10.0.0.6:22   # change a setting (see the list below)
komando vpn status                            # which are up, since when, what uses them
komando vpn rename office office-jkt          # rename; every --via path follows
komando vpn rm office                         # remove (several names or a selector allowed)
komando vpn edit tag:prod --protected         # mark VPNs protected (like host edit)
```

- `vpn status`: a session VPN is up while its session runs; a SOCKS or
  HTTP proxy VPN when its address answers; a `system` VPN when its
  `--check` address answers. WireGuard connects for each command, unless
  you ran `komando vpn up` for it: then it stays up like a session.
- `vpn rm` refuses a VPN that is still on a `--via` path (`VPN_IN_USE`, also
  with `--dry-run`). Change those `--via` paths first. Its answer lists the
  VPNs it removed (`removed`, always a list); `--dry-run` lists them as
  `would_remove`. Its keys stay in the vault until `komando secret rm`; a
  new WireGuard or OpenVPN VPN of the same name needs them gone first,
  unless it is added from the same file.
- `vpn edit` changes `--check`, `--proxy-address`, `--user`, `--password-ref`,
  `--portal`, `--server`, `--psk-ref`, `--id`, `--remote-id`, `--ca`,
  `--service`, `--mfa`, `--legacy-crypto`, `--allow-pap`, `--notes`,
  `--label KEY=VALUE` (an empty value removes it), `--protected`, and
  groups and tags: `--add-group` and `--add-tag` add one, `--rm-group` and
  `--rm-tag` take one away. `--unset` clears `user`, `password-ref`,
  `psk-ref`, `id`, `remote-id`, `ca`, `check` or `notes`; it does not take
  `mfa` or `protected`. An AI agent that swaps or clears a VPN's `--ca`
  needs a person's yes (`SAFETY_SETTING`): another CA lets another server
  get the VPN's login.
- `vpn edit` and `vpn rm` take several names or a selector (`@office`,
  `tag:lab`), as `host edit` and `host rm` do.
- A protected VPN (`--protected`) needs a person's yes before it is
  changed, replaced or removed (`PROTECTED_TARGET`). At your terminal
  komando asks you first; an AI agent or a script adds `--yes` after a
  person agrees. Turning its protection off (`--protected=false`) or
  turning `--mfa` off weakens a check, so it needs that yes too
  (`SAFETY_SETTING`). See [Safety](safety.md#what-needs-a-yes).
- To give a WireGuard or OpenVPN VPN a new config file, add it again with
  `--overwrite`.
- `vpn rename` refuses a VPN that is up: run `komando vpn down NAME` first.
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
  code, for Pritunl) at `komando vpn up`. Plain OpenVPN profiles exported
  from Pritunl work.
- Each session's local port needs a login only komando knows, so other users
  of your computer cannot use it.
- komando reads the `.ovpn` and refuses anything it and OpenVPN could read
  differently (backslash escapes, stray quotes, over-long lines, odd inline
  tags). A profile that leans on one of those tricks is refused; write it
  in plain form instead.

## AnyConnect and the other SSL VPNs

`anyconnect` runs inside komando. Traffic goes over DTLS (UDP, faster) when
the server offers it, and falls back to TLS when UDP is blocked.

`fortinet`, `globalprotect`, `f5` and `pulse` also have their own clients in
komando. `globalprotect` has been tried against a real Prisma Access portal
and gateway, with the browser sign-in and Cloud Authentication Service
below. `fortinet`, `f5` and `pulse` are experimental: written to the
vendors' protocols, but not tried against the vendors' own servers.
komando uses these clients:

- when the `openconnect` program is not installed, or
- always, when `KOMANDO_EXPERIMENTAL_VPN` names them
  (`KOMANDO_EXPERIMENTAL_VPN=fortinet,pulse`, or `all`).

Otherwise, if `openconnect` is installed, komando runs it together with
`ocproxy`. That also leaves your computer's network unchanged. Both
programs must be installed; when one is missing, `vpn up` stops with
`VPN_CLIENT_MISSING` (exit 3) and says how to install it. A GlobalProtect
VPN without `--user` always uses komando's own client: only that one does
the browser sign-in below.

### GlobalProtect with a browser sign-in

Many GlobalProtect portals log in through a web page: your company's
sign-in (Microsoft, Okta, Google ...) with a one-time code, also when the
portal uses Palo Alto's Cloud Authentication Service. Add such a VPN with
only its portal, no user and no password:

```bash
komando vpn add corp globalprotect --portal vpn.example.com
komando vpn up corp
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
  (`komando vpn edit corp --portal gw1.example.com`): komando then
  skips the portal.
- With none of those browsers, the sign-in opens in your own browser. The
  last page has a link or button that opens GlobalProtect: copy that
  link's address (it starts with `globalprotectcallback:`) and paste it
  into the terminal.

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
komando secret set office-psk          # type the pre-shared key
komando secret set office-pass         # type your password
komando vpn add office l2tp --server vpn.example.com --psk-ref secret:office-psk \
  --user alice --password-ref secret:office-pass --check 10.1.0.5:22
komando test office
```

- Without `--password-ref`, a person types the password at
  `komando vpn up NAME` (a password with a one-time code works too).
- `l2tp` logs in to PPP with MS-CHAPv2 (it checks the server's proof too)
  or CHAP, whichever the server asks for. A server that asks for PAP is
  asked for MS-CHAPv2 instead: PAP hands the server your password itself,
  and with a shared pre-shared key anyone who knows that key can pretend to
  be the server. A server that insists on PAP stops with an error that says
  so. If the server cannot do better and you accept that it gets your
  password, allow PAP for that VPN only: `komando vpn edit office --allow-pap`.
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
  `komando vpn edit office --legacy-crypto`. They then come after the
  strong ones, and the session log warns when the server picks one. IKEv2:
  AES-GCM and AES-CBC with SHA-2 or SHA-1, DH groups 14, 19, 20, 31 (and 2
  for old servers). Single DES and MD5 are never used.
- `--legacy-crypto` and `--allow-pap` make the login weaker, so turning
  one on needs a person's yes: at your terminal komando asks you first; an
  AI agent or a script adds `--yes` after a person agrees. Turn them on
  when you add the VPN (`komando vpn add office l2tp ... --legacy-crypto`)
  or later with `komando vpn edit`; `--legacy-crypto=false` and
  `--allow-pap=false` turn them off again. `komando doctor` lists every VPN
  that has one on.
- When a session ends by itself, `komando vpn status` shows why in
  `last_end`.
- If the server does not answer, run `KOMANDO_IPSEC_DEBUG=1 komando vpn up
  NAME`: the session log then lists every IKE message sent and received
  (sizes and types, never keys). Only sends and nothing received means UDP
  500 does not get through, or the server ignores komando's offer.

## Limits

- WireGuard uses the `MTU` line of its config file (1420 when there is
  none). With VPNs stacked inside each other, lower it there.
- `fortinet`, `f5` and `pulse` are experimental, and Pritunl's PIN or
  one-time-code login has not been tried against a Pritunl server.
- GlobalProtect: Prisma Access gateways behind a load balancer are not
  supported. Such a gateway is refused with an error that names the
  portal's other gateways; add one of those as the VPN's `--portal`.
- GlobalProtect: the device report (HIP) some companies ask for is not
  supported. A VPN that needs it connects but may let no traffic through.
- `l2tp`: a tunnel secret on the L2TP layer ("L2TP secret" or "challenge")
  is not supported.
- Pulse/Ivanti: a server that asks for a client certificate (EAP-TTLS) or
  for Host Checker is refused with a clear error. Traffic stays on TLS;
  komando does not switch it to UDP (ESP).
- A `system` VPN changes your computer's routes. `vpn up` compares the
  routes before and after, and warns when two networks claim the same
  addresses.

## Troubleshooting

| Code | What it means | What to do |
|------|---------------|------------|
| `VPN_DOWN` (exit 4) | the VPN does not answer | the hint depends on the kind: connect the `system` VPN; start the SOCKS proxy (`komando tunnel start bastion -D 1080`); check that the HTTP proxy answers and lets the port through (many company proxies allow only 443); check that a WireGuard endpoint is reachable and the keys match; for a session VPN, reconnect with `komando vpn down NAME` and `komando vpn up NAME` |
| `VPN_DOWN` at `vpn up` on WireGuard | nothing answered at `--check` through the tunnel (no handshake yet) | check the endpoint and the keys (`komando vpn show office`) |
| `VPN_LOGIN_REQUIRED` (exit 4) | the VPN needs a person's login and has no session | a person runs `komando vpn up NAME` |
| `VPN_CLIENT_MISSING` (exit 3) | `openconnect` or `ocproxy` is not installed | install the program the message names |
| `VPN_IN_USE` (exit 8) | `vpn rm` on a VPN still on a `--via` path | change those `--via` paths first |
| `VPN_CONFIG` (exit 2) | the stored settings or config file are wrong | fix them with `komando vpn add NAME ... --overwrite` |
| `OVPN_UNSUPPORTED` (exit 2) | the OpenVPN profile has an option komando's client does not support | change the profile; the message names the option |
| `SECRET_EXISTS` (exit 8) | a vault secret with the VPN's name exists already | pick another VPN name, or move the secret away first |

`komando vpn down` on a SOCKS VPN tells you which tunnel to stop.
