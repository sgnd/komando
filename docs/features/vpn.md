# VPNs

Reach servers and databases that sit behind a VPN, even several VPNs at the
same time, without switching between them. [All features](README.md)

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
| `system` | a VPN set up in your computer's own settings | by your computer | yes |

"Inside komando" means: no extra program, no Docker, no admin rights. The
VPN is opened inside komando for that command only. Your computer's routes
and DNS stay the same, so two VPNs that use the same addresses (both
`10.0.0.0/8`) do not get in each other's way.

## Add a VPN

```bash
komando vpn add office wireguard --config ~/Downloads/office.conf --check 10.0.0.5:22
komando vpn add kantor openvpn --config kantor.ovpn --user budi --password-ref secret:kantor --check 10.8.0.1:22
komando vpn add client-x globalprotect --portal vpn.client.com --user budi --password-ref secret:client-x --mfa
komando vpn add tailnet tailscale --password-ref secret:ts-authkey
komando vpn add kantor l2tp --server vpn.kantor.id --psk-ref secret:kantor-psk --user budi --password-ref secret:kantor --check 10.1.0.5:22
komando vpn add asa ipsec --server asa.client.com --id staff --psk-ref secret:asa-group --user budi --password-ref secret:asa
komando vpn add cloud ikev2 --server vpn.example.com --user budi --password-ref secret:cloud --check 10.2.0.5:22
komando vpn add corp system --service "Corp VPN" --check 10.20.0.1:443
komando vpn add lab socks --address 127.0.0.1:1080
```

- **`--check host:port`** is an address that answers only through the VPN.
  `komando test` and `komando vpn up` connect to it to prove the VPN works.
  Always add one; `system` and `openvpn` VPNs need it.
- **Config files** (`--config`): the WireGuard `.conf` or OpenVPN `.ovpn`
  file is stored in the vault, together with its keys. The original file
  still holds the private key, so delete it if you no longer need it.
- **Passwords** (`--password-ref`) work like everywhere else in komando:
  `secret:NAME`, `env:VAR`, a password manager, and so on (see
  [Servers](servers.md)). For Tailscale it is an auth key.
- **`--portal`** is the VPN server for `anyconnect`, `fortinet`,
  `globalprotect`, `f5` and `pulse`.
- **`--server`** is the VPN server for `l2tp`, `ipsec` and `ikev2`, and
  **`--psk-ref`** its pre-shared key ("shared secret"; for `ipsec` the group
  password), as a reference like `--password-ref`. See
  [L2TP/IPsec, IPsec and IKEv2 details](#l2tpipsec-ipsec-and-ikev2-details).
- **`--service`** (`system` only) is the VPN's name in your computer's
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
komando tunnel start office -D 1080                                      # browse "inside" the VPN
```

When a command connects a VPN by itself, it says so on one line:

```
komando: vpn office connected; it stays up until unused for 30m
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
komando vpn edit office --check 10.0.0.6:22   # change --check, --address, --user, --password-ref, --service, --mfa, --notes
komando vpn status                            # which are up, since when, what uses them
komando vpn rm office                         # remove (several names allowed)
```

- `vpn status`: a session VPN is up while its session runs, a SOCKS VPN when
  its address answers, a `system` VPN when its `--check` address answers.
  WireGuard connects for each command, so nothing stays running.
- `vpn rm` refuses a VPN that is still on a `--via` path (`VPN_IN_USE`, also
  with `--dry-run`). Change those `--via` paths first. Its keys stay in the
  vault until `komando secret rm`.
- To give a WireGuard or OpenVPN VPN a new config file, add it again with
  `--overwrite`.

## OpenVPN details

komando has its own OpenVPN client. It supports UDP and TCP, `tls-auth` and
`tls-crypt`, AES-GCM, ChaCha20-Poly1305 and AES-CBC, and logging in with
certificates, a user name and password, or both.

- The profile is checked when you add it. An option the client does not
  understand is refused by name (`OVPN_UNSUPPORTED`).
- The server's certificate must come from the profile's `<ca>`. The client
  also checks what the profile asks for, the way OpenVPN does:
  `remote-cert-tls server` (the certificate must say serverAuth),
  `ns-cert-type server`, `remote-cert-eku`, `remote-cert-ku`, and
  `verify-x509-name` (by default the whole subject must match exactly,
  attribute by attribute and in order, such as
  `"C=US, O=Corp, CN=vpn.corp.com"`).
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
  with sudo, which changes your computer's network.

## AnyConnect and the experimental SSL VPNs

`anyconnect` runs inside komando. Traffic goes over DTLS (UDP, faster) when
the server offers it, and falls back to TLS when UDP is blocked.

`fortinet`, `globalprotect`, `f5` and `pulse` also have their own clients in
komando. They are **experimental**: written to the vendors' protocols, but
not yet tried against the vendors' own servers. komando uses them:

- when the `openconnect` program is not installed, or
- always, when `KOMANDO_EXPERIMENTAL_VPN` names them
  (`KOMANDO_EXPERIMENTAL_VPN=fortinet,pulse`, or `all`).

Otherwise, if `openconnect` is installed, komando runs it together with
`ocproxy`. That also leaves your computer's network unchanged.

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
- `l2tp` logs in to PPP with MS-CHAPv2 (it checks the server's proof too),
  CHAP or PAP, whichever the server asks for. A tunnel secret on the L2TP
  layer ("L2TP secret" or "challenge") is not supported.
- `ikev2` with a user login checks the server's certificate against your
  computer's trusted CAs, or against `--ca`, and that it is made out to the
  server's name (or `--remote-id`). komando never skips that check.
- Sessions stay up: komando answers the server's liveness checks and
  rekeys, makes new keys itself before old ones expire, and notices when the
  server goes away.
- Ciphers: AES-GCM and AES-CBC with SHA-2 or SHA-1, DH groups 14, 19, 20,
  31 (and 2 and 5 for old servers); 3DES only for old IKEv1 servers. Single
  DES and MD5 are never used.
- When a session ends by itself, `komando vpn status` shows why in
  `last_end`.
- If the server does not answer, run `KOMANDO_IPSEC_DEBUG=1 komando vpn up
  NAME`: the session log then lists every IKE message sent and received
  (sizes and types, never keys). Only sends and nothing received means UDP
  500 does not get through, or the server ignores komando's offer.

## Troubleshooting

- **`VPN_DOWN`**: the VPN does not answer. The hint depends on the kind:
  connect the `system` VPN, start the SOCKS proxy
  (`komando tunnel start HOST -D ADDRESS`), or check a WireGuard endpoint
  that sends no handshake.
- `komando vpn up` on WireGuard connects to `--check` and fails if nothing
  answers through the tunnel.
- `komando vpn down` on a SOCKS VPN tells you which tunnel to stop.
- A `system` or `--os-mode` VPN changes your computer's routes. `vpn up`
  compares the routes before and after, and warns when two networks claim
  the same addresses.
