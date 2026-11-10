# Design: networking (bastions, forwarding, and many VPNs at once)

Status: **built, 2026-11-02; VPN clients built in since 2026-11-03** (see
[Phased plan](#phased-plan) and [built-in.md](built-in.md)). How to use it:
[docs/features/vpn.md](../features/vpn.md). The big goal is in [vision.md](vision.md), the command rules in
[ux.md](ux.md).

**Owner clarification (2026-11-02):** komando is also a **VPN client manager**.
VPN A can be OpenVPN, B GlobalProtect, C Pritunl, D Fortinet, E L2TP, and
so on. Their credentials are stored in komando (the vault). When a command
needs a target behind a VPN, komando **connects that VPN itself**, then
reaches the resource. Example: `komando exec app -- uptime` → `app` needs
`vpn-a` (OpenVPN) → connect → SSH to the bastion → SSH to app, in one
command. Several VPNs can be needed at the same time (app through VPN A, the database
through VPN B).

## Problem

One laptop often needs to reach many projects at once:

- Project A: servers behind an SSH bastion.
- Project B: a database on a private network, only reachable through the office WireGuard.
- Project C: a cluster on a client's Tailscale.
- Project D: a corporate VPN (OpenVPN, Cisco AnyConnect, FortiClient, GlobalProtect).

With a normal VPN, the VPN is set up at the **operating system** level. As a result:

1. Usually only one VPN can be active. We have to keep switching VPNs.
2. Two VPNs often use the same subnet (`10.0.0.0/8`), so their routes clash.
3. All of the laptop's traffic changes too, not only the traffic for that project.
4. It needs admin rights, and an AI agent cannot (and must not) handle that.

## Main idea: networking per connection, inside the komando process

komando already does this for bastions: `--via web1` opens SSH to
`web1`, then connects to the database **from inside the komando process**. No
local port is opened and no system route changes.

VPNs work the same way: komando runs the VPN **inside its own
process** (userspace), only for the connections that need it, then
closes it when the command finishes.

```
komando db query app-db ...
   └─ app-db --via office-vpn,bastion
        ├─ WireGuard "office-vpn" (inside the process, without changing the laptop's routes)
        └─ SSH to "bastion" through that VPN
             └─ TCP to the database from the bastion
```

The result:

- **Many VPNs active at once**, one per target. No need to keep switching.
- **Clashing subnets are not a problem**, because each target has its own path.
- **No admin rights**, no change to the laptop's network. Other traffic is not affected.
- AI agents can use it safely, because the keys are in the vault.

## One concept: `--via`

There used to be two flags for the same thing: `host --jump` and `conn --via`.
Following the rule "no overlapping features", `--via` is now the flag for
all targets.

`--via` holds a chain of hops, from the laptop to the destination, separated by commas:

```bash
komando host add db1 admin@10.0.0.5 --via bastion            # SSH bastion
komando host add db1 admin@10.0.0.5 --via office-vpn         # through a VPN
komando conn add app-db postgres://app@10.0.0.9/app --via office-vpn,bastion   # VPN, then bastion
```

Each step in the chain is a host (SSH bastion) or a VPN.

## The `komando vpn` command

`vpn` shares the namespace with `host` and `conn`; all selectors,
`komando list`, and `komando test` work with it too.

```bash
komando vpn add vpn-a openvpn --config office.ovpn --user alice --password-ref secret:vpn-a
komando vpn add vpn-b globalprotect --portal vpn.client.example.com --user alice --password-ref secret:vpn-b
komando vpn add office wireguard --config ~/Downloads/office.conf
komando vpn add lab socks --address 127.0.0.1:1080

komando host edit app --via vpn-a,bastion
komando conn edit app-db --via vpn-b
komando exec app -- uptime          # vpn-a connects by itself, then bastion, then app

komando vpn up vpn-b                # connect manually (e.g. for an MFA login)
komando vpn status                  # which are connected, since when, used by whom
komando vpn down vpn-b
komando test kind:vpn
```

## Two modes

| Mode | Kind | How it works | Admin? | Many at once? |
|---|---|---|---|---|
| **Userspace** | `wireguard` ✅ | wireguard-go + netstack inside the process | no | yes, clashing subnets are safe |
| | `socks` ✅ | an existing SOCKS5 proxy | no | yes |
| | `proxy` | an existing HTTP proxy (CONNECT), such as a company proxy | no | yes |
| | `tailscale` ✅ | `tsnet` (Tailscale/Headscale) inside the process | no | yes |
| | `openvpn` (including Pritunl profiles) ✅ | komando's own OpenVPN client on the same userspace stack ([built-in.md](built-in.md)) | no | yes |
| | `anyconnect` ✅ (CSTP and DTLS), `fortinet`, `globalprotect`, `f5`, `pulse` (experimental) | komando's own clients on the userspace stack; the experimental ones are used when `openconnect` is not installed, or with `KOMANDO_EXPERIMENTAL_VPN` | no | yes |
| | `l2tp`, `ipsec` (Cisco-style, XAUTH), `ikev2` ✅ | komando's own IKEv1/IKEv2, ESP-in-UDP, L2TP and PPP on the userspace stack (`make e2e-ipsec`) | no | yes |
| **OS mode** | `openvpn --os-mode` | deprecated: the `openvpn` program with sudo | once | limited |
| | `system` ✅ | a VPN that is already connected on the computer; komando only checks it | depends on the client | depends on the OS |

- OS mode can clash if two VPNs use the same subnet. komando must
  **detect and warn** before connecting, not silently
  break routes.
- Every userspace kind is built into komando. `openconnect` + `ocproxy` is
  only a fallback for the experimental kinds when it is installed.
  `komando doctor` checks what the registered VPNs need
  and shows how to install it.

## VPN sessions

- **Automatic connect.** A command whose `--via` starts with a VPN
  connects it if it is not connected yet.
- **One background session per VPN** (like `tunnel`), shared by
  the following commands so they do not log in again every time. The session
  disconnects by itself after it is not used (default 30 minutes, configurable).
  WireGuard can still run inside the process per command because there is no login.
- `vpn up`, `vpn down`, `vpn status` for manual control.
- The audit records when a VPN connects and disconnects, by whom, and for
  which command.

## MFA

Owner decision (2026-11-02): **MFA is always done by a person.**

- komando does **not** store TOTP secrets and does **not** generate MFA codes.
- A person runs `komando vpn up NAME` (password + MFA, or SSO login
  through the browser). The agent and later commands use that session.
- If the session expires, the agent's command fails with `VPN_LOGIN_REQUIRED` and the hint
  "ask a person to run `komando vpn up NAME`". The agent never
  answers MFA.
- VPNs without MFA (WireGuard keys, OpenVPN with only a password) may still
  connect automatically when needed.

## Forwarding for apps on the laptop

`--via` is only for komando's own connections. For other apps (TablePlus,
DBeaver, a browser, `psql`), `komando tunnel` opens a port on the laptop. It
takes the target's name, not an address:

```bash
komando tunnel start app-db                 # localhost:<port> → app-db, through its --via
komando tunnel start app-db --port 15432    # choose the local port
komando tunnel start web1 -L 8080:localhost:80   # the old form still works
komando tunnel start office -D 1080         # SOCKS through the VPN: the browser is "inside" the office network
```

The tunnel runs in the background and holds its path (VPN and bastion) while it is alive.
`komando tunnel list` shows the target, the local port, and the path.

## Safety

- VPN keys (WireGuard private key, Tailscale auth key) are **only in the vault**.
  `vpn add --config` reads the file, moves the key into the vault, and
  stores the rest without the key. The original file is not changed.
- Tunnels and proxies only listen on `127.0.0.1`. A different listen address
  goes in the `-L` or `-D` spec (`0.0.0.0:8080:localhost:80`) and needs `--yes`
  (`OPEN_BIND`).
- Protected follows the address within the same VPN network (see
  `protectedHost`). The same address on a different VPN is a different
  server.
- The audit records the path (`via`) of every command.
- komando never changes the laptop's routes, DNS, or firewall.

## Edge cases

- Two VPNs use the same subnet: safe, because each target has its own path.
- DNS inside the VPN (`db.internal`): the userspace resolver uses the DNS from the VPN configuration.
- VPN drops in the middle of a command: a `VPN_DOWN` or `TIMEOUT` error with the VPN's name.
- Slow WireGuard handshake on the first connection: `--connect-timeout` applies to the whole chain.
- Circular chains (`a --via b`, `b --via a`): refused at `add`/`edit`.
- Removing a VPN that is still used by `--via`: refused (`VPN_IN_USE`), the same as for hosts.
- Small MTU on stacked VPNs: use the MTU from the configuration; it can be changed per VPN.
- Binary size: `tsnet` is quite large, but binary size is not limited
  (see [vision.md](vision.md#technical-rules)).

## Phased plan

| Phase | Contents | Status |
|---|---|---|
| 0 | `--via` for all targets, `tunnel start TARGET`, `vpn add/show/rm`, kinds `wireguard`/`socks`/`system`, VPNs in `list`/`test`/selectors | ✅ tested end-to-end |
| 1 | `vpn up/down/status`, a background session per VPN with automatic disconnect; `tailscale` kind | ✅ tested with a real Headscale (`make e2e-vpnclients`) |
| 2 | The openconnect family (GlobalProtect, Fortinet, AnyConnect, Pulse, F5) through `ocproxy`; `doctor` checks their clients; `VPN_LOGIN_REQUIRED` for VPNs with MFA | ✅ then replaced by built-in clients ([built-in.md](built-in.md)) |
| 3 | OpenVPN/Pritunl without changing the laptop's network | ✅ first in a Docker container, now komando's own client (`make e2e-openvpn`) |
| 4 | L2TP/IPsec and built-in OS VPNs through `system --service` (scutil/nmcli); clashing-subnet warning for OpenVPN in OS mode | ✅ the clash warning compares the route table before and after connecting |
| 5 | L2TP/IPsec, Cisco-style IPsec and IKEv2 built in (no OS VPN, no strongSwan) | ✅ against strongSwan 5.9 and xl2tpd, rekeys included (`make e2e-ipsec`) |

## Owner decisions

1. **OS mode is allowed** (2026-11-02): L2TP/IPsec may use the operating
   system's VPN (`system`); since 2026-11-05 komando has its own `l2tp`,
   `ipsec` and `ikev2` clients. For OpenVPN it is replaced by the built-in client
   (2026-11-03, [built-in.md](built-in.md)); `--os-mode` is deprecated.
2. **MFA is always done by a person** (2026-11-02): no TOTP secrets in the vault;
   see the [MFA](#mfa) section.
