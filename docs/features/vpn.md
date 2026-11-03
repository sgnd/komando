# VPNs

Reach servers and databases that are only reachable through a VPN, several
VPNs at the same time, without switching. [All features](README.md)

## Add a VPN once

```bash
komando vpn add office wireguard --config ~/Downloads/office.conf --check 10.0.0.5:22
komando vpn add lab socks --address 127.0.0.1:1080
komando vpn add corp system --check 10.20.0.1:443
```

| Kind | What it is | Admin rights? | Several at once? |
|------|------------|---------------|------------------|
| `wireguard` | WireGuard, run inside komando | no | yes |
| `socks` | a SOCKS5 proxy that is already running (`komando tunnel start bastion -D 1080`, a company proxy) | no | yes |
| `system` | a VPN your computer runs itself; komando checks it is connected before using it | depends on the VPN | depends on the VPN |

- The WireGuard private key goes to the vault. The `.conf` file still has
  it, so delete that file if you no longer need it.
- `--check host:port` is an address that answers only through the VPN.
  `komando test office` and `komando vpn up office` connect to it, so add
  one: without it komando cannot tell whether the VPN works.
- `komando vpn edit NAME --check ... --address ... --notes ...` changes
  the common settings later.

## Use it

Put the VPN first in `--via`:

```bash
komando host add db1 admin@10.0.0.5 --via office              # server inside the VPN
komando conn add app-db postgres://app@10.0.0.9/app --via office,bastion   # VPN, then a bastion
komando exec db1 -- uptime                                    # connects the VPN by itself
komando tunnel start app-db                                   # for TablePlus, psql, ...
komando tunnel start office -D 1080                           # browse "inside" the VPN
```

The VPN is opened inside komando for that command only. Your computer's
network, routes and DNS do not change, and two VPNs that use the same
addresses (both `10.0.0.0/8`) do not get in each other's way.

```bash
komando list kind:vpn
komando test kind:vpn
komando vpn show office          # what uses it
komando vpn rm office            # refused while something still uses it (also with --dry-run); takes several names
komando vpn status               # UP: a SOCKS proxy or system VPN that answers right now
```

If a VPN does not answer, commands that need it stop with `VPN_DOWN` and a
hint for its kind: connect the `system` VPN, start the SOCKS proxy
(`komando tunnel start HOST -D ADDRESS`), or check a WireGuard endpoint
that sends no handshake. `komando vpn up` on WireGuard checks `--check`
and fails if nothing answers through the tunnel. `komando vpn down` on a
SOCKS VPN names the tunnel to stop.

## More kinds

```bash
komando vpn add kantor openvpn --config kantor.ovpn --user budi --password-ref secret:kantor --check 10.8.0.1:22
komando vpn add client-x globalprotect --portal vpn.client.com --user budi --mfa
komando vpn add tailnet tailscale --password-ref secret:ts-authkey
komando vpn up client-x          # a person logs in (MFA); later commands reuse it
komando vpn status
komando vpn down --all
```

| Kind | How it runs | Your computer's network changes? |
|------|-------------|----------------------------------|
| `openvpn` (and `pritunl`) | in a small Docker container; komando reaches it through a local port | no |
| `openvpn --os-mode` | on your computer, with sudo | yes |
| `globalprotect`, `fortinet`, `anyconnect`, `pulse`, `f5` | `openconnect` with `ocproxy` (`brew install openconnect ocproxy`) | no |
| `tailscale` | `tailscaled` in user-space mode | no |

VPNs with `--mfa` need a person: `komando vpn up NAME` asks for the login,
and later commands (and agents) reuse that connection. komando never
answers MFA itself. A connection unused for 30 minutes is closed
(`komando config set vpn_idle 1h` to change).
