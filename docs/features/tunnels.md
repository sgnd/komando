# Private servers and tunnels

Reach servers and services that are not on the internet, and open them in
the apps on your computer. [All docs](README.md)

## Reach private servers through a bastion

Many private servers can only be reached through one public gateway server,
called a bastion or jump host. Tell komando once with `--via`, and every
command goes through it by itself:

```bash
komando host add bastion ubuntu@203.0.113.10
komando host add db1 admin@10.0.0.5 --via bastion          # one step
komando exec db1 -- uptime                                 # goes through bastion
```

```bash
komando host add web2 admin@10.1.0.7 --via bastion,db1     # a chain: bastion, then db1
komando conn add prod-db postgres://app@10.0.0.9/app --via bastion   # a database behind it
```

- A chain lists the steps in order, from your computer to the target.
- `--via` works the same for servers and conns (databases, caches, storage).
  It can also start with a VPN: see [VPNs](vpn.md).
- komando opens the connection through the bastion inside its own process.
  No port opens on your computer, and your network settings do not change.
- Servers behind the same bastion share one connection to it within a
  command (see [Servers](servers.md#add-a-server)).

## Open a private database in your own app

To use TablePlus, DBeaver, psql or another app on a database behind a
bastion, start a tunnel by the conn's name. komando picks a free local port
and prints it:

```bash
komando tunnel start prod-db
```

```text
tunnel t1108-195255-ab12cd34 is up: 127.0.0.1:53412 (this computer) -> prod-db (10.0.0.9:5432), through bastion
stop it with: komando tunnel stop t1108-195255-ab12cd34
```

Typed alone at your terminal, `komando tunnel start` asks which server or
conn it goes to.

```bash
komando tunnel start prod-db --port 15432     # choose the port yourself
```

Point the app at that address, with the database's user name and password.
The password is in komando's vault: at your terminal, `komando secret show
prod-db-pass --reveal | pbcopy` copies it (macOS; `xclip` on Linux) without
showing it. AI agents never get it; they use `komando db query` instead.
The tunnel runs in the background until you stop it with
`komando tunnel stop`.

## Forward any port

A tunnel makes a service on a server appear on your own computer (or the
other way round). There are three kinds:

| Flag | Direction | Example | Meaning |
|------|-----------|---------|---------|
| `-L` | server → your computer | `-L 15432:localhost:5432` | port 15432 on *your* computer leads to port 5432 as seen from the server |
| `-R` | your computer → server | `-R 9000:localhost:3000` | port 9000 *on the server* leads to port 3000 on your computer |
| `-D` | SOCKS5 proxy | `-D 1080` | apps set to proxy `localhost:1080` connect through the server |

```bash
komando tunnel start db1 -L 15432:localhost:5432    # then connect to localhost:15432
komando tunnel start web1 -L 8080:localhost:80      # a web app on web1, at localhost:8080
komando tunnel start web1 -R 9000:localhost:3000    # show your local app to web1
komando tunnel start bastion -D 1080                # browse through the bastion
komando tunnel start office -D 1080                 # browse through the VPN office (-L works too; -R needs a server)
```

IPv6 addresses go in brackets, as with ssh: `-L 8080:[::1]:80`, or
`-L [::1]:8080:[fd00::5]:5432` to listen on the IPv6 loopback.

- A port of `0` picks a free one. The result shows the address that was used.
- For `-R`, the listening address is on the server. The result says so
  (`remote_listen`, `listen_on`).
- Ctrl-C while a tunnel starts stops it and forgets it (`CANCELLED`).

## See and stop tunnels

```bash
komando tunnel list                                 # tunnels and whether they still run
komando tunnel stop t1108-195255-ab12cd34           # stop one by its ID
komando tunnel stop --all
```

```text
ID                     HOST     KIND   LISTEN           TO                         STATE  AGE
t1108-195255-ab12cd34  bastion  local  127.0.0.1:53412  prod-db (10.0.0.9:5432)    up     2h
```

- `tunnel list` removes entries for tunnels that are no longer running.
- `tunnel stop` takes IDs or `--all`, not both.
- A tunnel whose process is gone, or whose process ID now belongs to
  another program, shows as down and is never signalled.
- `komando status` shows tunnels together with VPNs, logins and jobs
  ([What is still running](commands.md#see-what-is-still-running)).

## Behind a company proxy

Some networks reach the internet only through a company proxy. Set it the
way `curl`, `kubectl` and `docker` read it, for example in `~/.zshrc`:

```bash
export HTTPS_PROXY=http://proxy.example.com:3128
export NO_PROXY=.internal,10.0.0.0/8     # names and networks reached directly
```

| What | How it gets out |
|---|---|
| Web APIs: Kubernetes clusters (also `cluster exec`, `cluster forward`, `cluster shell`), registries, S3 storage, secret stores (Vault, 1Password, Bitwarden, AWS, GCP, Azure), the logins and tunnels of AnyConnect, Fortinet, GlobalProtect, F5 and Pulse VPNs, and `komando update` | through `HTTPS_PROXY` (and `HTTP_PROXY` for `http://` addresses), except what `NO_PROXY` names |
| Servers (SSH), databases, caches, FTP and SFTP | not through `HTTPS_PROXY`: `ssh` and `psql` do not read it either, and a company proxy usually lets only web traffic out. Reach them through the proxy added as a VPN, then `--via NAME`: an HTTP proxy with `komando vpn add NAME proxy --proxy-address HOST:PORT`, a SOCKS proxy with `komando vpn add NAME socks --proxy-address HOST:PORT`; or through a bastion |
| WireGuard, L2TP/IPsec, IPsec and IKEv2 VPNs | not through a proxy: they use UDP, which a web proxy cannot carry |

- A kubeconfig's `proxy-url` wins over `HTTPS_PROXY` for that cluster, as
  with `kubectl`. It may be `http://`, `https://` or `socks5://`.
- A server or conn reached with `--via` goes out through its path, never
  through these proxies.
- An HTTP proxy as a VPN (`proxy` kind) tunnels each connection with
  CONNECT. `host ssh-command` turns it into an OpenSSH `ProxyCommand`
  (`nc -X connect`) when the proxy needs no login.
- Addresses on this computer (`localhost`, a tunnel's `127.0.0.1` port)
  never use a proxy.
- A user name and password in the proxy URL
  (`http://user:password@proxy:3128`) are sent to the proxy. Errors show
  the URL with the password hidden.

## Limits

- Tunnels listen on `127.0.0.1`, so only your computer can use them. To
  listen on another address (`-L 0.0.0.0:8080:...`), add `--yes`; an AI
  agent adds it only after a person agrees ([Safety](safety.md)). Anyone on that network can
  then use the tunnel without logging in.
- `-R` needs a server at the end of the path: a VPN cannot listen for you.
- One tunnel takes exactly one of `-L`, `-R` and `-D`.
- Many company proxies let only port 443 through.
- WireGuard, L2TP/IPsec, IPsec and IKEv2 VPNs cannot go through a web proxy.
- Over WinRM, a Windows server takes no tunnels ([Windows servers](windows.md)).

## Troubleshooting

| Error code | What it means | What to do |
|------------|---------------|------------|
| `OPEN_BIND` | the tunnel would listen on an address other computers can reach (exit 6) | keep the default `127.0.0.1`, or add `--yes` when you mean it |
| `PORT_IN_USE` | the local port is taken (exit 8); for `-R`, sshd on the server may have `AllowTcpForwarding` off | pick another port, or `0` for a free one |
| `CANCELLED` | Ctrl-C stopped the tunnel before it came up; nothing is left running | start it again |
| `TUNNEL_NOT_FOUND` | no tunnel with that ID | see them with `komando tunnel list` |
| `VPN_DOWN` | the VPN or proxy on the path did not come up, or a proxy refused the port | read the message; `komando vpn test NAME` tries again |
| `HOST_IN_USE` | a server you want to remove is still a step on another one's `--via` path | change their `--via` first |
