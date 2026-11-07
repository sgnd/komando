# Private servers and tunnels

Reach servers and services that are not on the internet, and open them in
the apps on your computer. [All features](README.md)

## Quick start

```bash
komando host add bastion ubuntu@203.0.113.10
komando host add db1 admin@10.0.0.5 --via bastion          # a server behind the bastion
komando conn add app-db postgres://app@10.0.0.9/app --via bastion   # a database behind it
komando tunnel start app-db                                # open app-db in TablePlus, psql, ...
komando tunnel list                                        # what is running
komando tunnel stop --all                                  # stop every tunnel
```

## Reach private servers through a bastion

Many private servers can only be reached through one public gateway server,
called a **bastion** or jump host. Tell komando once with `--via`, and every
command goes through it by itself:

```bash
komando host add bastion ubuntu@203.0.113.10
komando host add db1 admin@10.0.0.5 --via bastion          # one step
komando host add db2 admin@10.1.0.7 --via bastion,db1      # a chain: bastion, then db1
komando conn add app-db postgres://app@10.0.0.9/app --via bastion
komando exec db1 -- uptime                                 # goes through bastion
```

- A chain lists the steps in order, from your computer to the target.
- `--via` works the same for servers and conns (databases, caches, storage).
  It can also start with a VPN: see [VPNs](vpn.md).
- komando opens the connection through the bastion inside its own process.
  No port opens on your computer, and your network settings do not change.
- Older docs may say `--jump`. On `komando host add` and `host edit` it
  still works and means the same as `--via`; conns take only `--via`.

## Open a private database in your own app

To use TablePlus, DBeaver, psql or another app on a database behind a
bastion, start a tunnel by the conn's name. komando picks a free local port
and prints it:

```bash
komando tunnel start app-db                  # → listen: 127.0.0.1:53412
komando tunnel start app-db --port 15432     # choose the port yourself
```

Point the app at that address, with the database's user name and password.
The tunnel runs in the background until you stop it with
`komando tunnel stop`.

## Forward any port

A tunnel makes a service on a server appear on your own computer (or the
other way round). There are three kinds:

| Flag | Direction | Example | Meaning |
|------|-----------|---------|---------|
| `-L` | server → your computer | `-L 15432:localhost:5432` | port 15432 on *your* computer leads to port 5432 as seen from the server |
| `-R` | your computer → server | `-R 9000:localhost:3000` | port 9000 *on the server* leads to port 3000 on your computer |
| `-D` | SOCKS5 proxy | `-D 1080` | apps set to proxy `localhost:1080` connect "from" the server |

```bash
komando tunnel start db1 -L 15432:localhost:5432    # then connect to localhost:15432
komando tunnel start web1 -L 8080:localhost:80      # a web app on web1, at localhost:8080
komando tunnel start web1 -R 9000:localhost:3000    # show your local app to web1
komando tunnel start bastion -D 1080                # browse "from" the bastion
komando tunnel list                                 # tunnels and whether they still run
komando tunnel stop t1102-...                       # stop one by its ID
komando tunnel stop --all
```

- A port of `0` picks a free one. The result shows the address that was used.
- For `-R`, the listening address is on the server. The result says so
  (`remote_listen`, `listen_on`).
- `tunnel list` removes entries for tunnels that are no longer running.
- `komando status` shows tunnels together with VPN sessions and jobs.

## Good to know

- **Only your computer can use a tunnel.** Tunnels listen on `127.0.0.1`.
  To listen on another address (`-L 0.0.0.0:8080:...`), add `--yes`;
  without it the tunnel stops with `OPEN_BIND`. Anyone on that network can
  then use the tunnel without logging in.
- **Port already taken?** The tunnel stops with `PORT_IN_USE` (exit 8).
  Pick another port, or `0` for a free one. For `-R` it can also mean that
  sshd on the server has `AllowTcpForwarding` turned off.
