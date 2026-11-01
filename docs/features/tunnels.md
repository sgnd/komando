# Private servers and tunnels

Reach servers and services that are not on the internet. [All features](README.md)

## Through a bastion

Many private servers can only be reached through one public "gateway"
server, often called a **bastion** or jump host. Tell komando once, and
every command goes through it by itself:

```bash
komando host add bastion ubuntu@203.0.113.10
komando host add db1 admin@10.0.0.5 --jump bastion          # a server behind the bastion
komando host add deep admin@10.1.0.7 --jump bastion,db1     # a chain: bastion, then db1
komando conn add app-db postgres://app@10.0.0.9/app --via bastion   # a database behind it
```

komando opens the connection through the bastion inside its own process. No
port opens on your computer and your network settings do not change.

## Tunnels for other apps

A tunnel makes a service on a server appear on your own computer. Tunnels
run in the background until you stop them.

`-L 15432:localhost:5432` means: "port 15432 on *my* computer leads to port
5432 (PostgreSQL) on the server". Then point your database app at
`localhost:15432`.

```bash
komando tunnel start db1 -L 15432:localhost:5432
komando tunnel start bastion -D 1080   # a SOCKS proxy: set your browser to localhost:1080 to browse "from" the server
komando tunnel list
komando tunnel stop --all
```
