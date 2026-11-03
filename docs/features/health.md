# Health and network checks

Find out what a server is and whether it is healthy. [All features](README.md)

## Check server health

```bash
komando facts web1               # OS, CPU, memory, disk, IPs, installed tools
komando recipe list                 # 39 ready-made checks
komando recipe run health @web
komando recipe run disk all
komando recipe run top-mem web1
komando recipe run cert-expiry web1 --var name=example.com
komando recipe run updates all
```

## Network checks

Run *from* your servers:

```bash
komando net check @web db.internal:5432 redis.internal:6379
komando net http web1 https://example.com
komando net ports web1 --sudo                     # PROTO ADDRESS PORT PROCESS PID (ss, or netstat on busybox)
komando net dns web1 api.example.com
komando net dns web1 example.com --type MX         # MX, TXT, CNAME, NS ... need dig on the server
```

- `net check` fails (exit 5, `PORT_CLOSED`) when a port does not answer and
  says why: `refused`, `timeout` (5 seconds), `dns` or `unreachable`.
- `net http` exits 4 (`NO_RESPONSE`) when nothing answers; `--expect 200`
  or `--expect 2xx` fails on another status.
- `net dns` exits 3 when the name does not resolve.
