# Health and network checks

Find out what a server is, whether it is healthy, and what it can reach.
[All features](README.md)

## Quick start

```bash
komando facts web1                               # OS, CPU, memory, disk, IPs, installed tools
komando recipe run health @web                   # uptime, load, memory, disk, failed services
komando recipe run disk all                      # disk use everywhere
komando net check @web 10.0.0.5:5432             # can the web servers reach the database?
komando net http web1 https://example.com        # does this URL answer from web1?
komando cert check web1 https://example.com      # when do the certificates expire?
```

## Learn what a server is

Run `facts` first on a server you do not know. It reports the OS, CPU,
memory, disk, load, IP addresses, the package manager, the init system and
which tools are installed, so you (or your agent) know which commands fit.

```bash
komando facts web1
komando facts @web
```

## Check server health

komando comes with 39 ready-made checks (built-in recipes). Run one on any
target:

```bash
komando recipe list                               # all of them, with what they run
komando recipe list --category security           # one category
komando recipe run health @web
komando recipe run top-mem web1
komando recipe run cert-expiry web1 --var name=example.com
komando recipe run updates all
```

| Category | Recipes |
|----------|---------|
| system | `health`, `disk`, `inodes`, `memory`, `big-dirs`, `big-files`, `cron-all`, `time-sync` |
| process | `top-cpu`, `top-mem`, `process`, `oom` |
| service and logs | `failed-units`, `journal-errors` |
| network | `ports`, `connections`, `dns`, `firewall` |
| web and TLS | `http-check`, `nginx-test`, `nginx-sites`, `apache-test`, `cert-expiry`, `certbot-certs` |
| security | `auth-failures`, `last-logins`, `sshd-config`, `sudoers` |
| packages | `updates`, `security-updates` |
| containers | `docker-overview`, `k8s-overview` |
| databases | `postgres-status`, `mysql-status`, `redis-info` |
| maintenance (these change things) | `apt-clean`, `docker-prune`, `drop-caches`, `journal-vacuum` |

Some recipes have blanks with defaults, for example `big-dirs` takes
`--var path=/srv --var depth=2`. `komando recipe list` shows each recipe's
blanks. To save your own checks, see [Recipes](commands.md#recipes-ready-made-and-saved-commands).

## Check TLS certificates

`cert check` tells you when certificates expire, before your visitors do.
It only reads.

```bash
komando cert check web1                               # the certificates web1's web servers use
komando cert check @prod --warn 14d                   # flag what expires within 14 days
komando cert check https://shop.example.com           # the certificate the website sends
komando cert check api.example.com:8443 intranet:443 --via bastion
komando cert check web1 --path /etc/ssl/private/site.pem
```

- **On a server** komando finds the certificates itself: certbot's
  (`/etc/letsencrypt/live/*/cert.pem`) and the files nginx
  (`ssl_certificate`), haproxy (`crt`) and apache (`SSLCertificateFile`)
  use. Add more with `--path`. Files that need root are read with sudo only
  when sudo works without a password; komando never asks for one. Only the
  certificate part of a file is read: a private key in the same file never
  leaves the server. When certbot is installed, the result also shows its
  renewal timer and whether the last renewal failed.
- **A website** (`https://NAME`, `NAME:PORT`) or a conn that uses TLS:
  komando connects from this computer, or through `--via` (a server or VPN),
  reads the certificate the site sends, and checks that it is trusted and
  matches the name.
- Each certificate shows its names, issuer, expiry date, days left, where
  it came from and a status: `ok`, `expiring`, `expired`, `not_yet_valid`,
  `not_trusted`, or `unreadable` (missing, or needs root).

| Result | Exit code |
|--------|-----------|
| every certificate is fine | 0 |
| one expires within `--warn` (default 30d), has expired, is not trusted, or certbot's last renewal failed (`CERT_PROBLEMS`) | 1 |
| a server or site could not be reached | 4 (or 7 on a timeout) |

`unreadable` files are listed but do not fail the command.

## Check the network from a server

These checks run *from* your servers, so you see what they see:

```bash
komando net check @web 10.0.0.5:5432 10.0.0.6:6379   # can each server open a TCP connection?
komando net http web1 https://example.com --expect 2xx
komando net ports web1 --sudo                         # PROTO ADDRESS PORT PROCESS PID
komando net dns web1 api.example.com
komando net dns web1 example.com --type MX            # MX, TXT, CNAME, NS ... need dig on the server
```

| Command | Fails when | Exit code |
|---------|-----------|-----------|
| `net check` | a port does not answer (`PORT_CLOSED`); the result says why: `refused`, `timeout` (after 5 seconds), `dns` or `unreachable` | 5 |
| `net http` | nothing answers (`NO_RESPONSE`, within 15 seconds) | 4 |
| `net http --expect 2xx` | the status is another one (`UNEXPECTED_STATUS`); `--expect 200` names one status | 5 |
| `net dns` | the name does not resolve (`NXDOMAIN`) or has no records of that type (`NO_RECORDS`) | 3 |

Good to know:

- `net ports` uses `ss`, or `netstat` on small systems such as busybox. Add
  `--sudo` to see the process names.
- `net dns` without `--type` shows the addresses the server would connect
  to. `--type` takes A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, PTR or CAA. A and
  AAAA work everywhere; the others need `dig` on the server, and the error
  says which package installs it.
- `net http` reports the status, timing, the IP it reached and any redirect.
