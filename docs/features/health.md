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
