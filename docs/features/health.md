# Health and network checks

Find out what a server is, whether it is healthy, and what it can reach.
[All docs](README.md)

## Quick start

```bash
komando facts web1                               # OS and its support, updates, Docker, ports, tools
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
It also shows what needs attention:

```bash
komando facts web1
komando facts @web
```

```text
● app3  Ubuntu 20.04.6 LTS · x86_64 · 4 cpu · 7.8 GB RAM · disk / 63% · load 0.12 · up 34d
  support:   UNSUPPORTED: no security updates
  updates:   12 pending, security unknown · index 11d old · REBOOT REQUIRED · restart needed: nginx.service
  access:    user deploy · sudo without password · 1 failed units
  docker:    docker 24.0.7 · swarm manager · 14 running
  pm2:       (deploy) api online, worker online
  ports:     22 sshd, 80 nginx, 443 nginx, 3000 node (local only)
  units:     pm2-deploy.service (active), backup.timer (active)
  warning: Ubuntu 20.04.6 LTS: standard support ended 2025-05-31 and Ubuntu Pro (ESM) is not enabled, so it gets no security updates; ...
```

| Line | What it tells you |
|------|-------------------|
| support | Whether the OS still gets security updates: `supported`, `extended` (Ubuntu Pro ESM is enabled, or Debian LTS), `unsupported` or `unknown`. |
| updates | Pending updates and how many are security updates, read from the server's package index as it is (komando does not refresh it; `komando pkg update` does). A needed reboot, and services that still run old libraries (when `needrestart` is installed and komando may use sudo). |
| access | The login user, and whether sudo works without a password. |
| docker | Docker's version, the Swarm role (manager, worker, none) and how many containers run. |
| pm2 | Node.js apps run by PM2, outside containers. |
| ports | Listening ports and the program behind each one. Without root or passwordless sudo, only your own programs have names. |
| units | Services and timers added by hand under `/etc/systemd/system` (not from a package). |

`facts` only reads. It never refreshes a package index or starts anything,
and it uses sudo only when sudo already works without a password (it never
asks for one).

### What "unknown" means

When komando cannot read something, the JSON says
`null` (and the text says "unknown"), never `0` or `false`. This matters most
for security updates: a server whose OS is past its support gets no new
security updates, so its package index shows none pending. komando reports
those as unknown, with a warning, instead of a reassuring `0`. Agents should
read `warnings` first.

### The JSON fields

In JSON (`-o json`), each server's `data` has these fields besides the
basics (`os`, `os_version`, `kernel`, `cpus`, `mem_total_mb`, `tools` ...):

| Field | Meaning |
|-------|---------|
| `os_support` | `status`, `standard_support_until`, `extended_support_until`, `extended_by` (`ubuntu-pro-esm`, `debian-lts`), `past_standard_support`, `esm_enabled` (Ubuntu), `dates_checked` |
| `updates` | `total`, `security`, `source`, `index_age_days` |
| `reboot_required`, `reboot_packages` | a reboot is needed, and for which packages (Debian and Ubuntu; `kernel` when needrestart sees a newer kernel than the running one); on dnf/yum from `needs-restarting -r` |
| `services_need_restart` | services that run old code, from `needrestart` (or `needs-restarting -s` on dnf/yum); `null` without either, or without sudo |
| `sudo_nopasswd`, `login_user` | the same check as `komando test` |
| `docker` | `installed`, `version`, `daemon_reachable`, `server_version`, `swarm`, `containers_running` |
| `pm2` | `daemon_users` (every user running PM2), `apps` of the login user (`name`, `status`, `pid`, `restarts`, `cpu_pct`, `memory_mb`), `other_users` |
| `listening` | `source` (`ss`, `netstat` or `/proc`), `process_names` (`all`, `own` or `none`), `ports[]` (`proto`, `address`, `port`, `process`, `pid`) |
| `custom_units` | `unit`, `enabled`, `active` for each unit added by hand; `failed_units` counts failed ones |
| `warnings` | things an agent must not miss, in plain words |

Only names are kept, never command lines or environments (they can hold
passwords), and secret-looking text is hidden.

### Where the support dates come from

komando has a small built-in table
for Ubuntu LTS, Debian, RHEL and its rebuilds (Rocky, AlmaLinux, Oracle
Linux, CentOS), Alpine and Amazon Linux, taken from each vendor's release
page (the sources are listed in `internal/cli/facts_support.go`). The JSON
shows the date it was checked (`os_support.dates_checked`). A release that
is not in the table, such as a short-lived Ubuntu release, is `unknown`. For
Ubuntu, komando also asks `pro status` whether ESM is enabled.

## Check server health

komando comes with 36 ready-made checks (built-in recipes). Run one on any
target:

```bash
komando recipe list                               # all of them, with what they run
komando recipe list --category security           # one category
komando recipe run health @web
komando recipe run top-mem web1
komando recipe run big-dirs web1 --var path=/srv
komando recipe run updates all
```

| Category (`--category`) | Recipes |
|-------------------------|---------|
| system | `health`, `disk`, `inodes`, `memory`, `big-dirs`, `big-files`, `cron-all`, `time-sync` |
| process | `top-cpu`, `top-mem`, `process`, `oom` |
| service, logs | `failed-units`, `journal-errors` |
| network | `ports`, `connections`, `dns`, `firewall` |
| web | `http-check`, `nginx-test`, `nginx-sites`, `apache-test` |
| security | `auth-failures`, `last-logins`, `sshd-config`, `sudoers` |
| packages | `updates`, `security-updates` |
| container | `docker-overview`, `k8s-overview` |
| database | `postgres-status`, `mysql-status`, `redis-info` |
| maintenance (these change things) | `apt-clean`, `drop-caches`, `journal-vacuum` |

Some recipes have blanks with defaults, for example `big-dirs` takes
`--var path=/srv --var depth=2`. `komando recipe list` shows each recipe's
blanks. Certificates have their own command, `komando cert check`, and
so does cleaning up docker, `komando docker prune` (with a preview).
To save your own checks, see [Recipes](commands.md#recipes-ready-made-and-saved-commands).

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

- On a server, komando finds the certificates itself: certbot's
  (`/etc/letsencrypt/live/*/cert.pem`) and the files nginx
  (`ssl_certificate`), haproxy (`crt`) and apache (`SSLCertificateFile`)
  use. Add more with `--path`. Files that need root are read with sudo only
  when sudo works without a password; komando never asks for one. Only the
  certificate part of a file is read: a private key in the same file never
  leaves the server. When certbot is installed, the result also shows its
  renewal timer and whether the last renewal failed.
- For a website (`https://NAME`, `NAME:PORT`) or a conn that uses TLS,
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
| `net http` | nothing answers (`NO_RESPONSE`, within 15 seconds, or `--timeout`) | 4 |
| `net http --expect 2xx` | the status is another one (`UNEXPECTED_STATUS`); `--expect 200` names one status | 5 |
| `net dns` | the name does not resolve (`NXDOMAIN`) or has no records of that type (`NO_RECORDS`) | 3 |

Good to know:

- `net ports` uses `ss`, or `netstat` on small systems such as busybox. Add
  `--sudo` to see the process names.
- `net dns` without `--type` shows the addresses the server would connect
  to. `--type` takes A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, PTR or CAA. A and
  AAAA work everywhere; the others need `dig` on the server, and the error
  says which package installs it.
- `net http` takes `http://` and `https://` URLs only. It reports the status,
  timing, the IP it reached and any redirect.
