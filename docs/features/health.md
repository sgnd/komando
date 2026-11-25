# Health and network checks

Find out what a server is, whether it is healthy, and what it can reach.
[All docs](README.md)

Every check on this page is a command that runs on the server through
`komando host ssh exec TARGET --read-only -- COMMAND`, or a ready-made
snippet. `--read-only` accepts only commands komando knows only read; for
a command it does not know, komando refuses with `READ_ONLY_VIOLATION`
and you run it without the flag, which counts as a change (a protected
server then asks first). Output is text, with no fixed shape: add `-o text`
to read it.

## Learn what a server is

Run these first on a server you do not know. They tell you the OS, CPU,
memory, disk, load, the package manager, the init system and which tools
are installed, so you (or your agent) know which commands fit.

```bash
komando host ssh exec web1 --read-only -- uname -a
komando host ssh exec web1 --read-only -- cat /etc/os-release
komando host ssh exec web1 --read-only -- uptime
komando host ssh exec web1 --read-only -- df -h
komando host ssh exec web1 --read-only -- free -m
```

Typed alone at your terminal, `komando host ssh exec` asks for the server
(from your list), then the command. `komando host ssh exec @web ...` runs
it on many servers at once, and each result names its server in `host`.

| To learn | Command after `--` |
|----------|--------------------|
| the OS and its release | `cat /etc/os-release` |
| CPU and memory | `nproc`, `free -m` |
| disks | `df -h` (add `-i` for inodes) |
| load and uptime | `uptime` |
| the package manager | `command -v apt-get dnf yum apk zypper pacman` |
| the init system | `ps -p 1 -o comm=` |
| listening ports and their programs | `ss -tlnp` (add `--sudo` to see the program names) |
| failed services | `systemctl --failed` |
| running containers | `docker ps` |
| whether a reboot is needed | `test -f /var/run/reboot-required && echo yes` |

`exec` only reads when you add `--read-only`. A command that reads with
sudo (for example `ss -tlnp`) takes `--sudo` as well. Without root or
passwordless sudo, only your own programs have names in `ss`.

Lost: the one-screen summary with the OS support dates, the pending-update
counts and the JSON fields the apps parsed (`os_support`, `updates`,
`listening`, `warnings` and the others). Read each fact with its own
command, as above. A date past an OS's end of life you check with the
vendor's release page.

TODO(cut): a ready-made snippet that gathers these facts in one call waits
on its row; the JSON fields apps read waits on O-22.

## Check server health

komando comes with ready-made checks (built-in snippets). Run one on any
target:

```bash
komando snippet exec health @web                  # uptime, load, memory, disk, failed services
komando snippet list                              # all of them, with what they run
komando snippet exec top-mem web1
komando snippet exec big-dirs web1 --var path=/srv
komando snippet exec oom all --var since=-2h
```

Typed alone, `komando snippet exec` asks for the snippet, then the target.

| Category | Snippets |
|----------|----------|
| system | `health`, `disk`, `inodes`, `memory`, `big-dirs`, `big-files`, `cron-all`, `time-sync` |
| process | `top-cpu`, `top-mem`, `process`, `oom` |
| network | `connections`, `firewall` |
| web | `nginx-test`, `nginx-sites`, `apache-test` |
| security | `auth-failures`, `last-logins`, `sshd-config`, `sudoers` |
| maintenance (these change things) | `apt-clean`, `drop-caches`, `journal-vacuum` |

Some snippets have blanks with defaults, for example `big-dirs` takes
`--var path=/srv --var depth=2`. `komando snippet show NAME` shows a
snippet's blanks. A time back from now is written with a minus
(`since=-2h`), as journalctl reads it.

TODO(cut): listing one category of snippets waits on the `Options` of
`snippet list` (PR B).

Checks that read one fact are plain commands, not snippets:

| Check | Command |
|-------|---------|
| listening ports | `komando host ssh exec TARGET --read-only --sudo -- ss -tlnp` |
| failed units | `komando host ssh exec TARGET --read-only -- systemctl --failed` |
| journal errors | `komando host ssh exec TARGET --read-only --sudo -- journalctl -p err --since -1h --no-pager` |
| pending updates | `komando host ssh exec TARGET --read-only -- apt list --upgradable` (dnf: `dnf check-update`) |
| containers | `komando host ssh exec TARGET --read-only -- docker ps -a` |
| Docker disk use | `komando host ssh exec TARGET --read-only -- docker system df` |
| a Kubernetes cluster | `komando cluster kubernetes raw prod-k8s -- get nodes` |
| database sessions | `komando database postgres query prod-db 'SELECT pid, state, query FROM pg_stat_activity'` |
| a cache | `komando cache redis raw prod-redis -- INFO` |

To save your own checks, see [Snippets](commands.md).

## Check TLS certificates

Lost: `cert check`, which told you when certificates expire. It comes back
when paid monitoring exists. Until then, read an expiry with `openssl`
through `exec`:

```bash
komando host ssh exec web1 --read-only -- openssl x509 -enddate -noout -in /etc/letsencrypt/live/shop.example.com/cert.pem
komando host ssh exec @web --read-only --sudo -- sh -c 'for f in /etc/letsencrypt/live/*/cert.pem; do echo $f; openssl x509 -enddate -noout -in $f; done'
```

To see the certificate a website sends, run `openssl s_client` from the
server:

```bash
komando host ssh exec web1 --read-only -- sh -c 'openssl s_client -connect shop.example.com:443 -servername shop.example.com </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -enddate'
```

- `-enddate` prints the expiry date. `openssl x509 -checkend 2592000 -noout
  -in FILE` exits non-zero when the certificate expires within 30 days.
- Read only the certificate part of a file. Never print a private key.
- komando finds no certificates for you: certbot keeps its own at
  `/etc/letsencrypt/live/*/cert.pem`, and nginx, haproxy and apache name
  theirs in their configuration (`ssl_certificate`, `crt`,
  `SSLCertificateFile`).

## Check the network from a server

These checks run *from* your servers, so you see what they see. Lost:
`net check`, `net ports`, `net http` and `net dns`, with their fixed
results and exit codes. Read each with the tool's own command:

```bash
komando host ssh exec @web --read-only -- nc -zv -w 5 10.0.0.5 5432     # can each server open a TCP connection?
komando host ssh exec web1 --read-only -- curl -sS -o /dev/null -w '%{http_code} %{time_total}s\n' https://example.com
komando host ssh exec web1 --read-only --sudo -- ss -tlnp               # listening ports and their programs
komando host ssh exec web1 --read-only -- dig +short api.example.com
komando host ssh exec web1 --read-only -- dig +short example.com MX     # MX, TXT, CNAME, NS ...
```

- `nc`, `curl` and `dig` must be installed on the server. Without `dig`,
  `getent hosts api.example.com` shows the addresses the server would
  connect to.
- `ss` is the tool on most servers; small systems such as busybox have
  `netstat`.
- Each result is the tool's own text and exit code (`exit_code` in JSON,
  per server), not a fixed `PORT_CLOSED`, `NO_RESPONSE` or `NXDOMAIN`
  error.

## Limits

- `--read-only` runs only commands komando knows only read. Anything else
  is `READ_ONLY_VIOLATION`.
- Without root or passwordless sudo, only your own programs in `ss` have
  names.
- Checks that read the package index show it as the server's own index is;
  `apt-get update` refreshes it and is a change.
- The checks hold no table of OS support dates.
- A check on a server needs the tool on that server (`nc`, `curl`, `dig`,
  `openssl`).
- Snippets with blanks refuse a `--var` value that starts with `-`, except
  a number or a time back from now (see [Snippets](commands.md)).

## Troubleshooting

| Error code | What it means | What to do |
|------------|---------------|------------|
| `READ_ONLY_VIOLATION` | `--read-only` does not know that the command only reads | check the command, then run it without `--read-only`; a protected server asks first |
| `SNIPPET_NOT_FOUND` | no snippet of that name (exit 3) | see them with `komando snippet list`; some checks are plain commands (table above) |
| `UNKNOWN_VAR` | `--var` names a blank the snippet does not have | check the blanks with `komando snippet show NAME` |
| `TOOL_MISSING` | the tool a check needs (`nc`, `curl`, `dig`, `openssl`) is not on the server | install the package that has it, or use another check |
| `PERMISSION_DENIED` | the login user may not read that | add `--sudo` |

TODO(cut): the exact error code for an unknown snippet waits on the error
catalog of the cut (S-8.2).
