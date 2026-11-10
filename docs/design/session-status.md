# Session status: "where am I, and what is still running?"

Status: built (2026-11-03). How to use it:
[docs/features/output.md](../features/output.md). Stress-tested against the
cases in [Stress test](#stress-test); several first ideas were dropped there.

## The question

A person using komando should always be able to answer two questions:

1. **Where am I typing right now?** Which server or database, as which user,
   through which VPN and bastions, and is it protected (production)?
2. **What is still running in the background?** VPNs kept up, tunnels, jobs.

Before this work komando answered neither in one place. `komando ssh web1`
passed the terminal straight to the server and printed nothing of its own;
`db shell` printed one line; VPN sessions, tunnels and jobs each had their
own list command.

## Four shapes of command

Every komando command has one of four shapes. Each shape gets one kind of
status, and no more, so the rules stay simple.

| Shape | Commands | Status it gets |
|---|---|---|
| **A. Interactive session**: a person types inside | `shell`/`ssh`, `db shell` | entry line + exit line on stderr |
| **B. Foreground until Ctrl-C** | `cluster forward`, `logs --follow` (host, docker, cluster) | entry line on stderr |
| **C. Background, outlives the command** | VPN sessions (`vpn up`, or started by a command), `tunnel start`, `job start` | `komando status`, and an optional prompt segment |
| **D. One-shot** (almost everything else: exec, fs, db query, cache, storage, registry, cluster get/deploy, svc, pkg, ...) | none | nothing new, except one notice when a command starts a VPN by itself |

One-shot commands deliberately get no banner: their stdout is data (JSON for
agents and pipes), and a line on every command is noise.

## The line format (shapes A, B, D)

One grammar for every line, always on **stderr**, always starting with
`komando:` so it is never mistaken for server output:

```
komando: <what> <target> [(<who/mode>)] [via <route>] [· PROTECTED]
```

Examples:

```
komando: shell on web1 (deploy@10.0.1.5) via vpn telkomsel → bastion1
komando: shell on prod-web1 (root@10.0.0.5) · PROTECTED
komando: psql on app-db (read-only) via bastion1
komando: forwarding 127.0.0.1:8080 → svc/api:80 on prod-k8s via bastion1 (Ctrl-C stops)
komando: following logs on web1, web2 (Ctrl-C stops)
komando: vpn telkomsel connected; it stays up until unused for 30m (`komando vpn down telkomsel` stops it)
```

Exit line, shape A only:

```
komando: left web1 (exit 0, 12m)
komando: connection to web1 lost after 3m
```

Rules:

- **Route** comes from the inventory (`resolveChain` for hosts, the conn's
  `--via` for conns): VPN first, then bastions in order, joined by ` → `.
  A proxy-command hop shows its host name only, never the command.
- **PROTECTED** is the word itself, plus red when colour is allowed (below).
  Uses `protectedHost` / `protectedConn`, so a second name for a protected
  server is marked too.
- The entry line is printed **before** connecting. The route is known from
  the inventory without any network, and a slow VPN login, MFA or proxy
  command then shows where it is waiting. If connecting fails, the normal
  error follows and there is no exit line.
- **Printed only when a person is at the terminal** (`interactive()`: stdin
  and stderr are terminals and no agent). Agents and pipes see exactly what
  they see today. JSON output never changes.

## Background status (shape C)

### `komando status`

One new top-level command that lists everything komando left running:

```
KIND    NAME    DETAIL                                     SINCE
vpn     office  used 3m ago, closes in 26m if unused       42m
tunnel  t-3f2a  127.0.0.1:5433 → app-db                    2h
job     j-81c2  web1: pg_dump app | gzip > /backup/app...  15m
jobs run on their servers: `komando job list --refresh` shows which still run
```

- VPNs and tunnels: liveness checked like `vpn status` and `tunnel list`.
- Jobs run on the server; locally komando only knows they were started.
  `status` lists them as **started**, with the command that checks them. It
  does not SSH anywhere (it must be fast and work offline).
- JSON output like every other command, so agents can use it at the start of
  a session.
- `vpn status`, `tunnel list` and `job list` stay; `status` is the summary.
- Added later: `status` also lists the server logins `komando login` keeps.

### Prompt segment (optional, opt-in)

The breadcrumb idea belongs in the person's **own** prompt on this
computer, for the one kind of state that lives between commands:

```
~/projects ⟨vpn:telkomsel tun:2⟩ $
```

`komando prompt` prints that short text, or nothing when nothing runs. The
person adds it to their prompt themselves; komando never edits shell
dotfiles. The docs give a snippet for zsh (including oh-my-zsh), bash and
starship. Jobs are left out: whether a remote job is still running is
unknown without SSH.

## Stress test

Each case below was checked against the current code. **Decision** says what
the plan does about it.

### Dropped ideas

| Idea | Why it breaks | Decision |
|---|---|---|
| Change the server's prompt to `ssh:web1 >` | Needs `PS1` injected on the server: changes the server, differs per shell (bash, zsh, sh, busybox), fights the owner's dotfiles; `Setenv` is refused by most `sshd` (`AcceptEnv`) | **Dropped** |
| Rewrite the remote prompt inside komando's stream | komando would have to parse the byte stream; breaks `vim`, `htop`, `less`, colour codes | **Dropped** |
| komando's own REPL (`vpn:telkomsel:ssh:web1 >`) | It is a TUI (vision decision 5: no TUI); agents cannot use it; a second shell to learn | **Dropped** |
| Terminal window title `komando: web1` | Ubuntu's default `.bashrc` overwrites the title on every prompt; macOS Terminal.app has no title stack, so the old title cannot be restored; tmux needs passthrough; after a crash the stale title says you are still on the server | **Dropped** (could return as opt-in later) |
| A banner on every one-shot command | Noise; agents and scripts read stdout | **Dropped** |

### Interactive sessions (shape A)

| Case | Risk | Decision |
|---|---|---|
| The terminal is in raw mode during the session | A line printed in raw mode has no carriage return and draws as a staircase | Exit line printed **after** `term.Restore` (in `shell.go` the restore is deferred inside the callback, so print after `withClient` returns) |
| Remote exit code | Banner must not change it | Exit code passed through as today; the line only reports it |
| Network drops | `sess.Wait` returns a non-`ExitError` | Exit line says "connection lost after …" instead of an exit code |
| Ctrl-C, terminal closed, komando killed | No exit line | Acceptable: entry line is already on screen |
| `stdout` redirected (`komando ssh web1 \| tee log`) | Banner in the log | Banner goes to stderr only |
| Host name, ad-hoc `user@host` or imported address contains escape codes | Terminal injection (a name could rewrite the screen or the title) | Inventory names are validated, but ad-hoc targets and addresses are not: **strip control characters** from every printed field |
| Secrets | A line could leak a password | Prints names, user, address and route only; never URLs, password refs or VPN session logins |
| Colour | komando has no colour today | Red only for PROTECTED, only when stderr is a terminal, not with `NO_COLOR` set or `TERM=dumb`; the word is always there (colour-blind people, logs) |
| Nested komando (komando run on the server) | Two banners | Fine: each says `komando:` and its own target |
| An agent with a pseudo-terminal runs `komando ssh` | `shell` checks only that stdin is a terminal, not `isAgent()`, so an agent can open an interactive shell, also on a protected host | **Found issue**, fixed: `shell` refuses agents, like `db shell` |
| `komando ssh prod-web1 --dry-run` | `shell.go` never reads `--dry-run`: it opens a real shell | **Found issue**, fixed: `--dry-run` prints the target and route and exits |
| `komando ssh` on a protected host | `db shell` asks for confirmation on a protected conn; `ssh` does not | **Found issue**, fixed: `shell` on a protected host asks `[y/N]` like `db shell` (approved by the owner) |

### Background status (shape C)

| Case | Risk | Decision |
|---|---|---|
| Prompt segment calls `netx.LiveSession` | `LiveSession` **writes** `LastUsed`: rendering the prompt would keep every VPN alive forever and defeat `vpn_idle`. It can also stop stale sessions | `prompt` and `status` never call `LiveSession`; they read only |
| Prompt segment runs on every Enter | `SessionAlive` runs `ps` on macOS: slow on every Enter | `prompt` checks the pid only (`kill 0`) plus the idle time, never runs another program and never changes the state file; `status` may do the full check. Measured: about 30 ms per call on an M-series Mac, of which about 20 ms is Go package start-up (mostly `rs/xid`, pulled in by the S3 client); reading the state takes well under 1 ms |
| `komando prompt` goes through the root command's setup | `PersistentPreRunE` reaps idle VPNs and checks the audit log is writable: work and writes on every prompt | `prompt` skips that setup |
| State file missing, corrupt, or being written | Broken prompt | State is written by rename (atomic), so a read sees old or new. On any error `prompt` prints nothing and exits 0: it must never break the person's shell |
| State holds VPN SOCKS logins | Leak into the prompt | Only VPN names and tunnel counts are printed |
| A VPN process died and its pid was reused | Prompt shows a VPN that is down | Accepted: the prompt is a hint; `komando status` is the full check (it also matches the program name). Documented |
| Several terminals | Is state per terminal? | No: VPN sessions and tunnels are shared by all terminals of the user, so every prompt shows them. That is correct |
| Jobs | Local record cannot tell whether the remote job finished | Not in the prompt; `status` says "started" and shows the check command |
| `komando status` offline | Must not hang | No network at all |

### Shapes B and D

| Case | Risk | Decision |
|---|---|---|
| `cluster forward`, `logs --follow` | The server prints its own lines too | Entry line is the first line, on stderr, before the stream starts |
| A one-shot command starts a VPN by itself | The person does not know a VPN is now up for 30 minutes | One notice line on stderr, interactive only. Agents get nothing new; `komando status` shows it |
