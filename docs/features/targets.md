# Targets

Pick which servers, conns and VPNs a command works on: one name, a group, a
tag, or everything. [All docs](README.md)

## Quick start

```bash
komando list @prod                     # what does this target pick?
komando test @prod                     # can komando reach and log in to each one?
komando exec @web -- uptime            # run on every server in group web
komando group add prod 'web-*'         # put matching servers in a group
komando group list                     # every group and tag with its members
```

## Write a target

Most commands take a *target*. One target picks servers, conns (databases,
caches, queues, storage, clusters, registries) and VPNs together:

| Write | Picks |
|-------|-------|
| `web1` | one server or conn, by name |
| `web-*` | names that start with `web-` |
| `@prod` | everything in group `prod` |
| `tag:prod` | everything tagged `prod` |
| `label:dc=jkt` | everything with label `dc=jkt` (`label:dc` picks everything that has a `dc` label) |
| `kind:db` | every database (also `kind:host`, `kind:conn`, `kind:vpn`, `kind:cache`, `kind:queue`, `kind:storage`, `kind:cluster`, `kind:registry`, `kind:postgres`, ...) |
| `os:windows` | every Windows server (`os:linux`: every other server) |
| `all` | everything |
| `@prod,!web3` | combine with `,`; leave out with `!` |
| `!web3` | everything except `web3` (same as `all,!web3`) |
| `root@203.0.113.10:22` | a one-off server that is not in your list (`203.0.113.10` or `203.0.113.10:22` uses your default user) |

Quote targets that contain `*` or `!` so your shell leaves them alone:
`'web-*'`, `'@prod,!web3'`.

Names, groups and tags match in any case: `WEB1` finds `web1` when there is
only one. A misspelled name, `@group` or `tag:` gets a "did you mean".

## Check what a target picks

```bash
komando list                 # everything: servers, conns and VPNs
komando list @prod           # only what @prod picks
komando list kind:db         # only databases
komando conn list            # only databases and other services (host list, vpn list: the others)
komando test @prod           # reach and log in to each one
```

## What each command does with a target

Each command uses what it can work with and tells you what it left out. For
example, `komando exec @prod -- uptime` runs on the servers in `prod` and
lists the databases under "skipped". `komando db query @prod "..."` does the
opposite. If a target picks nothing the command can use, the error names the
command to use instead.

## Groups, tags and labels

Set them when you add or edit a server or conn:

```bash
komando host edit web1 --add-group prod --add-tag web --label dc=jkt
komando host edit web1 -g prod -t web          # -g and -t are short for --add-group and --add-tag
```

Or manage a group for many entries at once:

```bash
komando group add prod 'web-*'          # add everything a target picks
komando group list prod                 # the members of one group
komando group rm prod web3              # take web3 out of prod
komando group rm old --dry-run          # delete a whole group: who would leave it
komando group rm old --yes              # more than 3 members needs --yes
```

Group, tag and label names use letters, digits and `. _ -`, like server
names, so every one can be written in a target.
