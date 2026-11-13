# Targets

Pick which servers, conns and VPNs a command works on: one name, a group, a
tag, or everything. [All docs](README.md)

## Write a target

Most commands take a *target*. One target picks servers, conns (databases,
caches, queues, storage, clusters, registries) and VPNs together:

```bash
komando exec @web -- uptime            # run on every server in group web
```

| Write | Picks |
|-------|-------|
| `web1` | one server or conn, by name |
| `web-*` | names that start with `web-` |
| `@prod` | everything in group `prod` |
| `tag:prod` | everything tagged `prod` |
| `label:dc=jkt` | everything with label `dc=jkt` (`label:dc` picks everything that has a `dc` label) |
| `kind:db` | every database (also `kind:host`, `kind:conn`, `kind:vpn`, `kind:cache`, `kind:queue`, `kind:storage`, `kind:cluster`, `kind:registry`, `kind:postgres`, and the other conn kinds) |
| `os:windows` | every Windows server (`os:linux`: every other server) |
| `all` | everything |
| `@prod,!web2` | combine with `,`; leave out with `!` |
| `!web2` | everything except `web2` (same as `all,!web2`) |
| `root@203.0.113.10:22` | a one-off server that is not in your list (`203.0.113.10` or `203.0.113.10:22` uses your default user) |

Quote targets that contain `*` or `!` so your shell leaves them alone:
`'web-*'`, `'@prod,!web2'`.

Names, groups and tags match in any case: `WEB1` finds `web1` when there is
only one. A misspelled name, `@group` or `tag:` gets a "did you mean".

At your terminal, a command typed without its target asks for it: pick a
row by number, type part of a name to narrow the list, or type a target as
above ([details](commands.md#at-your-terminal-komando-asks-for-what-is-missing)).

## Check what a target picks

```bash
komando list @prod           # only what @prod picks
```

```text
NAME     KIND      WHERE                VIA      GROUPS  TAGS  PROTECTED
web1     host      ubuntu@203.0.113.10  -        prod    web   yes
prod-db  postgres  10.0.0.9:5432        bastion  prod    -     yes
```

```bash
komando list                 # everything: servers, conns and VPNs
komando list kind:db         # only databases
komando test @prod           # reach and log in to each one
```

## What each command does with a target

Each command uses what it can work with and tells you what it left out. For
example, `komando exec @prod -- uptime` runs on the servers in `prod` and
lists the databases under "skipped". `komando db query @prod "..."` does the
opposite: it uses the one database in `@prod` (a `db` command needs exactly
one) and skips the servers. If a target picks nothing the command can use,
the error names the command to use instead. A target that picks nothing is
an error, not an empty result.

## Groups, tags and labels

Set them when you add or edit a server or conn:

```bash
komando host edit web1 --add-group prod --add-tag web --label dc=jkt
komando host edit web1 --rm-group prod --rm-tag web
```

Or manage a group for many entries at once:

```bash
komando group add prod 'web-*'          # add everything a target picks
komando group add prod web1 web2        # several names
komando group list                      # every group and tag with its members
komando group list prod                 # the members of one group
komando group rm prod web2              # take web2 out of prod
komando group rm old --dry-run          # delete a whole group: who would leave it
komando group rm old                    # more than 3 members: asks first
```

Typed alone, `komando group add` asks for the group, then what goes in it.

Deleting a group with more than 3 members asks first: at your terminal
komando asks `[y/N]`; an AI agent or a script adds `--yes` after a person
agrees ([Safety](safety.md)). At a terminal, `group rm` ends with the way
back: `Next: komando group add old TARGET...`.

## Limits

- A server, conn or VPN name uses letters, digits, `.`, `_` and `-`,
  starts with a letter or digit, and is at most 63 characters long.
- Group, tag and label names use the same letters, so every one can be
  written in a target.
- `all` cannot be a name, because as a target it means everything.
- Servers, conns and VPNs share one list of names, and `Web1` and `web1`
  are the same name.
- A `db`, `cache` or other conn command needs exactly one conn of its kind
  in the target.

## Troubleshooting

| Error code | What it means | What to do |
|------------|---------------|------------|
| `TARGET_EMPTY` | the target matched nothing (exit 3) | `komando list` shows servers, conns, groups and tags |
| `NO_MATCHING_TARGETS` | the target picked only things this command cannot use (exit 3) | the hint names the command for what it picked |
| `HOST_NOT_FOUND` | no server of that name (exit 3) | check the "did you mean", or `komando host list` |
| `USAGE` | a command that needs exactly one conn got a target with several | name the one conn |
| `CONFIRM_REQUIRED` | `group rm` of a group with more than 3 members, from an AI agent or a script without `--yes` | check the members with `komando group list GROUP`, then add `--yes` after a person agrees |
