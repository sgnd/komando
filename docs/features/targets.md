# Targets

Pick which entries a command works on: one name, a group, a tag, or
everything. [All docs](README.md)

## Write a target

Most commands take a *target*. One target can pick entries of every type
(servers, databases, caches, queues, storage, clusters, registries, VPNs):

```bash
komando host ssh exec @web -- uptime   # run on every ssh server in group web
```

| Write | Picks |
|-------|-------|
| `web1` | one entry, by name |
| `web-*` | names that start with `web-` |
| `@prod` | everything in group `prod` |
| `tag:prod` | everything tagged `prod` |
| `label:dc=jkt` | everything with label `dc=jkt` (`label:dc` picks everything that has a `dc` label) |
| `kind:database` | every database (also `kind:host`, `kind:cache`, `kind:queue`, `kind:storage`, `kind:cluster`, `kind:vpn`, `kind:postgres`, and the other providers) |
| `os:windows` | every Windows server (`os:linux`: every other server) |
| `all` | everything |
| `@prod,!web2` | combine with `,`; leave out with `!` |
| `!web2` | everything except `web2` (same as `all,!web2`) |
| `root@203.0.113.10:22` | a one-off server that is not in your list (`203.0.113.10` or `203.0.113.10:22` uses your default user) |

<!-- TODO(cut): the selectors `kind:`, `os:`, a glob, `!` and the one-off address wait on the target parser of the table builder (PR B). -->

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
NAME     TYPE      PROVIDER  WHERE          VIA      GROUPS  TAGS  PROTECTED
web1     host      ssh       203.0.113.10   -        prod    web   yes
prod-db  database  postgres  10.0.0.9:5432  bastion  prod    -     yes
```

```bash
komando list                 # everything: every entry
komando list kind:database   # only databases
komando test @prod           # reach and log in to each one
```

## What each command does with a target

A command under a provider works on that provider's entries and names
the others in `meta.skipped`. For example,
`komando host ssh exec @prod -- uptime` runs on the ssh servers in `prod`
and lists the databases as skipped. A group that also holds Windows
servers needs a second run, `komando host winrm exec @prod`.
`komando database postgres query @prod 'SELECT 1'` does the opposite: it
uses the one PostgreSQL database in `@prod` (a database command needs
exactly one) and skips the servers. `list`, `test`, `copy` and `status` take
a mixed target as it is. A target that picks nothing the command can use
is an error, not an empty result.

<!-- TODO(cut): the field and the exit code for skipped members wait on O-30. -->

## Groups, tags and labels

Set a label when you add or edit an entry. Put entries in a group with
`group`:

```bash
komando host ssh edit web1 --label dc=jkt
```

<!-- TODO(cut): the flags that set and clear tags and groups on `edit` (`--add`, `--remove`) wait on the leaf Options of the table (PR B). -->

Or manage a group for many entries at once:

```bash
komando group create prod 'web-*'            # make a group from everything a target picks
komando group edit prod --add web1,web2      # put entries in it
komando group list                           # every group and tag with its members
komando group show prod                      # the members of one group
komando group edit prod --remove web2        # take web2 out of prod
komando group remove old --dry-run           # remove the group itself
komando group remove old                     # more than 3 members: asks first
```

Typed alone, `komando group create` asks for the group, then what goes in
it.

`group remove` removes the group only; its members stay in your list.
Removing a group with more than 3 members asks first: at your terminal
komando asks `[y/N]`; an AI agent or a script adds `--yes` after a person
agrees ([Safety](safety.md)). At a terminal, `group remove` ends with the
way back: `Next: komando group list`.

## Limits

- An entry name uses letters, digits, `.`, `_` and `-`,
  starts with a letter or digit, and is at most 63 characters long.
- Group, tag and label names use the same letters, so every one can be
  written in a target.
- `all` cannot be a name, because as a target it means everything. A name
  may not be a type word or a provider word either (`host`, `ssh`).
- Every entry shares one list of names, and `Web1` and `web1` are the same
  name.
- A command like `database postgres query` needs exactly one entry of its
  provider in the target.

## Troubleshooting

| Error code | What it means | What to do |
|------------|---------------|------------|
| `TARGET_EMPTY` | the target matched nothing (exit 3) | `komando list` shows entries, groups and tags |
| `NO_MATCHING_TARGETS` | the target picked only things this command cannot use (exit 3) | the hint names the command for what it picked |
| `TARGET_NOT_FOUND` | no entry of that name (exit 3) | check the "did you mean", or `komando list` |
| `USAGE` | a command that needs exactly one entry got a target with several | name the one entry |
| `CONFIRM_REQUIRED` | `group remove` of a group with more than 3 members, from an AI agent or a script without `--yes` | check the members with `komando group show GROUP`, then add `--yes` after a person agrees |
