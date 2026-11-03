# Targets

Pick which servers and conns a command works on. [All features](README.md)

Most commands take a *target*. A target picks servers and conns (databases,
caches, storage) together:

| Write | Meaning |
|-------|---------|
| `web1` | one server or conn, by name |
| `web-*` | names starting with `web-` |
| `@prod` | everything in group `prod` |
| `tag:prod` | everything tagged `prod` |
| `label:dc=jkt` | everything with label `dc=jkt` |
| `kind:db` | every database (also `kind:host`, `kind:cache`, `kind:storage`, `kind:postgres`, ...) |
| `all` | everything |
| `@prod,!web3` | combine with `,` and leave out with `!` |
| `!web3` | everything except `web3` (same as `all,!web3`) |
| `root@1.2.3.4:22` | a one-off server not in your list (`1.2.3.4:22` uses your default user) |

Names, groups and tags match in any case (`WEB1` finds `web1` when there is
only one). A misspelled name, `@group` or `tag:` gets a "did you mean".

Each command uses what it can work with and says what it left out. For
example `komando exec @prod -- uptime` runs on the servers in `prod` and lists
the databases under "skipped"; `komando db query @prod "..."` does the
opposite. If a target picks nothing the command can use, the error says which
command to use instead.

Groups, tags and labels are set when adding or editing:
`komando host edit web1 --add-group prod --add-tag web --label dc=jkt` (or
`-g prod -t web`), or for many at once, `komando group add prod 'web-*'`.
Their names use letters, digits and `. _ -`, like server names, so every one
can be written in a target.

```bash
komando group list                 # every group and tag with its members
komando group list prod            # the members of one group
komando group rm prod web3         # take web3 out of prod
komando group rm old --dry-run     # delete a whole group: who would leave it
komando group rm old --yes         # (more than 3 members needs --yes)
```

See what a target picks, and check that all of it is reachable:

```bash
komando list @prod       # servers and conns in one list
komando test @prod       # can komando reach and log in to each one?
```
