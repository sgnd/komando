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
| `root@1.2.3.4:22` | a one-off server not in your list |

Each command uses what it can work with and says what it left out. For
example `komando exec @prod -- uptime` runs on the servers in `prod` and lists
the databases under "skipped"; `komando db query @prod "..."` does the
opposite. If a target picks nothing the command can use, the error says which
command to use instead.

Groups, tags and labels are set when adding or editing:
`komando host edit web1 --add-group prod --add-tag web --label dc=jkt`, or
for many at once, `komando group add prod 'web-*'`.

See what a target picks, and check that all of it is reachable:

```bash
komando list @prod       # servers and conns in one list
komando test @prod       # can komando reach and log in to each one?
```
