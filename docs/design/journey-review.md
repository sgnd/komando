# komando menu redesign: synthesis and completeness check

Status: **replaced (2026-11-12).** This was the plan for the menu
redesign, shipped in v0.11.0. The owner then chose commands instead of a
menu (vision.md decision 5): the menu is gone, and a typed command asks a
person for what is missing; see
[docs/features/commands.md](../features/commands.md#at-your-terminal-komando-asks-for-what-is-missing).
Kept for the history of the questions it settled.
Two points shipped differently from the plan: the main menu footer is
`↑↓ move · Enter or 1-N choose · ? help · q quit`, with no Esc and no
filter there (typing filters only in the lists of servers and services), and the production question of item 15
is one of the basic questions again, so its default (Yes, protect it)
applies.

The function names and line numbers below are from the code before the
redesign. Several of those functions no longer exist.

## 1. New main menu: pick a thing first, then what to do with it

### Layout (no more than 7 fixed rows; the list of your things scrolls and can be filtered by typing)

**Header:** `komando  3 servers · 2 databases · 1 VPN (office connected)`. Never use "conn". Show the version only under Settings and help.

**First run (nothing added).** Title: `Welcome to komando. Start by adding a server.`
1. `Add a server`: "Its address and the user you log in with"
2. `Bring in my SSH servers`: "12 servers found in ~/.ssh/config". Shown only when N > 0.
3. `Set up my AI agent`: "Lets Claude, Codex, Cursor or Gemini use komando safely"
4. `Settings and help`

**With items.** Rows in this fixed order; rows never move or disappear to make room:
1. `Servers`: "web1, web2, db1 and 4 more"
2. `Databases and services`: "shop-db, cache1, orders-queue". This covers db, cache, queue, storage, cluster and registry, grouped under small labels.
3. `VPNs`: "office connected · lab not connected". Always shown. With no VPN it opens Add a VPN.
4. `Add something`: "A server, a database, a VPN or another service"
5. `Check everything`: "See if every server and service answers" (`test all`, then a short doctor summary)
6. `History and undo`: "What komando and your AI agent changed, and how to put it back"
7. `Settings and help`: "AI agent, saved passwords, production servers, blocked commands, keys"

Conditional rows, inserted above row 4 only while they apply:
- `Running now (N)`: "Jobs, tunnels, VPNs and logins komando left running" (`komando status`)
- `Log in (N need a code)`: shown while a host's login method asks for a two-factor code

When fewer than 15 items exist, rows 1-3 may list the items themselves instead of the group rows. Typing filters across every item, and number keys pick 1-9.

**Footer, the same on every screen:** `Enter choose · Esc back · type to filter · ? help · q quit`. Esc always goes back one step. q always leaves, and asks "Leave komando? Your answers are lost. y/n" when a form has answers.

**`?`** explains the current screen in one paragraph, lists the keys, and ends with "For scripts and AI agents: komando --help".

### Per-kind action lists (picking an item shows "web1 (Ubuntu 22.04, 10.0.0.5): what do you want to do?")

**Server:** Open a shell · Check health (facts + health recipe) · Read logs · Services (start, stop, restart) · Run a command (asks "Keep it running if the connection drops?" Yes builds `job start`) · Files (look, edit, copy, put a backup back) · Docker containers · Updates and packages · Reboot · Change this server (address, user, "Ask me before changes" = protected, group, rename) · Remove from list · More… (cron, users, network checks, run a script, sync a folder, tunnel, SSL certificates, SSH keys, saved commands/recipes)

**Group (`@web`, shown above the servers in the Servers list):** same as Server but run on all members, plus Edit members.

**Database:** Look around (info, tables, sizes) · Run a query (read only) · Open a SQL shell · Back up to a file · Load a backup (offers a backup first) · Who is running what (activity, locks, stop a query) · Users and rights · Test · Change or remove. Tasks the engine cannot do are hidden (for example no dump on BigQuery or Snowflake).

**Cache:** Summary · Find keys · Show a key · Set a key · Delete keys · Send a command · Test · Change or remove

**Queue:** Summary · List topics or queues · Look at messages · Is a reader behind? · Send a message · Create · Empty or delete (shows the message count and asks first) · Change or remove

**File storage:** See files · Download · Upload · Share a link · More… (show a text file, delete) · Change or remove

**Cluster (Kubernetes or Swarm; Swarm managers listed here too):** Is it healthy? · What is running? · Show logs · Roll out a new image · Undo the last rollout · Restart an app · Change the number of copies · More… (events, describe, exec, shell, forward, apply, helm, kubectl/docker for experts, delete) · Change or remove

**Registry:** See images and tags · Image details · Copy an image · More… (clean up old images, delete) · Change or remove

**VPN:** Connect, or Disconnect when connected (asks "Disconnect office? 3 servers behind it stop answering.") · Test · Change login or test address · Remove (shows the vault-key cleanup line)

**Add something:** Server · Database · VPN ("Which VPN app does your company use?", app names first) · Something else (Cache, Message queue, File storage: a cloud bucket or a file server, Cluster: Kubernetes or Docker Swarm, Container registry) · Bring in from SSH config / .pgpass / my.cnf / .env (`import`). After a successful add, the cursor lands on the new item with the note "Added web1. Pick it to see what you can do."

**History and undo:** the audit as one sentence per entry. "Put it back" appears where a backup or a previous value exists (fs backup, host edit, cluster rollback).

**Settings and help:** AI agent (install, reinstall, remove) · Saved passwords (secret list/set/rm) · Production servers (protect or unprotect) · Blocked commands (check, add, remove) · SSH keys · Check my setup (doctor) · Export my list · Settings (config) · Update komando · Version · Keys and help

### Implementation changes

- **`menu.go:59-72`:** delete `allAction`, `shellAction`, `factsAction`, `dbAction`, `testAction`, `listAction` and `doctorAction` as main rows. Add kind rows (`serversAction`, `servicesAction`, `vpnsAction`), plus `addAction` (renamed "Add something"), `checkAction` (args `test all`), `historyAction` (replaces the dead `auditAction`), `settingsAction`, `statusAction` and `loginAction`.
- **`menuMainActions` (472-511):** rewrite to a fixed order. Remove the `len(acts)+1+len(last) <= 9` rule and the `last` slice.
- **`menuPickCommand` (145-200):** after `menuTargets` returns an item, call a new `menuItemActions(st, kind, name) *menuList`. It builds the rows above and maps each row to `formCmdSpec(cobraCmd)` with the item name pre-filled as the first argument. This reuses `formGuidedOrAll`'s guided path, skipping its choice screen (see 2.9). Remove the `menuVpnUp` silent toggle at :194-196.
- **`menuTargets` (524):** add group rows (`@name (N servers)`) and Swarm hosts to the cluster kind. `menuConnRows` already splits by family.
- **`form_cmd.go`:** delete `formAllFeatures` and `formAreaCommands`. Keep `formAreas`/`formCommands` only to drive a test proving every listed command is reachable through some item action, More…, Add or Settings. Each cobra command gets a new `menuHome` entry that names where it lives in the menu.
- **`menuHelpFor`/`menuHelp` (425-470):** make them context help per screen.
- **`menuHeader` (697):** the new wording above.
- **`menu_test.go`:** add a reachability test (every action var used; every non-agent command has a `menuHome`), and replace the README menu-block drift test.

## 2. Fixes outside the menu, ranked and deduplicated

**High**
1. **Undo for file edits.** Add `komando fs restore HOST PATH` (puts PATH.bak back, shows a diff with `--dry-run`). In `fs replace`/`fs write --backup`, print "Changed /etc/nginx/nginx.conf on web1. To undo: komando fs restore web1 /etc/nginx/nginx.conf". Show the diff on the form's review screen. (Files: `internal/cli/fs*.go`, `form_hints_files.go:21`.)
2. **Text-mode errors lead with meaning** (`internal/out/out.go:342,377`). Change to "Stopped: web1 is production, so komando asks first. Nothing was changed." followed by a hint, with "(code PROTECTED_HOST, exit 6)" at the end. Keep JSON unchanged. A "no" from the person (`root.go:103-106`) prints "Cancelled. Nothing was changed on web1." with no `error` prefix.
3. **Hints written for the person** (`common.go:283-298,340-342,551`, `errcodes.go:155,156,192,193`). Put the agent wording only in `approvalHint` (`approval.go:282`). Example for a person: "web1 is marked as production. Run it again in a terminal to answer the question, or add --yes in a script if you are sure."
4. **Not-found errors** (HOST_NOT_FOUND/CONN_NOT_FOUND). Scope them to the command family and suggest a near match: `No database named "nosuch". Did you mean prod-db? Your databases: prod-db, shop-db.` With none: "You have no database yet: Add in the menu, or komando db add."
5. **Remove "conn" from user-facing text** (`db.go`, `cache.go`, `queue.go`, `storage`, `test`, `list` and root help Long/Short, `approval.go:143-158`). Use "database", "cache", "service". Add `komando db add`, `cache add`, `queue add`, `storage add`, `cluster add` and `registry add` as aliases of `conn add` that open the guided form when run with no args.
6. **Destructive actions offer a way back.** `db restore` asks "Back up the database as it is now first?" (default yes; `form_hints_db.go:106`). `queue purge`/`rm` show the message count; `cache rm` shows the keys; `storage rm`/`cluster rm`/`scale 0`/`registry rm|prune` dry-run on the review screen and say "cannot be undone" (`form_hints_queue.go:46-49`, `form_hints_data.go:32`, `form_storage.go:688`, `form_cluster.go:195-200`). After `cluster deploy`, print the rollback command (`clusterdeploy.go`).
7. **After the add, a failed test needs a way forward** (form finish path in `form_kinds.go`). Show "web1 did not answer: <reason>" with the choices Change the answers (prefilled, runs host edit) / Keep it anyway / Remove it.
8. **Root `--help`.** Put a "First steps" block on top (`komando`, `komando host add web1 ubuntu@203.0.113.10`, `komando test web1`, `komando guide install`). Move the JSON and exit-code text below the command list. Split the flags into "Common" and "Safety overrides (ask a person first)" with `--yes`, `--allow-dangerous` and `--reveal` listed last (`root.go`).
9. **The guided form opens directly.** Drop the "Step by step / Every option" screen (`form_cmd.go:661 formGuidedOrAll`) and add a "More options" row on the review screen.
10. **Swarm missing from the cluster pick** (`form_cluster.go:139`). List Swarm manager hosts there.
11. **Login gaps** (`login.go:23-40`). `login gcp`/`login azure` should say "Google Cloud login is not built yet. For now: komando secret set gcp-key". Plain help: "Type the password and code once; for 8 hours your commands and AI agent reuse it."
12. **Passwords inside forms** (`form_hints_access.go:29,57`, `form_registry.go:33,101`). Offer Type it now (saved as web1-pass) / Use a saved password (picker) / None. Use the name "saved password" everywhere; never "vault" or "secret:NAME" in forms.

**Medium**
13. **`vpn status -o text` USED BY column.** Show "48 (app-01, app-02, +46)".
14. **VPN add.** Ask "Which VPN app does your company use?" first, and keep protocols and proxies under "Something else" (`form_vpn.go:23-39`). Rename "Phone code" to "Extra sign-in step" with clear choices (`form_vpn.go:183-188`). Give the OpenVPN error its own hint (`--config kantor.ovpn`). Group `vpn add --help` flags by kind. In `vpnCheckQ`, say it is optional.
15. **Server form order** (`form_kinds.go:242-283`). Name, Address, User, then OS. Windows questions come only after OS=Windows. "Reached" becomes "Through another server (a jump host)?" Production, group, notes and the one-time code go under "More options". Drop the docs path from `form_winserver.go:44`.
16. **Read-only question** (`form_hints_servers.go:20`). Ask "Will this command change anything on the server?" with the default "Yes, or not sure". Drop "lets it run on production without asking".
17. **docker exec.** One question, "What command should run inside the container?", split into words in code.
18. **Cluster kind and workload** become picks, with live `cluster ls` (`form_cluster.go:166-169`). `cluster run` accepts and strips a leading `kubectl`/`docker` and moves to More… (`:248`).
19. **Registry copy** asks from / image / to / new name (`form_registry.go:445`).
20. **Storage Add** asks "A cloud bucket or a file server?" first. Use one name, "Windows share (SMB)". `storage link` is classified as a change (`kinds.go:286`).
21. **Kubeconfig missing** (`form_cluster.go:21-26`). Give per-cloud steps, and do not offer `~/.kube/config` when it does not exist.
22. **An empty pick is a dead end** (`form_storage.go:671`, `form_registry.go:432`). Show a single row "Add a file storage now" that returns to the task afterwards.
23. **Help texts lead with the task.** `secret --help` (crypto details last), `db query --help` (2 lines, engine notes after Usage), `db dump` ("Saves a copy to a file on this computer"; default file `<conn>-<date>.sql.gz`; print the restore line), `exec --help` (say komando asks at a terminal; flags are for scripts; replace the psql example with `df -h`), global `-y` ("answer yes in advance, for scripts"), `guide install --help` (restart the agent, then Codex /hooks).
24. **Policy.** Rename `policy allow` to `policy rm` (keep a hidden alias). "Block a command" takes an example command. In text mode `policy check` prints one line and exits 0. The form example must really be blocked (`form_hints_inventory.go:260-264`).
25. **Protected wording.** One sentence everywhere: "Production: komando asks you before every change, and an AI agent needs your yes in a window" (`form_kinds.go:95-99`, `host edit --protected` help).
26. **Approval window** (`approval.go:143-158`). "Claude wants to change web1 (production): <cmd>. Allow this once?" with the rule details in a small last line.
27. **`komando guide`.** Open with a short rules section, add `guide <topic>`, keep the full text under `--all`. `doctor`/`guide` warn when there is no TTY and no agent variable ("set KOMANDO_AGENT=1"). Move `export KOMANDO_AGENT=1` into the AGENTS.md setup block.
28. **`host add --help` / `conn add --help`.** Basic flags first, then Advanced. Shorten the `--password-ref` text.
29. **Docs.** Remove every "All features" mention (README.md:79-91,131-137; docs/features/README.md:14-15). Keep only steps 1-4 in "Your first five minutes" (move vault-key and keychain to servers.md). The README prompt lists `--reveal` too. features/README says "Connecting an AI agent? Run komando guide install".

**Low**
30. Remove the duplicate Pub/Sub sentence in `form_hints_queue.go:22-23`.
31. Use the same labels in Add, help and CLI: Databases / Caches (Redis, Valkey, Memcached) / Queues / File storage / Clusters / Images (registries).
32. Give PROTECTED_TARGET its own message ("protected database db-main"). Replace the circular KEY_PASSPHRASE_REQUIRED and NO_PASSPHRASE hints with real steps (`errcodes.go:109,132,155-156`).
33. `cert check` row becomes "Check SSL certificates", with "Warns 14 days before. Empty keeps that."

## 3. Gaps the reviewers missed (from `komando --help`)

- **`status`** ("What komando left running: VPNs, logins, tunnels, jobs") is the best answer to "what is still on?" No reviewer placed it. It becomes the conditional "Running now (N)" row, with Stop on each entry: `vpn down`, `logout`, tunnel stop, `job kill`.
- **`tunnel`** (-L/-R/-D port forwards) has no beginner path. Under Server > More…: "Reach a port on this server from my computer", asking "Which port on the server? Which port here?". Stop it from Running now.
- **`sync`** (one-way folder copy) and **`script`** (run a local script remotely) are not covered. Put them under Server > Files ("Copy a folder to it") and More… ("Run a script from this computer"). Both dry-run first.
- **`recipe`** (health, disk, certs, your own) is used by "Check health" but saved recipes have no home. Add a Server > More… row "My saved commands" (run, save the last command as a recipe).
- **`key`** (generate, deploy) is missing from the server form. When the login method is a password, offer "Make an SSH key and put it on web1 (no password next time)". Also under Settings > SSH keys.
- **`import`** of .pgpass, my.cnf and .env: reviewers only covered ssh-config. Show it under Add something > "Bring in what I already have", with a preview list and checkboxes.
- **`export`**, **`rename`** (bulk), **`group`** management, **`config`**, **`update`** and **`version`**: none had a menu home. Settings and help gets Export my list, Settings, Update komando and Version. Rename goes under Change this server, and bulk rename goes under the Servers list's "Rename several". Group create and membership go under "Save these as a group" plus Group > Edit members.
- **`logs`**, **`svc`**, **`pkg`**, **`cron`**, **`user`**, **`net`** and **`reboot`** are mapped above (Server actions and More…). `reboot` needs a confirm screen: "Reboot web1? It will be away for about a minute; komando waits until it answers."
- **`ssh-gate`**, **`prompt`**, **`completion`**, **`schema`** and **`guide`** are script, agent or setup tools. Keep them CLI-only and list them in `?`: "For scripts and AI agents: komando --help". Exclude them from the reachability test with an explicit `menuHome: "cli-only"`.
- **`logout`** and the list of kept logins are reachable only via the Log in row and Running now. Make sure both exist.
- **`host trust`** (the host key) after HOSTKEY_MISMATCH: the menu must never offer to "fix" it. Show "web1's identity changed. This can be an attack. Ask whoever runs web1 before trusting it." with no action row, in line with AGENTS.md rule 8.
- **`list`** stops being a menu row (the menu is now the list). Keep the command for the CLI.
