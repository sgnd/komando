# Clusters (Kubernetes and Docker Swarm)

See and change what runs in Kubernetes and Docker Swarm with one set of
commands. You do not need `kubectl` or `docker` on your computer: komando
speaks to the cluster itself. [All docs](README.md)

## Check a cluster's health

```bash
komando import kubeconfig                  # one conn per kubeconfig context (see Add a cluster)
komando conn rename my-ctx-name prod-k8s   # give it a short name (import names it after the context)
komando cluster status prod-k8s            # version, nodes, and every problem
```

Typed alone at a terminal, `komando cluster status` asks which cluster,
with a list of yours to pick from.

```text
prod-k8s: version v1.30.4, 3 of 3 nodes ready
not healthy: 2 problems
OBJECT                 PROBLEM
pod/shop/api-7d9f-x2   api: CrashLoopBackOff
deployment/shop/api    1 of 3 replicas ready
```

`cluster status` lists each problem by name: pods that crash or cannot
start, deployments, StatefulSets and DaemonSets short of replicas, and
nodes under pressure (`MemoryPressure`). With none it says
`healthy: no problems found` (`healthy: true` in JSON). On Swarm it lists
nodes that are down or drained and services short of replicas, with the
error of each task that does not run.

The same commands work on Kubernetes and on Docker Swarm.

## Add a cluster

### Kubernetes

komando reads your kubeconfig (the login file `kubectl` uses, usually
`~/.kube/config`) and adds one conn per context (one cluster and user in
that file):

```bash
komando import kubeconfig --dry-run           # see what would be added
komando import kubeconfig                     # reads $KUBECONFIG, else ~/.kube/config
komando conn edit prod-k8s --via bastion      # API server on a private network? reach it like anything else
```

Typed alone at a terminal, `komando cluster add` asks whether it is
Kubernetes (then for your kubeconfig file) or Docker Swarm (then for a
manager's address).

How the login works:

- komando keeps each context's kubeconfig in the vault.
- It makes the EKS and GKE logins itself (`aws eks get-token`,
  `aws-iam-authenticator`, `gke-gcloud-auth-plugin`), so you do not need
  those programs.
- Any other login program the kubeconfig names runs on this computer, so
  an AI agent needs a person's yes (`--yes`) to import it, as with a
  server's `--proxy-command`.
- When that program is missing, cluster commands stop with `TOOL_MISSING`
  (exit 3) and the kubeconfig's own `installHint`. When it runs but cannot
  log in (it may want a person to sign in first), they stop with
  `LOGIN_FAILED` (exit 4).
- Once a person imported (or allowed) a kubeconfig, agents use the conn
  without asking. If the kubeconfig in the vault changes to another program
  or server (`secret set`), or reads its token from a local file
  (`tokenFile`), every agent command asks again, reads included, until a
  person imports it again.

komando checks the API server's certificate against the kubeconfig's CA.
A context with `insecure-skip-tls-verify` and no CA skips that check, as
kubectl does; the import names it in its notes, because its login goes
to whoever answers at that address. With a CA, the certificate is always
checked, even if `insecure-skip-tls-verify` is set too.

To add one cluster by hand, store its kubeconfig in the vault first, then
name it with `cluster add` (the same as `conn add`, but it refuses a URL
that is not a cluster):

```bash
komando secret set prod-kubeconfig < prod.kubeconfig
komando cluster add prod-k8s k8s://api.cluster.example:6443 --password-ref secret:prod-kubeconfig
```

### Docker Swarm

A Swarm is reached through a manager server: add the manager as a server
and give it the tag `swarm`, so a group or `all` picks it as a cluster too
(see [Many clusters at once](#many-clusters-at-once)):

```bash
komando host add swarm1 admin@10.0.0.10 --tag swarm
komando host edit swarm1 --add-tag swarm     # a manager already in your list
```

`komando cluster add` typed alone at a terminal adds the tag for you when
you answer Docker Swarm.

### Remove a cluster from komando

```bash
komando conn rm prod-k8s                 # komando forgets it; the cluster is not touched
komando secret rm prod-kubeconfig        # its kubeconfig, once nothing uses it
```

`conn rm` lists the vault secrets nothing uses any more
(`secrets_unused`). `cluster rm` is different: it deletes an object inside
the cluster.

## Name objects

Every command names objects the way kubectl does: `TYPE NAME` or
`TYPE/NAME` (`deployment api`, `deploy/api`, `deployment.apps/api`). If you
mistype a kind, the error suggests the one you probably meant.

- Name a namespace (see [Glossary](glossary.md)) with `--namespace`, or
  `-n` as in kubectl. Without it, komando uses the cluster's usual
  namespace: the one its kubeconfig context names, else `default`. Change
  it for good with `komando conn edit prod-k8s --option namespace=shop`.
- How many lines or objects to show is `--limit` (it has no short form in
  cluster commands). A number after `-n` (`-n 50`) is refused, with a
  hint: write `--limit 50`, or `--namespace=50` for a namespace named 50.
- `-A` (`--all-namespaces`) works on `list`, `events` and `helm list`. It
  cannot go with `--namespace`.
- Swarm kinds are `service` (`svc`), `task`, `node` and `stack`. Swarm
  has no namespaces, so `--namespace` is refused there.

## Look around

```bash
komando cluster status prod-k8s --namespace shop                # only the problems in one namespace
komando cluster list prod-k8s pods --namespace shop
komando cluster list prod-k8s deploy -A                         # every namespace
komando cluster list prod-k8s pods -l app=api                   # only objects with these labels
komando cluster describe prod-k8s deployment/api --namespace shop   # images, strategy, pods, events
komando cluster events prod-k8s --namespace shop --warnings     # what went wrong, oldest first
komando cluster events prod-k8s --for deployment/api --namespace shop
komando cluster get prod-k8s deploy/api --namespace shop        # the whole object (Secret values hidden)

komando cluster status swarm1                                   # a Swarm manager
komando cluster list swarm1 services                            # also: tasks, nodes, stacks
komando cluster describe swarm1 service/web                     # image, replicas, update state, task errors
```

Typed alone at a terminal, `komando cluster list` asks for the cluster,
then what to list (pods by default).

```text
$ komando cluster list prod-k8s deploy --namespace shop
NAME   READY   UP-TO-DATE   AVAILABLE   AGE
api    3/3     3            3           12d
web    2/2     2            2           40d
```

`cluster list` shows the useful columns for each kind: ready replicas,
restarts, ingress hosts, volume claims, job completions, cron schedules and
autoscaler targets. In text mode the tables look like kubectl's
(`NAME READY STATUS RESTARTS AGE NODE` for pods). In JSON the same rows are
under `data.items[]`, for Kubernetes and Swarm alike.

### Many clusters at once

`cluster status`, `cluster list`, `cluster events` and `cluster helm list`
take a selector that picks several clusters: a group, `kind:k8s`, a tag or
`all`. komando reads them at the same time and shows one block per
cluster. A server counts as a Swarm manager there only when it has the tag
`swarm` or is named in the selector; other servers are listed in
`meta.skipped`:

```bash
komando cluster status kind:k8s                  # health of every Kubernetes cluster
komando cluster events tag:prod --warnings -A    # what goes wrong anywhere in production
komando cluster list all nodes
```

In JSON each cluster is a row of `data.results[]` (`cluster`, `engine`,
`ok`, and its `data` or `error`), with `data.summary`. A cluster that
cannot be read fails alone: the others still show, and the command ends
with `PARTIAL_FAILURE`. One cluster gives the same output as always.
Commands that change a cluster (`apply`, `deploy`, `restart`, `scale`,
`rm`, `rollback`) and a rollout's `status` stay on one cluster.

### Helm releases (read-only)

komando reads the Helm releases stored in the cluster, without the `helm`
program. It only reads: install, upgrade and rollback stay with `helm`.

```bash
komando cluster helm list prod-k8s -A                                   # name, revision, status, chart, app version
komando cluster helm status prod-k8s shop-api --namespace shop          # deployed when, description, notes
komando cluster helm history prod-k8s shop-api --namespace shop
komando cluster helm values prod-k8s shop-api --namespace shop          # the values it was installed with
komando cluster helm values prod-k8s shop-api --namespace shop --all    # with the chart's defaults
```

`--revision N` shows an older revision in `status` and `values`. Helm keeps
releases as Secrets, so the kubeconfig's user needs to list Secrets in that
namespace (`K8S_FORBIDDEN` otherwise). For an AI agent, passwords and
tokens in the values show as `[hidden]`, as everywhere.

## Read logs

```bash
komando cluster logs prod-k8s api-7d9f-x2 --namespace shop --since 10m --limit 100   # one pod
komando cluster logs prod-k8s deploy/api --namespace shop -f                         # every pod of a workload, following
komando cluster logs prod-k8s -l app=api --namespace shop --limit 50                 # every pod with a label
komando cluster logs prod-k8s api-7d9f-x2 --namespace shop --previous                # the run before the last restart
komando cluster logs swarm1 service/web -f --timeout 1m                              # a Swarm service
```

Typed alone at a terminal, `komando cluster logs` asks for the cluster,
then the pod or workload.

```text
[api-7d9f-x2] GET /health 200 1ms
[api-7d9f-k4] GET /orders 500 32ms
```

- When several pods answer, each line starts with `[pod]`. JSON names the
  `object` and its `pods`.
- `-f` keeps reading new lines. Ctrl-C or `--timeout` ends it normally.
- `--since` takes a duration (`10m`, `2h`) or a time (`2026-01-02T10:00:00Z`).
- `--timestamps` starts each line with its time; `-c` picks a container.

## Deploy a new version, and roll back

```bash
komando cluster deploy prod-k8s deployment/api --image ghcr.io/acme/api:1.4.3 --namespace shop --wait
komando cluster status prod-k8s deployment/api --namespace shop --wait    # has it rolled out?
komando cluster history prod-k8s deployment/api --namespace shop          # revisions and their images
komando cluster rollback prod-k8s deployment/api --namespace shop --wait  # back to the previous one
komando cluster rollback prod-k8s deployment/api --revision 3 --namespace shop  # back to revision 3

komando cluster deploy swarm1 service/web --image nginx:1.27 --wait
komando cluster rollback swarm1 service/web --wait
```

Typed alone at a terminal, `komando cluster deploy` asks for the cluster,
the workload and the new image.

With several containers in a pod, name the one that gets the image with
`--container` (or `--image CONTAINER=IMAGE`).

`--wait` stays until every replica runs the new version. It stops with:

| Code | When |
|------|------|
| `ROLLOUT_FAILED` (exit 5) | the cluster gives up, or pods sit in `ImagePullBackOff`, `CrashLoopBackOff` and the like for 3 minutes |
| `ROLLOUT_TIMEOUT` (exit 7) | `--timeout` passed (default 5 minutes) |

Both name the stuck pods (or Swarm tasks), why they are stuck, and their
image. Run `cluster rollback` to go back.

`rollback` without `--revision` goes to the newest earlier revision with
different images. The revision it replaced (the broken one) is then
skipped, so rolling back twice does not bring it back. `--revision` picks
any revision: one that does not exist lists the ones that do, and the
current one changes nothing (`unchanged`). On Swarm, a rollback you start
is followed to its end, not reported as a failed update.

## Change the cluster

```bash
komando cluster apply prod-k8s --file app.yaml --dry-run       # the server checks it; nothing changes
komando cluster apply prod-k8s --file app.yaml                 # created / configured / unchanged per object
komando cluster restart prod-k8s deployment/api --namespace shop --wait
komando cluster scale prod-k8s deployment/api 3 --namespace shop --wait
komando cluster rm prod-k8s pod/api-7d9f-x2 --namespace shop

komando cluster apply swarm1 --file compose.yml --stack shop --dry-run   # checked like docker stack config
komando cluster apply swarm1 --file compose.yml --stack shop
komando cluster scale swarm1 service/web 4
```

- `apply` first sends the whole file to the server as a dry run. If the
  cluster refuses one object (a typo, an unknown field or kind), it stops
  there and nothing in the file is applied (`K8S_INVALID`, "nothing was
  applied: configmap/bad: ...").
- `apply` uses server-side apply as `komando`. A field another tool owns
  (an autoscaler's replicas, a `kubectl edit`) stops it with `K8S_CONFLICT`,
  which names that tool and the fields, and nothing is applied. Leave those
  fields out of the file, or add `--force-conflicts` to take them over (as
  `kubectl apply --server-side --force-conflicts` does). It is still a
  change: a protected cluster needs a person's yes, as without it.
- `apply --dry-run` shows for each object whether it would be created,
  changed or stay the same, with a diff. Secret values never show: a changed
  value reads `(hidden, changed)`. Objects in a namespace that the same file
  creates are reported as created too. `--file -` reads from stdin.
- An object whose namespace in the file differs from `--namespace` is
  refused, as kubectl does.
- `scale` reports `previous_replicas` (or `unchanged`).
- A protected cluster needs a person's yes before any change.
- Scaling to 0 and `rm` stop things. At your terminal komando asks you
  first: type the object's name (`Type the name api-7d9f-x2 to continue`);
  any other answer, the cluster's name too, changes nothing. An AI agent or
  a script adds `--allow-dangerous` after a person agrees. See
  [Safety](safety.md#what-needs-a-yes).

## Work inside a pod

```bash
komando cluster exec prod-k8s deploy/api --namespace shop --read-only -- cat /app/config.yml
komando cluster exec prod-k8s api-7d9f-x2 -c api --namespace shop -- php artisan cache:clear
komando cluster forward prod-k8s svc/api 8080:80 --namespace shop   # 127.0.0.1:8080 until Ctrl-C
komando cluster shell prod-k8s deploy/api --namespace shop          # interactive, for people
```

- `cluster exec` runs one command (not interactive). The
  dangerous-command filter checks it, as with `exec` on servers.
  `--read-only` says it only looks, checked as for `exec`: a command that
  clearly changes something is refused (`READ_ONLY_VIOLATION`), and a
  protected cluster skips `--yes` only for commands komando knows read
  (`cat`, `ls`, `printenv` ...; see [Commands](commands.md#protected-servers-and---read-only)).
- `cluster forward` makes a pod or service port reachable on this
  computer only (127.0.0.1). For a service, the service port is forwarded to
  the pod port behind it. Ctrl-C or `--timeout` ends it normally. What goes
  through it skips komando's checks, so a protected cluster asks first
  (`--yes`), and the audit log records the forward.
- `cluster shell` opens a terminal in the pod (bash, else sh) for a
  person, and asks first on a protected cluster. Agents get
  `NEEDS_TERMINAL` and use `cluster exec` instead.
- komando speaks Kubernetes' exec and port-forward protocols itself:
  WebSocket, and SPDY on clusters older than Kubernetes 1.30, as kubectl
  does. A pod or service that does not exist is "not found" (exit 3).

## Anything else kubectl or docker can do

```bash
komando cluster run prod-k8s -- get pods -A -o wide
komando cluster run prod-k8s --write -- rollout undo deployment/api -n shop
komando cluster run swarm1 -- service ps web
```

On Kubernetes, `cluster run` is komando's own kubectl. It understands kubectl
commands and prints what kubectl prints, through the conn's `--via` path,
with no kubectl installed. On Swarm the command goes to docker on the
manager. The words after `--` are kubectl's (or docker's), so `-n` there
is kubectl's namespace flag.

- It only reads unless you add `--write`. Delete, drain, scaling to 0 and
  similar also need `--allow-dangerous`.
- `--dry-run` sends a change to the server as a server-side dry run
  (`apply`, `create`, `delete`, `scale`, `patch`, ...). A command the server
  cannot dry-run (`exec`, `cp`, `create token`, `config view`, `get` of
  Secret values for a person) is only shown, not run.
- For AI agents, Secret values and env values named like secrets
  (`DB_PASSWORD`) show as hidden in `get` output, as in `cluster get`, so
  `get secret -o yaml` is a read for them. `apply`, `create` and `replace`
  refuse a file that still holds a hidden value (`HIDDEN_VALUE`): change
  one field with `set image` or `patch` instead.
- For AI agents, files of this computer that would go to the cluster
  (`-f`, `--from-file`, `cp` to a pod) may not be secrets by their name
  (`.env`, keys) unless the person allows `--reveal`, and never komando's
  own folder (`SENSITIVE_FILE`).
- `delete -f FILE` deletes each object in the namespace its file names,
  and refuses a `-n` that says otherwise. An empty name is refused.
- `cp POD:SRC DST` writes only inside DST, never into a `.git` folder, and
  skips links and devices, like kubectl cp. It brings at most 512 MiB
  (`FILE_TOO_LARGE`): komando checks every name before it writes any, so
  it holds the copy in memory. For an AI agent it copies as `download`
  does: a file that is a secret by its name (`.env`, a private key) is
  refused (`SENSITIVE_FILE`), a text file is written with its secret
  values `[hidden]`, and a binary or larger file that holds a vault value
  is refused; nothing is written when any file is refused.
- On Swarm, `docker run`, `create` and `service create|update` that give a
  container the server (`--privileged`, `--cap-add`, devices, the host's
  network or processes, `--volumes-from`, a bind of `/`, the docker socket,
  system or credential folders) also need `--allow-dangerous`, as do
  `plugin install|create|enable|set` and a `volume create` that is a host
  folder.
- It stops at `--timeout` (default 5 minutes). A watch (`get -w`) or follow
  (`logs -f`) that ends there ends normally. `logs -f` prints lines as they
  come and follows all selected pods at once (`--max-log-requests`, 5 by
  default).
- Sessions have their own commands: `cluster forward` (port-forward) and
  `cluster shell` (`exec -it`).
- A command it does not know gets a "did you mean". The commands it knows
  are in [Reference](#reference).

## Limits

- `cluster status` on a cluster with more than 20000 objects of one kind
  reads only those, says `truncated: true`, and `healthy` is `null` unless
  it found a problem. Narrow it with `--namespace`.
- `cluster run` knows kubectl's own commands, not kubectl plugins (krew).
  `edit` is refused (get the YAML, change it, then `apply -f`), and of
  `config` only `current-context` and `get-contexts` work.
- On Swarm, komando cannot see inside a compose or stack file on the
  server, so `cluster run swarm1 -- stack deploy -c FILE` and `compose up`
  are rated by their flags only.
- Helm: komando reads releases only; install, upgrade and rollback stay
  with `helm`.

## Troubleshooting

| Code | What it means | What to do |
|------|---------------|------------|
| `TOOL_MISSING` (exit 3) | the login program the kubeconfig names is not installed | install it; the error shows the kubeconfig's `installHint` |
| `LOGIN_FAILED` (exit 4) | the login program ran but could not log in | a person signs in with that program, then run it again |
| `K8S_UNREACHABLE` (exit 4) | the API server did not answer | `komando test prod-k8s`, and check its `--via` path or VPN |
| `K8S_FORBIDDEN` (exit 4) | the kubeconfig's user may not do this (Helm: list Secrets) | give the user the right, or name one namespace with `--namespace` |
| `K8S_INVALID` (exit 2) | the cluster refused the request or the file as written | read the cluster's words in the message; fix the YAML or the `-l` selector |
| `K8S_NOT_FOUND` (exit 3) | the workload has no running pod to read or run in | `komando cluster list prod-k8s pods --namespace shop` |
| `NOT_SWARM_MANAGER` (exit 3) | the server is not a Swarm manager | name a manager; `komando exec swarm1 --read-only -- docker node ls` shows whether it is one |
| `ROLLOUT_FAILED` (exit 5), `ROLLOUT_TIMEOUT` (exit 7) | the new version did not come up | `komando cluster describe prod-k8s deployment/api --namespace shop`, then `cluster rollback` |
| `HIDDEN_VALUE` (exit 2) | the file holds a value komando hid from an AI agent | leave hidden entries out, or change one field with `cluster run ... --write -- set image` or `patch` |
| `NEEDS_TERMINAL` (exit 2) | `cluster shell` needs a person | agents and scripts use `cluster exec` |
| `PARTIAL_FAILURE` (exit 1) | some clusters of a selector failed | read each cluster's error in the output |

## Reference

Kubectl commands `cluster run` knows:

| Group | Commands |
|-------|----------|
| Read | `get` (server tables, `-o wide\|name\|json\|yaml\|jsonpath=...\|custom-columns=...`, `-w`, `-l`, `-A`), `describe`, `logs`, `events`, `top`, `explain`, `version`, `api-resources`, `api-versions`, `cluster-info`, `auth can-i`, `auth whoami`, `wait` |
| Roll out | `rollout status\|history\|undo\|restart\|pause\|resume`, `set image`, `scale` |
| Change | `apply`, `diff`, `create` (`-f`, namespace, configmap, secret, deployment, job, cronjob, service, role, rolebinding, token), `replace`, `delete`, `patch`, `label`, `annotate` |
| Nodes | `cordon`, `uncordon`, `drain`, `taint` |
| Pods | `run`, `exec`, `cp`, `debug` |
| Other | `certificate approve\|deny`, `config` |
