# Clusters (Kubernetes and Docker Swarm)

See and change what runs in Kubernetes and Docker Swarm with one set of
commands. [All features](README.md)

## Quick start

```bash
komando import kubeconfig                                  # one conn per kubeconfig context
komando cluster status prod                                # version, nodes, and every problem
komando cluster ls prod pods --namespace shop              # what runs
komando cluster logs prod deploy/api --namespace shop -f   # follow the logs
komando cluster deploy prod deploy/api --image ghcr.io/acme/api:1.4.3 --namespace shop --wait
komando cluster rollback prod deploy/api --namespace shop --wait
```

The same commands work on Kubernetes and on Docker Swarm. You do not need
`kubectl` or `docker` on your computer: komando speaks to the cluster itself.

## Add a cluster

**Kubernetes.** komando reads your kubeconfig (the login file `kubectl`
uses, usually `~/.kube/config`) and adds one conn per context (one cluster
and user in that file):

```bash
komando import kubeconfig --dry-run        # see what would be added
komando import kubeconfig                  # reads ~/.kube/config
komando conn edit prod --via bastion       # API server on a private network? reach it like anything else
```

The kubeconfig of each context is stored in the vault. komando makes the
EKS and GKE logins itself (`aws eks get-token`, `aws-iam-authenticator`,
`gke-gcloud-auth-plugin`), so you do not need those programs. Other
credential plugins run as the kubeconfig says: they are programs on this
computer, so an AI agent needs a person's yes (`--yes`) to import such a
kubeconfig, as with a host's `--proxy-command`. A kubeconfig a person
imported (or allowed) is trusted for that program and server: agents then
use the conn without asking. If the kubeconfig in the vault changes to
another program or server (for example with `secret set`), every agent
command asks again, reads included, until a person imports it again. The
same goes for a kubeconfig that reads its token from a local file
(`tokenFile`).

**Docker Swarm.** Nothing to add: use a manager server as the target.

## Name objects

Every command names objects the way kubectl does: `TYPE NAME` or
`TYPE/NAME` (`deployment api`, `deploy/api`, `deployment.apps/api`). If you
mistype a kind, the error suggests the one you probably meant.

- **Namespaces** (see [Glossary](glossary.md)) use `--namespace`. komando keeps `-n` for "how many"
  (`--limit`); if you write `-n shop`, the error tells you the right flag.
  `-A` (`--all-namespaces`) works on `ls` and `events`.
- **Swarm** kinds are `service` (`svc`), `task`, `node` and `stack`. Swarm
  has no namespaces, so `--namespace` is refused there.

## Check health and look around

```bash
komando cluster status prod                                     # version, nodes, every problem it finds
komando cluster status prod --namespace shop                    # only the problems in one namespace
komando cluster ls prod pods --namespace shop
komando cluster ls prod deploy -A                               # every namespace
komando cluster ls prod pods -l app=api                         # only objects with these labels
komando cluster describe prod deployment/api --namespace shop   # images, strategy, pods, events
komando cluster events prod --namespace shop --warnings         # what went wrong, oldest first
komando cluster events prod --for deployment/api --namespace shop
komando cluster get prod deploy api --namespace shop            # the whole object (Secret values hidden)

komando cluster status swarm1                                   # a Swarm manager
komando cluster ls swarm1 services                              # also: tasks, nodes, stacks
komando cluster describe swarm1 service/web                     # image, replicas, update state, task errors
```

**`cluster status`** lists each problem by name, for example
`pod/shop/api-7d9f-x2: api: CrashLoopBackOff`,
`deployment/shop/api: 1 of 3 replicas ready`, or a node under
`MemoryPressure`. `healthy` is true when there are none. On Swarm it lists
nodes that are down or drained and services short of replicas, with the
error of each task that does not run. A server that is not a Swarm manager
says so (`NOT_SWARM_MANAGER`, exit 3).

**`cluster ls`** shows the useful columns for each kind: ready replicas,
restarts, ingress hosts, volume claims, job completions, cron schedules and
autoscaler targets. In text mode the tables look like kubectl's
(`NAME READY UP-TO-DATE AVAILABLE AGE` for deployments,
`NAME READY STATUS RESTARTS AGE NODE` for pods). In JSON the same rows are
under `data.items[]`, for Kubernetes and Swarm alike.

### Many clusters at once

`cluster status`, `cluster ls`, `cluster events` and `cluster helm ls` take
a selector that picks several clusters: a group, `kind:k8s`, a tag or `all`.
komando reads them at the same time and shows one block per cluster:

```bash
komando group add prod prod-eu,prod-us,prod-ap
komando cluster status @prod                     # health of every production cluster
komando cluster events @prod --warnings -A       # what goes wrong anywhere
komando cluster ls @prod nodes
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
komando cluster helm ls prod -A                             # name, revision, status, chart, app version
komando cluster helm status prod shop-api --namespace shop  # deployed when, description, notes
komando cluster helm history prod shop-api --namespace shop
komando cluster helm values prod shop-api --namespace shop        # the values it was installed with
komando cluster helm values prod shop-api --namespace shop --all  # with the chart's defaults
```

`--revision N` shows an older revision in `status` and `values`. Helm keeps
releases as Secrets, so the kubeconfig's user needs to list Secrets in that
namespace (`K8S_FORBIDDEN` otherwise). For an AI agent, passwords and
tokens in the values show as `[hidden]`, as everywhere.

## Read logs

```bash
komando cluster logs prod api-7d9f-x2 --namespace shop --since 10m -n 100   # one pod
komando cluster logs prod deploy/api --namespace shop -f                    # every pod of a workload, following
komando cluster logs prod -l app=api --namespace shop -n 50                 # every pod with a label
komando cluster logs prod api-7d9f-x2 --namespace shop --previous           # the run before the last restart
komando cluster logs swarm1 service/web -f --timeout 1m                     # a Swarm service
```

- When several pods answer, each line starts with `[pod]`. JSON names the
  `object` and its `pods`.
- `-f` keeps reading new lines. Ctrl-C or `--timeout` ends it normally.
- `--since` takes a duration (`10m`, `2h`) or a time (`2026-01-02T10:00:00Z`).
- `--timestamps` starts each line with its time; `-c` picks a container.

## Deploy a new version, and roll back

```bash
komando cluster deploy prod deployment/api --image ghcr.io/acme/api:1.4.3 --namespace shop --wait
komando cluster status prod deployment/api --namespace shop --wait    # has it rolled out?
komando cluster history prod deployment/api --namespace shop          # revisions and their images
komando cluster rollback prod deployment/api --namespace shop --wait  # back to the previous one
komando cluster rollback prod deployment/api --to 3 --namespace shop  # back to revision 3

komando cluster deploy swarm1 service/web --image nginx:1.27 --wait
komando cluster rollback swarm1 service/web --wait
```

With several containers in a pod, name the one that gets the image with
`--container` (or `--image CONTAINER=IMAGE`).

**`--wait`** stays until every replica runs the new version. It stops with:

| Code | When |
|------|------|
| `ROLLOUT_FAILED` (exit 5) | the cluster gives up, or pods sit in `ImagePullBackOff`, `CrashLoopBackOff` and the like for 3 minutes |
| `ROLLOUT_TIMEOUT` (exit 7) | `--timeout` passed (default 5 minutes) |

Both name the stuck pods (or Swarm tasks), why they are stuck, and their
image. Run `cluster rollback` to go back.

**`rollback`** without `--to` goes to the newest earlier revision with
different images. The revision it replaced (the broken one) is then
skipped, so rolling back twice does not bring it back. Pick any revision
with `--to`: a revision that does not exist lists the ones that do, and the
current one changes nothing (`unchanged`). On Swarm, a rollback you start is
followed to its end, not reported as a failed update.

## Change the cluster

```bash
komando cluster apply prod --file app.yaml --dry-run       # the server checks it; nothing changes
komando cluster apply prod --file app.yaml                 # created / configured / unchanged per object
komando cluster restart prod deployment/api --namespace shop --wait
komando cluster scale prod deployment/api 3 --namespace shop --wait
komando cluster rm prod pod api-7d9f-x2 --namespace shop --allow-dangerous

komando cluster apply swarm1 --file compose.yml --stack shop --dry-run   # checked like docker stack config
komando cluster apply swarm1 --file compose.yml --stack shop
komando cluster scale swarm1 service/web 4
```

- **`apply --dry-run`** shows for each object whether it would be created,
  changed or stay the same, with a diff. Secret values never show: a changed
  value reads `(hidden, changed)`. Objects in a namespace that the same file
  creates are reported as created too. `--file -` reads from stdin.
- An object whose namespace in the file differs from `--namespace` is
  refused, as kubectl does.
- **`scale`** reports `previous_replicas` (or `unchanged`).
- A **protected** cluster needs `--yes` before any change.
- **Scaling to 0** and **`rm`** stop things, so they need `--allow-dangerous`.

## Work inside a pod

```bash
komando cluster exec prod deploy/api --namespace shop --read-only -- cat /app/config.yml
komando cluster exec prod api-7d9f-x2 -c api --namespace shop -- php artisan cache:clear
komando cluster forward prod svc/api 8080:80 --namespace shop   # 127.0.0.1:8080 until Ctrl-C
komando cluster shell prod deploy/api --namespace shop          # interactive, for people
```

- **`cluster exec`** runs one command (not interactive). The
  dangerous-command filter checks it, as with `exec` on servers.
  `--read-only` says it only looks, checked as for `exec`: a command that
  clearly changes something is refused (`READ_ONLY_VIOLATION`), and a
  protected cluster skips `--yes` only for commands komando knows read
  (`cat`, `ls`, `printenv` ...; see [Commands](commands.md#protected-servers-and---read-only)).
- **`cluster forward`** makes a pod or service port reachable on this
  computer only (127.0.0.1). For a service, the service port is forwarded to
  the pod port behind it. Ctrl-C or `--timeout` ends it normally. What goes
  through it skips komando's checks, so a protected cluster asks first
  (`--yes`), and the audit log records the forward.
- **`cluster shell`** opens a terminal in the pod (bash, else sh) for a
  person, and asks first on a protected cluster. Agents get
  `NEEDS_TERMINAL` and use `cluster exec` instead.
- komando speaks Kubernetes' exec and port-forward protocols itself:
  WebSocket, and SPDY on clusters older than Kubernetes 1.30, as kubectl
  does. A pod or service that does not exist is "not found" (exit 3).

## Anything else kubectl or docker can do

```bash
komando cluster run prod -- get pods -A -o wide
komando cluster run prod --write -- rollout undo deployment/api -n shop
komando cluster run swarm1 -- service ps web
```

On Kubernetes, `cluster run` is komando's own kubectl. It understands kubectl
commands and prints what kubectl prints, through the conn's `--via` path,
with no kubectl installed. On Swarm the command goes to docker on the
manager.

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
  skips links and devices, like kubectl cp.
- On Swarm, `docker run`, `create` and `service create|update` that give a
  container the server (`--privileged`, `--cap-add`, devices, the host's
  network or processes, `--volumes-from`, a bind of `/`, the docker socket,
  system or credential folders) also need `--allow-dangerous`, as do
  `plugin install|create|enable|set` and a `volume create` that is a host
  folder. Known gap: komando cannot see inside a compose or stack file on
  the server, so `stack deploy -c FILE` and `compose up` are rated by
  their flags only.
- It stops at `--timeout` (default 5 minutes). A watch (`get -w`) or follow
  (`logs -f`) that ends there ends normally. `logs -f` prints lines as they
  come and follows all selected pods at once (`--max-log-requests`, 5 by
  default).
- Sessions have their own commands: `cluster forward` (port-forward) and
  `cluster shell` (`exec -it`).

Supported kubectl commands:

| Group | Commands |
|-------|----------|
| Read | `get` (server tables, `-o wide\|name\|json\|yaml\|jsonpath=...\|custom-columns=...`, `-w`, `-l`, `-A`), `describe`, `logs`, `events`, `top`, `explain`, `version`, `api-resources`, `api-versions`, `cluster-info`, `auth can-i`, `auth whoami`, `wait` |
| Roll out | `rollout status\|history\|undo\|restart\|pause\|resume`, `set image`, `scale` |
| Change | `apply`, `diff`, `create` (`-f`, namespace, configmap, secret, deployment, job, cronjob, service, role, rolebinding, token), `replace`, `delete`, `patch`, `label`, `annotate` |
| Nodes | `cordon`, `uncordon`, `drain`, `taint` |
| Pods | `run`, `exec`, `cp`, `debug` |
| Other | `certificate approve\|deny`, `config` |
