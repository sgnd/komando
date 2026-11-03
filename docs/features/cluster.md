# Clusters (Kubernetes and Docker Swarm)

See and change what runs in Kubernetes and Docker Swarm with one set of
commands. [All features](README.md)

## Add a cluster

Kubernetes clusters come from your kubeconfig, one conn per context:

```bash
komando import kubeconfig --dry-run        # see what would be added
komando import kubeconfig                  # ~/.kube/config
komando conn edit prod --via bastion       # a private API server? reach it like anything else
```

The kubeconfig for each context goes to the vault. EKS and GKE logins in
the kubeconfig (`aws eks get-token`, `aws-iam-authenticator`,
`gke-gcloud-auth-plugin`) are made by komando itself, so those programs are
not needed; other credential plugins run as the kubeconfig says.

A Docker Swarm needs nothing extra: use a manager server as the target.

## Look

```bash
komando cluster status prod                         # version, nodes, and every problem it finds
komando cluster status prod --namespace shop        # only the problems in one namespace
komando cluster ls prod pods --namespace shop
komando cluster ls prod deploy -A                   # -A is --all-namespaces
komando cluster ls prod pods -l app=api             # only objects with these labels
komando cluster describe prod deployment/api --namespace shop   # images, strategy, pods, events
komando cluster events prod --namespace shop --warnings          # what went wrong, oldest first
komando cluster get prod deploy api --namespace shop   # the whole object (Secret values are hidden)
komando cluster logs prod api-7d9f-x2 --namespace shop --since 10m -n 100

komando cluster status swarm1                       # a Swarm manager
komando cluster ls swarm1 services                  # also: tasks, nodes, stacks
komando cluster describe swarm1 service/web         # image, replicas, update state, tasks and errors
komando cluster logs swarm1 service/web -n 100
```

Objects are named like kubectl names them, in every command: `TYPE NAME` or
`TYPE/NAME` (`deployment api`, `deploy/api`, `deployment.apps/api`). A
mistyped kind says which one you probably meant. On Swarm the kinds are
`service` (`svc`), `task`, `node` and `stack`; Swarm has no namespaces, so
`--namespace` is refused there.

Namespaces are `--namespace` (komando keeps `-n` for "how many"; `-n shop`
answers with the right flag instead of guessing).

With `-o text` lists are tables like kubectl's (`NAME READY UP-TO-DATE
AVAILABLE AGE` for deployments, `NAME READY STATUS RESTARTS AGE NODE` for
pods); JSON has the same rows under `data.items[]`, for Kubernetes and Swarm
alike.

Logs of one pod, of every pod of a workload, or of every pod with a label
(lines start with `[pod]` when there are several; JSON names the `object`
and its `pods`). `-f` keeps reading new lines until Ctrl-C or `--timeout`,
which both end it normally. `--since` takes a duration (`10m`, `2h`) or a
time (`2026-01-02T10:00:00Z`); `--timestamps` starts each line with its time.

```bash
komando cluster logs prod deploy/api --namespace shop -f
komando cluster logs prod -l app=api --namespace shop -n 50
komando cluster logs swarm1 service/web -f --timeout 1m
```

## Inside a pod

```bash
komando cluster exec prod deploy/api --namespace shop --read-only -- cat /app/config.yml
komando cluster exec prod api-7d9f-x2 -c api --namespace shop -- php artisan cache:clear
komando cluster forward prod svc/api 8080:80 --namespace shop   # 127.0.0.1:8080 until Ctrl-C
komando cluster shell prod deploy/api --namespace shop          # interactive, for people
```

`cluster exec` checks the command against the dangerous-command filter, like
`exec` on servers; `--read-only` says it only looks. `cluster forward` makes a
pod or service port reachable on this computer only; Ctrl-C or `--timeout`
ends it normally; for a service, the service's port is forwarded to the
pod's port behind it. `cluster shell` opens a terminal in the pod (bash,
else sh) for a person, and asks first on a protected cluster. komando
speaks Kubernetes' exec and port-forward protocols itself: kubectl is not
needed. A pod or service that does not exist is "not found" (exit 3).

`cluster status` lists problems by name, for example
`pod/shop/api-7d9f-x2: api: CrashLoopBackOff`, `deployment/shop/api: 1 of 3
replicas ready`, or a node under `MemoryPressure`. `healthy` is true when
there are none. On Swarm the same answer lists nodes that are down or
drained and services short of replicas, with the error of a task that does
not run. A server that is not a Swarm manager says so (exit 3). `cluster ls` shows the useful columns per kind: ready
replicas, restarts, ingress hosts, volume claims, job completions, cron
schedules and autoscaler targets.

## Change

```bash
komando cluster apply prod --file app.yaml --dry-run   # the server checks it, nothing changes
komando cluster apply prod --file app.yaml             # created / configured / unchanged per object
komando cluster restart prod deployment/api --namespace shop --wait
komando cluster scale prod deployment/api 3 --namespace shop --wait
komando cluster rm prod pod api-7d9f-x2 --namespace shop --allow-dangerous

komando cluster apply swarm1 --file compose.yml --stack shop --dry-run   # docker stack config checks it
komando cluster apply swarm1 --file compose.yml --stack shop
komando cluster scale swarm1 service/web 4
```

`apply --dry-run` shows per object whether it would be created, changed or
stay the same, with a diff. Secret values never show: a changed value reads
`(hidden, changed)`. Objects in a namespace the same file creates are
reported as created too. An object whose namespace in the file differs from
`--namespace` is refused, like kubectl does. `scale` says the
`previous_replicas` (or `unchanged`).

## Deploy a new version, and go back

```bash
komando cluster deploy prod deployment/api --image ghcr.io/acme/api:1.4.3 --namespace shop --wait
komando cluster status prod deployment/api --namespace shop --wait   # has it rolled out?
komando cluster history prod deployment/api --namespace shop         # revisions and their images
komando cluster rollback prod deployment/api --namespace shop --wait # back to the previous one
komando cluster rollback prod deployment/api --to 3 --namespace shop

komando cluster deploy swarm1 service/web --image nginx:1.27 --wait
komando cluster rollback swarm1 service/web --wait
```

`--wait` stays until every replica runs the new version. It stops with
`ROLLOUT_FAILED` when the cluster gives up (or pods sit in
`ImagePullBackOff`, `CrashLoopBackOff` and the like for 3 minutes), or
`ROLLOUT_TIMEOUT` after `--timeout` (default 5 minutes). Both name the stuck
pods (or Swarm tasks), why, and their image; `cluster rollback` goes back.

`rollback` without `--to` goes to the newest earlier revision with other
images than now. After a rollback, the revision it replaced (the broken one)
is skipped, so rolling back twice does not bring it back; pick any revision
with `--to` (a missing one lists those that exist; the current one changes
nothing and says `unchanged`). A Swarm rollback that you start is followed
to its end, not reported as a failed update.

- A protected cluster asks for `--yes` before any change.
- Scaling to 0 and `rm` stop things, so they need `--allow-dangerous`.

## Anything kubectl or docker can do

```bash
komando cluster run prod -- get pods -A -o wide
komando cluster run prod --write -- rollout undo deployment/api -n shop
komando cluster run swarm1 -- service ps web
```

For Kubernetes, `cluster run` is komando's own kubectl: it understands the
kubectl commands and prints what kubectl prints, through the conn's `--via`
path, with no kubectl installed. It covers get (the server's tables, `-o
wide|name|json|yaml|jsonpath=...|custom-columns=...`, `-w`, `-l`, `-A`),
describe, logs, events, top, explain, version, api-resources, api-versions,
cluster-info, auth can-i/whoami, wait, rollout (status, history, undo,
restart, pause, resume), apply, diff, create (`-f`, namespace, configmap,
secret, deployment, job, cronjob, service, role(binding), token), replace,
delete, patch, label, annotate, scale, set image, cordon, uncordon, drain,
taint, run, exec, cp, debug, certificate approve/deny and config. Sessions
have their own commands: `cluster forward` (port-forward) and `cluster
shell` (`exec -it`). On Swarm the command goes to docker on the manager. It
only reads unless you add `--write`; delete, drain and similar need
`--allow-dangerous` too.

`cluster run` stops at `--timeout` (default 5 minutes); a watch (`get -w`)
or follow (`logs -f`) that ends there ends normally.
