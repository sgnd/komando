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

The kubeconfig for each context goes to the vault. Credential plugins
(`aws eks get-token`, `gke-gcloud-auth-plugin`) still work: komando runs them
when needed.

A Docker Swarm needs nothing extra: use a manager server as the target.

## Look

```bash
komando cluster status prod                         # version, nodes, and every problem it finds
komando cluster ls prod pods --namespace shop
komando cluster ls prod deploy --all-namespaces
komando cluster ls prod pods -l app=api             # only objects with these labels
komando cluster describe prod deployment api --namespace shop   # state, pods, recent events
komando cluster events prod --namespace shop --warnings          # what went wrong, oldest first
komando cluster get prod deploy api --namespace shop   # the whole object (Secret values are hidden)
komando cluster logs prod api-7d9f-x2 --namespace shop --since 10m -n 100

komando cluster status swarm1                       # a Swarm manager
komando cluster ls swarm1 services
komando cluster logs swarm1 web -n 100
```

Logs of one pod, of every pod of a workload, or of every pod with a label
(lines start with `[pod]` when there are several). `-f` keeps reading new
lines until Ctrl-C or `--timeout`:

```bash
komando cluster logs prod deploy/api --namespace shop -f
komando cluster logs prod -l app=api --namespace shop -n 50
komando cluster logs swarm1 web -f
```

## Inside a pod

```bash
komando cluster exec prod deploy/api --namespace shop --read-only -- cat /app/config.yml
komando cluster exec prod api-7d9f-x2 -c api --namespace shop -- php artisan cache:clear
komando cluster forward prod svc/api 8080:80 --namespace shop   # 127.0.0.1:8080 until Ctrl-C
```

`cluster exec` checks the command against the dangerous-command filter, like
`exec` on servers; `--read-only` says it only looks. `cluster forward` makes a
pod or service port reachable on this computer only. Both need `kubectl`.

`cluster status` lists problems by name, for example
`pod/shop/api-7d9f-x2: api: CrashLoopBackOff`, `deployment/shop/api: 1 of 3
replicas ready`, or a node under `MemoryPressure`. `healthy` is true when
there are none. `cluster ls` shows the useful columns per kind: ready
replicas, restarts, ingress hosts, volume claims, job completions, cron
schedules and autoscaler targets.

## Change

```bash
komando cluster apply prod --file app.yaml --dry-run   # the server checks it, nothing changes
komando cluster apply prod --file app.yaml
komando cluster restart prod deployment/api --namespace shop
komando cluster scale prod deployment/api 3 --namespace shop
komando cluster rm prod pod api-7d9f-x2 --namespace shop --allow-dangerous

komando cluster apply swarm1 --file compose.yml --stack shop
komando cluster scale swarm1 service/web 4
```

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
`ROLLOUT_FAILED` when the cluster gives up, or `ROLLOUT_TIMEOUT` after
`--timeout` (default 5 minutes); then `cluster describe` shows why and
`cluster rollback` goes back.

- A protected cluster asks for `--yes` before any change.
- Scaling to 0 and `rm` stop things, so they need `--allow-dangerous`.

## Anything kubectl or docker can do

```bash
komando cluster run prod -- get pods -A -o wide
komando cluster run prod --write -- rollout undo deployment/api -n shop
komando cluster run swarm1 -- service ps web
```

`cluster run` passes the command to kubectl on this computer (with a
private, temporary kubeconfig, through the conn's `--via` path), or to
docker on the Swarm manager. It only reads unless you add `--write`; delete,
drain and similar need `--allow-dangerous` too. kubectl must be installed
for Kubernetes.

Namespaces are `--namespace` (komando keeps `-n` for "how many").
