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
komando cluster status prod                         # version, nodes ready, pods not running
komando cluster ls prod pods --namespace shop
komando cluster ls prod deploy --all-namespaces
komando cluster get prod deploy api --namespace shop   # the whole object (Secret values are hidden)
komando cluster logs prod api-7d9f-x2 --namespace shop --since 10m -n 100

komando cluster status swarm1                       # a Swarm manager
komando cluster ls swarm1 services
komando cluster logs swarm1 web -n 100
```

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
