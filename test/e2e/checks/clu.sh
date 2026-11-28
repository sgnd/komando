# shellcheck shell=bash
# Clusters, Swarm, docker and registry: shapes, names, errors and safety.
# Uses namespace t-e2eclu, Swarm service t-e2eclu-web and image tag
# t-e2eclu/busybox:2; everything is removed at the end.
CLU_K8S_IMG=${CLU_K8S_IMG:-rancher/mirrored-pause:3.6}
CLU_IMG=${CLU_IMG:-busybox:1.37}
set +e

# each part runs in the area that has its containers (run.sh)
if in_area k8s; then
# Kubernetes
cat > "$TMP/clu.yaml" <<YAML
apiVersion: v1
kind: Namespace
metadata: { name: t-e2eclu }
---
apiVersion: v1
kind: Secret
metadata: { name: creds, namespace: t-e2eclu }
stringData: { password: one }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: web, namespace: t-e2eclu }
spec:
  replicas: 1
  selector: { matchLabels: { app: web } }
  template:
    metadata: { labels: { app: web } }
    spec: { containers: [ { name: web, image: "$CLU_K8S_IMG" } ] }
YAML
q $K cluster kubernetes raw lab-k3s --write -- apply -f "$TMP/clu.yaml"
$K cluster kubernetes raw lab-k3s --timeout 90s -- rollout status deployment/web -n t-e2eclu >/dev/null
check "exec in a missing pod is not found" 3 "$($K cluster kubernetes exec lab-k3s nopod --namespace t-e2eclu --read-only -- ls >/dev/null 2>&1; echo $?)"
check "cluster kubernetes raw ends a watch at --timeout" 0 "$($K cluster kubernetes raw lab-k3s --timeout 3s -- get pods -n t-e2eclu -w >/dev/null; echo $?)"
# :80 takes any free local port (like kubectl), so the check never meets a port in use;
# kubectl's words stay in $TMP/fw.err to show why if it fails
check "forward ends normally at --timeout" "0 True" "$($K cluster kubernetes tunnel start lab-k3s deploy/web :80 --namespace t-e2eclu --timeout 5s >"$TMP/o" 2>"$TMP/fw.err"; echo $?) $(jget 'd["ok"]' <"$TMP/o")"
[ "$(jget 'd["ok"]' <"$TMP/o")" = True ] || { echo "  forward stderr:"; head -5 "$TMP/fw.err"; }
# Ctrl-C ends a forward cleanly: exit 0, the local port is closed again
$K cluster kubernetes tunnel start lab-k3s deploy/web 18096:80 --namespace t-e2eclu >"$TMP/fwi.out" 2>/dev/null &
FW=$!
for _ in $(seq 1 40); do (exec 3<>/dev/tcp/127.0.0.1/18096) 2>/dev/null && break; sleep 0.5; done
kill -INT "$FW"; wait "$FW"; RC=$?
check "forward: Ctrl-C ends it normally" "0 True" "$RC $(jget 'd["data"]["stopped"]' <"$TMP/fwi.out")"
check "forward: the local port is closed after Ctrl-C" closed "$( (exec 3<>/dev/tcp/127.0.0.1/18096) 2>/dev/null && echo open || echo closed)"
q $K cluster kubernetes raw lab-k3s --write --allow-dangerous -- delete namespace t-e2eclu
fi

if in_area swarm; then
# Docker Swarm
# a Swarm service pulls by digest, so the tag may not be there to copy
q $K docker pull swarm1 "$CLU_IMG"
q $K docker raw swarm1 -- tag "$CLU_IMG" t-e2eclu/busybox:2
q $K cluster swarm raw swarm1 --write -- service create --detach --name t-e2eclu-web "$CLU_IMG" sleep 86400
# service create --detach returns before the task runs: wait for its container (docker ps lists running ones)
CTR=""
for _ in $(seq 1 60); do
  CTR=$($K docker ps swarm1 | jget '[c["Names"] for c in d["data"]["results"][0]["data"] if c["Names"].startswith("t-e2eclu-web.")][0]' 2>/dev/null) || CTR=""
  [ -n "$CTR" ] && break
  sleep 2
done
check "docker exec passes words as given" "3 out" "$($K docker exec swarm1 "$CTR" --read-only -- sh -c 'echo out; exit 3' | jget 'str(d["data"]["results"][0]["exit_code"]) + " " + d["data"]["results"][0]["stdout"].strip()')"
check "docker raw: global flags do not hide rm" POLICY_BLOCKED "$($K docker raw swarm1 -- -l debug volume rm nothing | jget 'd["error"]["code"]')"
check "docker compose: down -v behind -p is checked" POLICY_BLOCKED "$($K docker compose swarm1 --dry-run -- -p proj down -v | jget 'd["meta"]["would_be_blocked"]["code"]')"
check "docker raw refuses an unknown leading flag" USAGE "$($K docker raw swarm1 -- --weird x ps | jget 'd["error"]["code"]')"
check "docker inspect of a missing object is not found" 3 "$($K docker inspect swarm1 nope >/dev/null; echo $?)"
q $K cluster swarm raw swarm1 --write --allow-dangerous -- service rm t-e2eclu-web
q $K docker raw swarm1 --allow-dangerous -- rmi t-e2eclu/busybox:2
fi

if in_area registry; then
# registry
check "a missing tag names the tags there" "3 True" "$($K registry oci image show reg mirror/busybox:latest >"$TMP/o"; echo $?) $(jget '"mirror/busybox:latest not found; tags: stable" in d["error"]["message"]' <"$TMP/o")"
check "rm --dry-run names the tags that go" True "$($K registry oci image delete reg mirror/busybox:stable --dry-run | jget '"stable" in d["data"]["would_remove_tags"]')"
check "copy without CONN: is a usage error" USAGE "$($K registry oci image copy mirror/busybox:stable reg:x | jget 'd["error"]["code"]')"
fi

set -e
