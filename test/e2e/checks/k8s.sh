# shellcheck shell=bash
# Kubernetes (k3s on the private network, reached through the bastion).
# Kubernetes (k3s on the private network, reached through the bastion)
echo "==> cluster (k3s through the bastion)"
for _ in $(seq 1 60); do docker compose -p "$PROJECT" -f "$E2E/compose.yml" exec -T k3s kubectl get nodes 2>/dev/null | grep -q " Ready" && break; sleep 2; done
# a new cluster makes no pod before its default ServiceAccount exists
for _ in $(seq 1 60); do docker compose -p "$PROJECT" -f "$E2E/compose.yml" exec -T k3s kubectl get serviceaccount default >/dev/null 2>&1 && break; sleep 2; done
docker compose -p "$PROJECT" -f "$E2E/compose.yml" exec -T k3s cat /etc/rancher/k3s/k3s.yaml | sed 's#https://127.0.0.1:6443#https://k3s:6443#; s#: default$#: lab-k3s#' > "$TMP/kubeconfig"
q $K import kubeconfig "$TMP/kubeconfig"
q $K conn edit lab-k3s --via bastion
check "cluster status through bastion" 1 "$($K cluster status lab-k3s | jget 'd["data"]["nodes_ready"]')"
cat > "$TMP/app.yaml" <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata: { name: web, namespace: default }
spec:
  replicas: 1
  selector: { matchLabels: { app: web } }
  template:
    metadata: { labels: { app: web } }
    spec: { containers: [ { name: web, image: "rancher/mirrored-pause:3.6" } ] }
YAML
check "apply --dry-run changes nothing" "K8S_NOT_FOUND" "$($K cluster apply lab-k3s --file "$TMP/app.yaml" --dry-run >/dev/null; $K cluster get lab-k3s deploy web | jget 'd["error"]["code"]' || true)"
check "apply --dry-run shows the change" create "$($K cluster apply lab-k3s --file "$TMP/app.yaml" --dry-run | jget 'd["data"]["changes"][0]["action"]')"
q $K cluster apply lab-k3s --file "$TMP/app.yaml"
check "apply then list" web "$($K cluster ls lab-k3s deployments | jget 'd["data"]["items"][0]["name"]')"
check "ls -l picks by label" "True 0" "$($K cluster ls lab-k3s pods -l app=web | jget 'd["data"]["count"] >= 1') $($K cluster ls lab-k3s pods -l app=nope | jget 'd["data"]["count"]')"
check "events for an object" True "$($K cluster events lab-k3s --for deployment/web | jget 'd["data"]["count"] > 0')"
check "describe lists the pods" True "$($K cluster describe lab-k3s deployment web | jget 'len(d["data"]["pods"]) > 0')"
cat > "$TMP/broken.yaml" <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata: { name: broken, namespace: default }
spec:
  replicas: 1
  selector: { matchLabels: { app: broken } }
  template:
    metadata: { labels: { app: broken } }
    spec: { containers: [ { name: app, image: "komando.invalid/none:0" } ] }
YAML
q $K cluster apply lab-k3s --file "$TMP/broken.yaml"
for _ in $(seq 1 45); do $K cluster status lab-k3s | jget 'any("ImagePull" in p["problem"] or "ErrImage" in p["problem"] for p in d["data"]["problems"])' | grep -q True && break; sleep 2; done
check "status names a bad image" True "$($K cluster status lab-k3s | jget 'any(("ImagePull" in p["problem"] or "ErrImage" in p["problem"]) and "broken" in p["object"] for p in d["data"]["problems"])')"
check "status counts the deployment short" True "$($K cluster status lab-k3s | jget 'any(p["object"]=="deployment/default/broken" for p in d["data"]["problems"])')"
check "describe shows the container reason" True "$($K cluster describe lab-k3s pod "$($K cluster ls lab-k3s pods -l app=broken | jget 'd["data"]["items"][0]["name"]')" | jget '"Err" in str(d["data"]["containers"][0].get("reason")) or "ImagePull" in str(d["data"]["containers"][0].get("reason"))')"
q $K cluster rm lab-k3s deployment broken --allow-dangerous
q $K cluster scale lab-k3s deployment/web 2
check "scale" 2 "$($K cluster get lab-k3s deploy web | jget 'd["data"]["spec"]["replicas"]')"
set +e; $K cluster scale lab-k3s deployment/web 0 >/dev/null; check "scale to 0 needs --allow-dangerous" 6 $?; set -e
q $K cluster restart lab-k3s deployment/web
set +e; $K cluster run lab-k3s -- delete deploy web >/dev/null; check "cluster run delete needs --write" 6 $?; set -e
check "cluster run secret values need --allow-dangerous" POLICY_BLOCKED "$($K cluster run lab-k3s --write -- get secrets -A -o yaml | jget 'd["error"]["code"]' || true)"
check "cluster run reads through bastion" True "$(env PATH=/usr/bin:/bin $K cluster run lab-k3s -- get deploy web -o name | jget '"deployment.apps/web" in d["data"]["stdout"]')"
check "rollout status --wait" True "$($K cluster status lab-k3s deployment/web --wait --timeout 90s | jget 'd["data"]["rolled_out"]')"
check "deploy a bad image times out" ROLLOUT_TIMEOUT "$($K cluster deploy lab-k3s deployment/web --image komando.invalid/none:1 --wait --timeout 20s | jget 'd["error"]["code"]' || true)"
check "history keeps the revisions" True "$($K cluster history lab-k3s deployment/web | jget 'len(d["data"]["revisions"]) >= 2 and d["data"]["revisions"][0]["images"] == ["komando.invalid/none:1"]')"
check "rollback brings the old image back" "rancher/mirrored-pause:3.6" "$($K cluster rollback lab-k3s deployment/web --wait --timeout 90s | jget 'd["data"]["images"][0]')"
check "rolled back and healthy" True "$($K cluster status lab-k3s deployment/web | jget 'd["data"]["rolled_out"]')"
check "logs of a workload" True "$($K cluster logs lab-k3s deploy/web | jget '"object" in d["data"]')"
check "logs by label" True "$($K cluster logs lab-k3s -l app=web | jget '"logs" in d["data"]')"
check "logs -f stops at --timeout" True "$($K cluster logs lab-k3s deploy/web -f --timeout 3s | tail -1 | jget 'd["data"]["followed"]')"
check "exec in a pod needs --read-only or a change" True "$($K cluster exec lab-k3s deploy/web --read-only --dry-run -- cat /etc/hostname | jget '"exec deploy/web" in d["data"]["would_run"]')"
check "exec checks the policy" POLICY_BLOCKED "$($K cluster exec lab-k3s deploy/web -- rm -rf / | jget 'd["error"]["code"]' || true)"
check "forward runs on 127.0.0.1" True "$($K cluster forward lab-k3s deploy/web 18099:80 --dry-run | jget '"--address 127.0.0.1" in d["data"]["would_run"]')"
# exec and port-forward for real, with no kubectl on PATH
write_tools_yaml "$TMP/tools.yaml"
q $K cluster apply lab-k3s --file "$TMP/tools.yaml"
$K cluster status lab-k3s deployment/tools --wait --timeout 120s >/dev/null || true
NOKUBE=(env PATH=/usr/bin:/bin)
check "exec without kubectl" hello-from-pod "$("${NOKUBE[@]}" $K cluster exec lab-k3s deploy/tools --read-only -- cat /www/index.html | jget 'd["data"]["stdout"].strip()' || true)"
check "exec keeps stdout, stderr and the exit code" "3 out err" "$("${NOKUBE[@]}" $K cluster exec lab-k3s deploy/tools --read-only -- sh -c 'echo out; echo err >&2; exit 3' | jget 'str(d["data"]["exit_code"]) + " " + d["data"]["stdout"].strip() + " " + d["data"]["stderr"].strip()' || true)"
"${NOKUBE[@]}" $K cluster forward lab-k3s deploy/tools 18099:8080 --timeout 20s >/dev/null 2>&1 &
"${NOKUBE[@]}" $K cluster forward lab-k3s svc/tools 18098:80 --timeout 20s >/dev/null 2>&1 &
for _ in $(seq 1 20); do curl -sf http://127.0.0.1:18099/ >/dev/null && curl -sf http://127.0.0.1:18098/ >/dev/null && break; sleep 1; done
check "forward a pod port without kubectl" hello-from-pod "$(curl -sf http://127.0.0.1:18099/ || true)"
check "forward a service port to its named target port" hello-from-pod "$(curl -sf http://127.0.0.1:18098/ || true)"
check "two connections through one forward" "hello-from-pod hello-from-pod" "$(curl -sf http://127.0.0.1:18099/ || true) $(curl -sf http://127.0.0.1:18099/ || true)"
wait
echo "copied in" > "$TMP/cp-in.txt"
check "cluster shell needs a person" NEEDS_TERMINAL "$($K cluster shell lab-k3s deploy/tools </dev/null | jget 'd["error"]["code"]' || true)"
check "cluster shell for a person" hello-from-pod "$(ptyrun 'cat /www/index.html; exit\n' env NO_COLOR=1 "$K" cluster shell lab-k3s deploy/tools | tr -d '\r' | grep -x hello-from-pod | head -1 || true)"
# cluster run is komando's own kubectl: every verb here runs with no kubectl on PATH
KR() { "${NOKUBE[@]}" $K cluster run lab-k3s "$@"; }
KS() { KR "$@" | jget 'd["data"]["stdout"]' || true; }
check "run: get prints the server's table" True "$(KS -- get pods -l app=tools | python3 -c 'import sys; s=sys.stdin.read(); print(s.startswith("NAME") and "READY" in s and "STATUS" in s and "tools-" in s)')"
check "run: get -o jsonpath" tools "$(KS -- get deploy tools -o 'jsonpath={.metadata.name}')"
check "run: get -o custom-columns" True "$(KS -- get svc tools -o 'custom-columns=PORT:.spec.ports[0].port' | grep -qx 80 && echo True)"
check "run: describe" True "$(KS -- describe deploy tools | grep -q 'deployment/tools' && echo True)"
check "run: api-resources" True "$(KS -- api-resources | grep -q '^deployments ' && echo True)"
check "run: version" True "$(KS -- version | grep -q 'Server Version: v1\.' && echo True)"
check "run: auth can-i" yes "$(KS -- auth can-i get pods | tr -d '\n')"
check "run: explain a field" True "$(KS -- explain deployment.spec.replicas | grep -q 'FIELD: replicas <integer>' && echo True)"
check "run: wait for a condition" True "$(KS -- wait deploy/tools --for=condition=Available --timeout=60s | grep -q 'condition met' && echo True)"
check "run: rollout status" True "$(KS -- rollout status deploy/tools | grep -q 'rolled out' && echo True)"
check "run: exec" hello-from-pod "$(KS --write --allow-dangerous -- exec deploy/tools -- cat /www/index.html | tr -d '\n')"
q KR --write -- create configmap e2e-cfg --from-literal=color=blue
check "run: create configmap, read it back" blue "$(KS -- get cm e2e-cfg -o 'jsonpath={.data.color}')"
q KR --write -- label cm e2e-cfg tier=test
check "run: label" test "$(KS -- get cm e2e-cfg -o 'jsonpath={.metadata.labels.tier}')"
check "run: label refuses to overwrite" 5 "$(KR --write -- label cm e2e-cfg tier=other >/dev/null; echo $?)"
q KR --write --allow-dangerous -- patch cm e2e-cfg --type merge -p '{"data":{"color":"green"}}'
check "run: patch" green "$(KS -- get cm e2e-cfg -o 'jsonpath={.data.color}')"
check "run: delete needs --allow-dangerous" 6 "$(KR --write -- delete cm e2e-cfg >/dev/null; echo $?)"
q KR --write --allow-dangerous -- delete cm e2e-cfg
check "run: deleted is not found" K8S_NOT_FOUND "$(KR -- get cm e2e-cfg | jget 'd["error"]["code"]' || true)"
POD=$(KS -- get pods -l app=tools -o 'jsonpath={.items[0].metadata.name}')
q KR --write --allow-dangerous -- cp "$TMP/cp-in.txt" "$POD:/tmp/cp-in.txt"
q KR --write --allow-dangerous -- cp "$POD:/tmp/cp-in.txt" "$TMP/cp-back.txt"
check "run: cp there and back" "copied in" "$(cat "$TMP/cp-back.txt" 2>/dev/null)"
check "run: diff a change exits 1" 5 "$(sed 's/replicas: 1/replicas: 2/' "$TMP/tools.yaml" > "$TMP/tools2.yaml"; KR -- diff -f "$TMP/tools2.yaml" >/dev/null; echo $?)"
check "run: scale" 2 "$(KR --write -- scale deploy/tools --replicas=2 >/dev/null; KS -- get deploy tools -o 'jsonpath={.spec.replicas}')"
q $K cluster rm lab-k3s deployment tools --allow-dangerous
q $K cluster rm lab-k3s service tools --allow-dangerous
q $K cluster rm lab-k3s deployment web --allow-dangerous
