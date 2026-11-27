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
q $K cluster kubernetes raw lab-k3s --write -- apply -f "$TMP/app.yaml"
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
q $K cluster kubernetes raw lab-k3s --write -- apply -f "$TMP/broken.yaml"
q $K cluster kubernetes raw lab-k3s --write --allow-dangerous -- delete deployment broken
q $K cluster kubernetes raw lab-k3s --write -- scale deployment/web --replicas=2
q $K cluster kubernetes raw lab-k3s --write -- rollout restart deployment/web
set +e; $K cluster kubernetes raw lab-k3s -- delete deploy web >/dev/null; check "cluster kubernetes raw delete needs --write" 6 $?; set -e
check "cluster kubernetes raw secret values need --allow-dangerous" POLICY_BLOCKED "$($K cluster kubernetes raw lab-k3s --write -- get secrets -A -o yaml | jget 'd["error"]["code"]' || true)"
check "cluster kubernetes raw reads through bastion" True "$(env PATH=/usr/bin:/bin $K cluster kubernetes raw lab-k3s -- get deploy web -o name | jget '"deployment.apps/web" in d["data"]["stdout"]')"
check "exec in a pod needs --read-only or a change" True "$($K cluster kubernetes exec lab-k3s deploy/web --read-only --dry-run -- cat /etc/hostname | jget '"exec deploy/web" in d["data"]["would_run"]')"
check "exec checks the policy" POLICY_BLOCKED "$($K cluster kubernetes exec lab-k3s deploy/web -- rm -rf / | jget 'd["error"]["code"]' || true)"
check "forward runs on 127.0.0.1" True "$($K cluster kubernetes tunnel start lab-k3s deploy/web 18099:80 --dry-run | jget '"--address 127.0.0.1" in d["data"]["would_run"]')"
# exec and port-forward for real, with no kubectl on PATH
write_tools_yaml "$TMP/tools.yaml"
q $K cluster kubernetes raw lab-k3s --write -- apply -f "$TMP/tools.yaml"
$K cluster kubernetes raw lab-k3s --timeout 120s -- rollout status deployment/tools >/dev/null || true
NOKUBE=(env PATH=/usr/bin:/bin)
check "exec without kubectl" hello-from-pod "$("${NOKUBE[@]}" $K cluster kubernetes exec lab-k3s deploy/tools --read-only -- cat /www/index.html | jget 'd["data"]["stdout"].strip()' || true)"
check "exec keeps stdout, stderr and the exit code" "3 out err" "$("${NOKUBE[@]}" $K cluster kubernetes exec lab-k3s deploy/tools --read-only -- sh -c 'echo out; echo err >&2; exit 3' | jget 'str(d["data"]["exit_code"]) + " " + d["data"]["stdout"].strip() + " " + d["data"]["stderr"].strip()' || true)"
"${NOKUBE[@]}" $K cluster kubernetes tunnel start lab-k3s deploy/tools 18099:8080 --timeout 20s >/dev/null 2>&1 &
"${NOKUBE[@]}" $K cluster kubernetes tunnel start lab-k3s svc/tools 18098:80 --timeout 20s >/dev/null 2>&1 &
for _ in $(seq 1 20); do curl -sf http://127.0.0.1:18099/ >/dev/null && curl -sf http://127.0.0.1:18098/ >/dev/null && break; sleep 1; done
check "forward a pod port without kubectl" hello-from-pod "$(curl -sf http://127.0.0.1:18099/ || true)"
check "forward a service port to its named target port" hello-from-pod "$(curl -sf http://127.0.0.1:18098/ || true)"
check "two connections through one forward" "hello-from-pod hello-from-pod" "$(curl -sf http://127.0.0.1:18099/ || true) $(curl -sf http://127.0.0.1:18099/ || true)"
wait
echo "copied in" > "$TMP/cp-in.txt"
check "cluster kubernetes shell needs a person" NEEDS_TERMINAL "$($K cluster kubernetes shell lab-k3s deploy/tools </dev/null | jget 'd["error"]["code"]' || true)"
check "cluster kubernetes shell for a person" hello-from-pod "$(ptyrun 'cat /www/index.html; exit\n' env NO_COLOR=1 "$K" cluster kubernetes shell lab-k3s deploy/tools | tr -d '\r' | grep -x hello-from-pod | head -1 || true)"
# cluster kubernetes raw is komando's own kubectl: every verb here runs with no kubectl on PATH
KR() { "${NOKUBE[@]}" $K cluster kubernetes raw lab-k3s "$@"; }
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
q KR --write --allow-dangerous -- exec "$POD" -- sh -c 'echo DB_PASSWORD=e2e-pod-pass > /tmp/.env'
# an agent's cp stops at the approval gate (cp is destructive); the name check behind it is in kctl_cp_name_test.go
check "run: an agent's cp from a pod needs a person's yes, nothing copied" "6 no" "$(KOMANDO_AGENT=1 "${NOKUBE[@]}" $K cluster kubernetes raw lab-k3s --write -- cp "$POD:/tmp/.env" "$TMP/agent.env" >/dev/null 2>&1; echo "$? $(test -e "$TMP/agent.env" && echo yes || echo no)")"
q KR --write --allow-dangerous -- cp "$POD:/tmp/.env" "$TMP/person.env"
check "run: a person's cp of a pod's .env is as it is" "DB_PASSWORD=e2e-pod-pass" "$(cat "$TMP/person.env" 2>/dev/null)"
check "run: diff a change exits 1" 5 "$(sed 's/replicas: 1/replicas: 2/' "$TMP/tools.yaml" > "$TMP/tools2.yaml"; KR -- diff -f "$TMP/tools2.yaml" >/dev/null; echo $?)"
check "run: scale" 2 "$(KR --write -- scale deploy/tools --replicas=2 >/dev/null; KS -- get deploy tools -o 'jsonpath={.spec.replicas}')"
q $K cluster kubernetes raw lab-k3s --write --allow-dangerous -- delete deployment tools
q $K cluster kubernetes raw lab-k3s --write --allow-dangerous -- delete service tools
q $K cluster kubernetes raw lab-k3s --write --allow-dangerous -- delete deployment web
