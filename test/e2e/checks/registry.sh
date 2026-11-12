# shellcheck shell=bash
# Container registry (registry:2 on the private network, through the
# bastion), and one with HTTPS from a private CA.
echo "==> registry"
docker pull -q busybox:1.37 >/dev/null && docker tag busybox:1.37 "127.0.0.1:$E2E_REGISTRY"/tools/busybox:1.37 && docker push -q "127.0.0.1:$E2E_REGISTRY"/tools/busybox:1.37 >/dev/null
q $K conn add reg 'registry://e2e@registry:5000?tls=false' --via bastion
check "registry catalog" True "$($K registry ls reg | jget '"tools/busybox" in d["data"]["repositories"]')"
check "registry tags" 1.37 "$($K registry ls reg tools/busybox | jget 'd["data"]["tags"][0]')"
check "registry inspect digest" True "$($K registry inspect reg tools/busybox:1.37 | jget 'd["data"]["digest"].startswith("sha256:")')"
q $K registry copy reg:tools/busybox:1.37 reg:mirror/busybox:stable
check "registry copy keeps the digest" "$($K registry inspect reg tools/busybox:1.37 | jget 'd["data"]["digest"]')" "$($K registry inspect reg mirror/busybox:stable | jget 'd["data"]["digest"]')"
set +e; $K registry rm reg tools/busybox:1.37 >/dev/null; check "registry rm needs --allow-dangerous" 6 $?; set -e
check "registry rm names the tags it takes" True "$($K registry rm reg tools/busybox:1.37 --allow-dangerous --dry-run | jget '"1.37" in d["data"]["tags"]')"
q $K registry rm reg tools/busybox:1.37 --allow-dangerous
check "registry rm removed it" REGISTRY_NOT_FOUND "$($K registry inspect reg tools/busybox:1.37 | jget 'd["error"]["code"]' || true)"
# a person deleting an image: told which tags go, then types the conn's name
rtty() { ptyrun "$1" env NO_COLOR=1 TERM=dumb "$K" -o text "${@:2}" | tr -d '\r'; }
q $K registry copy reg:mirror/busybox:stable reg:mirror/busybox:also
set +e
O=$(rtty 'wrong\n' registry rm reg mirror/busybox:stable); RC=$?
check "person: registry rm says every tag that goes" 1 "$(grep -c 'every tag on it: also, stable' <<<"$O")"
check "person: registry rm asks to type the name" 1 "$(grep -c 'Type the name reg to continue' <<<"$O")"
check "person: a wrong name stops registry rm (6)" 6 "$RC"
check "person: a wrong name deleted nothing" True "$($K registry inspect reg mirror/busybox:also | jget 'd["ok"]')"
O=$(rtty 'reg\n' registry rm reg mirror/busybox:stable); RC=$?
check "person: the right name deletes the image" "0 1" "$RC $(grep -c 'with it went every tag on that image: also, stable' <<<"$O")"
check "person: both tags are gone" "[]" "$($K registry ls reg mirror/busybox | jget 'd["data"]["tags"]')"
check "person: registry ls in text says what is next" 1 "$(rtty '' registry ls reg | grep -c 'Next: komando registry ls reg REPO')"
check "agent: registry names are checked first" USAGE "$($K registry inspect reg 'tools/../_catalog:1' | jget 'd["error"]["code"]' || true)"
set -e
# prune: three images built one after the other; keepme is the same image as v1
for v in 1 2 3; do
  printf 'FROM busybox:1.37\nRUN echo %s > /build\n' "$v" | docker build -q -t "127.0.0.1:$E2E_REGISTRY/prune/app:v$v" - >/dev/null
  docker push -q "127.0.0.1:$E2E_REGISTRY/prune/app:v$v" >/dev/null; sleep 1
done
docker tag "127.0.0.1:$E2E_REGISTRY/prune/app:v1" "127.0.0.1:$E2E_REGISTRY/prune/app:keepme" && docker push -q "127.0.0.1:$E2E_REGISTRY/prune/app:keepme" >/dev/null
check "registry prune needs --allow-dangerous" 6 "$($K registry prune reg prune/app --keep 1 >/dev/null 2>&1; echo $?)"
check "registry prune --dry-run: only v2 goes (v1 is keepme's image)" "['v2'] False" \
  "$($K registry prune reg prune/app --keep 1 --match '^v' --dry-run | jget '[t for d_ in d["data"]["delete"] for t in d_["tags"]], "deleted" in d["data"]')"
q $K registry prune reg prune/app --keep 1 --match '^v' --allow-dangerous
check "registry prune deleted v2 and kept the rest" "['keepme', 'v1', 'v3']" "$($K registry ls reg prune/app | jget 'sorted(d["data"]["tags"])')"
# registry TLS: HTTPS with a private CA, at a name only bastion can look up
q $K conn add regtls 'registry://e2e@registry.lab.test' --via bastion
check "registry: a private CA is refused by default" REGISTRY_TLS "$($K registry ls regtls | jget 'd["error"]["code"]' || true)"
check "registry: the refusal points at ca= first" True "$($K registry ls regtls | jget '"?ca=secret:NAME" in d["error"]["hint"]' || true)"
docker compose -p "$PROJECT" -f "$E2E/compose.yml" exec -T regtls cat /certs/ca.crt | $K secret set regtls-ca >/dev/null
q $K conn edit regtls --url 'registry://e2e@registry.lab.test?ca=secret:regtls-ca'
check "registry: ?ca=secret:NAME trusts the private CA (name looked up on bastion)" True "$($K registry ls regtls | jget 'd["ok"]')"
check "registry: conn test logs in with ca=" login "$($K conn test regtls | jget 'd["data"]["results"][0]["detail"]["check"]')"
check "registry: ca= is not a doctor warning" False "$($K doctor | jget 'any(c["name"] == "security:conn:regtls" for c in d["data"]["security"])')"
q $K conn edit regtls --url 'registry://e2e@registry.lab.test?tls=skip-verify'
check "registry: ?tls=skip-verify works without the CA" True "$($K registry ls regtls | jget 'd["ok"]')"
check "registry: doctor warns about tls=skip-verify, --via too" True "$($K doctor | jget 'any(c["name"] == "security:conn:regtls" and c["warning"] for c in d["data"]["security"])')"
check "registry: an unknown tls value is refused" USAGE "$($K conn edit regtls --url 'registry://e2e@registry.lab.test?tls=insecure' | jget 'd["error"]["code"]' || true)"
q $K conn rm regtls
