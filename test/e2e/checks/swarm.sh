# shellcheck shell=bash
# Docker Swarm (a one-node manager, Docker-in-Docker, over SSH). +swarm
# has added swarm1.
check "swarm status" True "$($K cluster status swarm1 | jget 'd["data"]["healthy"]')"
cat > "$TMP/stack.yml" <<'YAML'
services:
  web:
    image: busybox:1.37
    command: ["sleep", "86400"]
YAML
q $K cluster apply swarm1 --file "$TMP/stack.yml" --stack e2e
check "swarm services" True "$($K cluster ls swarm1 services | jget 'any(r["name"]=="e2e_web" for r in d["data"]["items"])')"
q $K cluster scale swarm1 service/e2e_web 2
check "swarm scale" True "$($K cluster ls swarm1 services | jget 'any(r["ready"].endswith("/2") for r in d["data"]["items"])')"
check "swarm status --wait" True "$($K cluster status swarm1 service/e2e_web --wait --timeout 90s | jget 'd["data"]["rolled_out"]')"
check "swarm rollback --wait" 1/1 "$($K cluster rollback swarm1 service/e2e_web --wait --timeout 90s | jget 'd["data"]["replicas"]')"
check "swarm logs -f stops at --timeout" True "$($K cluster logs swarm1 e2e_web -f --timeout 3s >/dev/null; echo True)"
check "swarm run reads" True "$($K cluster run swarm1 -- service ls | jget 'd["data"]["results"][0]["ok"]')"
set +e; $K cluster run swarm1 --write -- service rm e2e_web >/dev/null; check "swarm run rm needs --allow-dangerous" 6 $?; set -e
check "docker raw volume rm needs --allow-dangerous" POLICY_BLOCKED "$($K docker raw swarm1 -- volume rm nothing | jget 'd["error"]["code"]' || true)"
check "docker raw reads stay reads" True "$($K docker raw swarm1 -- volume ls | jget 'd["data"]["results"][0]["ok"]')"
q $K cluster rm swarm1 stack e2e --allow-dangerous
