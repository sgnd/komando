# shellcheck shell=bash
# The everyday commands of every area, run by an AI agent (A: CLAUDECODE=1,
# no approval window). Other checks drive komando as a script ($K); here the
# same lab is read the way an agent reads it, and each answer must
#   - be one JSON envelope that says ok,
#   - never hold a password of the lab (they are all known here),
#   - never wait for a person: stdin is closed, so a prompt would fail.
# Then each area's change that an agent may not make alone must stop with
# the code that tells the agent what to ask the user.
#
# Each part runs in the area that has its containers (run.sh), after the
# area's other checks: every conn and host they leave is there by then.
AG="$TMP/zz-agent.log" # every agent answer, for the leak check at the end
: >"$AG"
ag() { A "$@" </dev/null | tee -a "$AG"; }      # ag ARGS...: run as the agent, keep the answer
aok() { check "agent: $1" True "$(ag "${@:2}" | jget 'd["ok"]' || true)"; } # aok NAME ARGS...
acode() { # acode NAME CODE ARGS...: the agent's command stops with CODE
  check "agent: $1" "$2" "$(ag "${@:3}" | jget '(d.get("error") or d.get("data", {}).get("would_be_blocked") or {}).get("code")' || true)"
}

if in_area data; then
# inventory, settings and help
aok "version" version
aok "list" list
aok "test direct" test direct
aok "host show (references, no values)" host show direct
aok "conn show" conn show pg
aok "conn kinds" conn kinds
aok "vpn list" vpn list
aok "vpn show" vpn show corp
aok "group list" group list
aok "key list" key list
aok "secret list" secret list
aok "config show" config show
aok "policy list" policy list
check "agent: policy check names the rule" True "$(ag policy check 'rm -rf /' | jget '"rm-root" in json.dumps(d)' || true)"
aok "audit" audit --limit 5
aok "audit verify" audit verify
aok "doctor" doctor
aok "status" status
aok "schema" schema --compact
aok "recipe list" recipe list

# servers
aok "facts" facts direct
aok "exec --read-only" exec direct --read-only -- uname -a
aok "recipe run health" recipe run health direct
aok "fs ls" fs ls direct /etc
aok "fs stat" fs stat direct /etc/hostname
aok "fs cat" fs cat direct /etc/hostname
aok "logs from a file" logs direct --file /etc/hostname
aok "job list" job list
aok "tunnel list" tunnel list
aok "net ports" net ports direct
aok "net dns" net dns direct localhost
aok "net check" net check bastion pg:5432
aok "pkg installed" pkg installed direct curl
aok "user list" user list direct
aok "cron list" cron list direct
fi

if in_area swarm; then
aok "docker ps" docker ps swarm1
aok "docker images" docker images swarm1
fi

if in_area data; then
# data
aok "db query" db query pg 'select 1'
aok "db schema" db schema pg
aok "db info" db info pg
aok "db sizes" db sizes pg
aok "db activity" db activity pg
aok "db locks" db locks pg
aok "db user ls" db user ls pg
aok "db on a protected conn reads" db query maria 'select 1'
aok "cache info" cache info cache
aok "cache keys" cache keys cache '*'
aok "storage ls" storage ls bucket
fi

if in_area registry; then
aok "registry ls" registry ls reg
fi

if in_area k8s; then
# clusters
aok "cluster status" cluster status lab-k3s
aok "cluster ls" cluster ls lab-k3s pods -A
aok "cluster events" cluster events lab-k3s -A
aok "cluster helm ls" cluster helm ls lab-k3s -A
check "agent: cluster get hides Secret values" True \
  "$(ag cluster get lab-k3s secret --namespace kube-system "$(A cluster ls lab-k3s secrets --namespace kube-system </dev/null | jget 'd["data"]["items"][0]["name"]')" | jget 'len(d["data"]["data"]) > 0 and all(v == "(hidden)" for v in d["data"]["data"].values())' || true)"
fi

if in_area data; then
# what an agent may not do alone: each stops with a code that says why
acode "db write needs --write" WRITE_REQUIRES_FLAG db query pg 'create table t_agent(x int)'
acode "db write on a protected conn needs a person" PROTECTED_TARGET db query maria --write 'create table t_agent(x int)'
acode "cache write needs --write" WRITE_REQUIRES_FLAG cache run cache -- SET t-agent 1
acode "storage rm needs --allow-dangerous" POLICY_BLOCKED storage rm bucket e2e/nothing
fi

if in_area registry; then
acode "registry rm needs --allow-dangerous" POLICY_BLOCKED registry rm reg e2e/nothing:1
fi

if in_area k8s; then
acode "scaling to 0 needs --allow-dangerous" POLICY_BLOCKED cluster scale lab-k3s deploy/web 0
fi

if in_area data; then
acode "a service on a protected host needs a person" PROTECTED_HOST svc restart target nginx
acode "a change on a protected host needs a person" PROTECTED_HOST exec target -- touch /tmp/t-agent
acode "an agent cannot log in for a person" NEEDS_TERMINAL login direct
acode "an agent gets no SQL shell" NEEDS_TERMINAL db shell pg
fi

if in_area k8s; then
acode "an agent gets no pod shell" NEEDS_TERMINAL cluster shell lab-k3s deploy/web
fi

if in_area data; then
acode "an agent cannot change the vault passphrase" NEEDS_PERSON secret passphrase
check "agent: secret passphrase --dry-run previews" "True NEEDS_PERSON" "$(ag secret passphrase --dry-run | jget 'd["data"]["dry_run"], d["meta"]["would_be_blocked"]["code"]' || true)"
# secrets: the user types a password, never the agent
acode "an agent does not type a password" NEEDS_PERSON secret set t-agent-pass
check "agent: secret set --dry-run previews" "True NEEDS_PERSON" "$(ag secret set t-agent-pass --dry-run | jget 'd["data"]["would_set"], d["meta"]["would_be_blocked"]["code"]' || true)"
acode "a value on the command line is refused" SECRET_IN_ARGS secret set t-agent-pass hunter22
export T_AGENT_EMPTY=
acode "an empty --from-env is refused" USAGE secret set t-agent-pass --from-env T_AGENT_EMPTY
unset T_AGENT_EMPTY
acode "only a person compares a value" NEEDS_PERSON secret check ops-pass
check "agent: a generated token can come on stdin" True "$(echo gen-token-123 | A secret set t-agent-token | jget 'd["ok"]' || true)"
check "agent: the token is listed, without its value" "True False" "$(ag secret list | jget '"t-agent-token" in json.dumps(d), "gen-token-123" in json.dumps(d)' || true)"
check "agent: rename a secret it cannot read" True "$(ag secret mv t-agent-token t-agent-token2 | jget 'd["ok"]' || true)"
check "agent: removing a secret needs a person's yes" POLICY_BLOCKED "$(ag secret rm t-agent-token2 | jget 'd["error"]["code"]' || true)"
q $K secret rm t-agent-token2 --allow-dangerous
check "agent: nothing was stored for the typed password" SECRET_NOT_FOUND "$(ag secret get t-agent-pass | jget 'd["error"]["code"]' || true)"
fi

# not one password of the lab in anything the agent saw
check "agent: no lab password in any answer" 0 \
  "$(grep -c -E 'agentpass|apppass|shoppass|redispass|opspass|mcpass|deploypass|hunter22' "$AG" || true)"
