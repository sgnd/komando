# shellcheck shell=bash
# RabbitMQ through --via bastion, with the management API: conn test logs
# in, a quorum queue is created (dry run first), a message goes in, peek
# shows it and gives it back (redelivered), and purge and rm need
# --allow-dangerous.
set +e
RDC() { docker compose -p "$PROJECT" -f "$E2E/compose.yml" "$@"; }
for _ in $(seq 1 90); do
  RDC exec -T rabbitmq rabbitmq-diagnostics -q check_port_connectivity >/dev/null 2>&1 && break
  sleep 1
done
echo -n rabbitpass | $K secret set rabbit-pass >/dev/null
q $K conn add jobs 'amqp://app@rabbitmq:5672/%2F?management=15672' --via bastion --password-ref secret:rabbit-pass
for _ in $(seq 1 30); do [ "$($K conn test jobs | jget 'd["data"]["results"][0]["ok"]' 2>/dev/null)" = True ] && break; sleep 1; done
check "rabbitmq conn test logs in through --via" login "$($K conn test jobs | jget 'd["data"]["results"][0]["detail"]["check"]')"
check "rabbitmq info through the management API" True "$($K queue info jobs | jget 'd["data"]["management"] and len(d["data"]["nodes"]) == 1')"
check "rabbitmq create --dry-run makes nothing" QUEUE_NOT_FOUND "$($K --dry-run queue create jobs e2e-emails --type quorum >/dev/null; $K queue describe jobs e2e-emails | jget 'd["error"]["code"]')"
check "rabbitmq create" quorum "$($K queue create jobs e2e-emails --type quorum | jget 'd["data"]["type"]')"
check "rabbitmq create twice" QUEUE_EXISTS "$($K queue create jobs e2e-emails | jget 'd["error"]["code"]')"
q $K queue send jobs e2e-emails --value '{"id": 1}' --header source=e2e
q $K queue send jobs e2e-emails --value '{"id": 2}'
check "rabbitmq peek reads both" 2 "$($K queue peek jobs e2e-emails | jget 'd["data"]["count"]')"
check "rabbitmq peek gives them back, redelivered" "[True, True]" "$($K queue peek jobs e2e-emails | jget '[m["redelivered"] for m in d["data"]["messages"]]')"
check "rabbitmq peek counts deliveries on a quorum queue" 3 "$($K queue peek jobs e2e-emails | jget 'd["data"]["messages"][0]["deliveries"]')"
check "rabbitmq groups is not for RabbitMQ" NOT_SUPPORTED "$($K queue groups jobs | jget 'd["error"]["code"]')"
check "rabbitmq purge needs --allow-dangerous" POLICY_BLOCKED "$($K queue purge jobs e2e-emails | jget 'd["error"]["code"]')"
check "rabbitmq rm needs --allow-dangerous" POLICY_BLOCKED "$($K queue rm jobs e2e-emails | jget 'd["error"]["code"]')"
check "rabbitmq purge --dry-run counts" 2 "$($K --dry-run queue purge jobs e2e-emails | jget 'd["data"]["messages"]')"
check "rabbitmq peek --wait is for Kafka" NOT_SUPPORTED "$($K queue peek jobs e2e-emails --wait 2s | jget 'd["error"]["code"]')"
# the management API's counts lag a few seconds behind a give-back
ready() { for _ in $(seq 1 15); do r=$($K queue describe jobs e2e-emails | jget 'd["data"]["ready"]'); [ "$r" = 2 ] && break; sleep 1; done; echo "$r"; }
check "rabbitmq peek took nothing" 2 "$(ready)"
check "rabbitmq ls -n 1 is cut and says so" "1 True" "$($K queue create jobs e2e-zz >/dev/null; $K queue ls jobs 'e2e-*' -n 1 | jget '"%d %s" % (d["data"]["count"], d["data"].get("truncated"))')"
# a person purges by typing the conn's name; a wrong one stops it
pty() { ptyrun "$1" env NO_COLOR=1 TERM=dumb "$K" -o text "${@:2}" | tr -d '\r'; }
O=$(pty 'wrong\n' queue purge jobs e2e-emails); RC=$?
check "rabbitmq person: purge names the queue" 1 "$(grep -q 'Dangerous: deletes every message in e2e-emails' <<<"$O" && echo 1)"
check "rabbitmq person: a wrong name stops purge (6)" 6 "$RC"
check "rabbitmq person: the messages are still there" 2 "$($K queue peek jobs e2e-emails | jget 'd["data"]["count"]')"
pty 'jobs\n' queue purge jobs e2e-emails >/dev/null
check "rabbitmq person: the right name purges" 0 "$($K queue peek jobs e2e-emails | jget 'd["data"]["count"]')"
pty 'jobs\n' queue rm jobs e2e-zz >/dev/null
check "rabbitmq person: the right name removes the queue" QUEUE_NOT_FOUND "$($K queue describe jobs e2e-zz | jget 'd["error"]["code"]')"
q $K queue rm jobs e2e-emails --allow-dangerous
q $K conn rm jobs
set -e
