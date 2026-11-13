# shellcheck shell=bash
# Kafka through --via bastion: conn test logs in, a topic is created
# (dry run first), a message goes in and peek reads it back without a
# consumer group, and purge and rm need --allow-dangerous.
set +e
KDC() { docker compose -p "$PROJECT" -f "$E2E/compose.yml" "$@"; }
for _ in $(seq 1 60); do
  KDC exec -T kafka /opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server localhost:9092 >/dev/null 2>&1 && break
  sleep 1
done
q $K conn add events kafka://kafka:9092 --via bastion
for _ in $(seq 1 30); do [ "$($K conn test events | jget 'd["data"]["results"][0]["ok"]' 2>/dev/null)" = True ] && break; sleep 1; done
check "kafka conn test logs in through --via" login "$($K conn test events | jget 'd["data"]["results"][0]["detail"]["check"]')"
check "kafka info lists the advertised broker" kafka:9092 "$($K queue info events | jget 'd["data"]["brokers"][0]["address"]')"
check "kafka create --dry-run makes nothing" True "$($K --dry-run queue create events e2e-orders --partitions 2 --replicas 1 | jget 'd["data"]["dry_run"]')"
check "kafka ls is empty after the dry run" 0 "$($K queue ls events 'e2e-*' | jget 'd["data"]["count"]')"
check "kafka create" 2 "$($K queue create events e2e-orders --partitions 2 --replicas 1 | jget 'd["data"]["partitions"]')"
check "kafka send" 0 "$($K queue send events e2e-orders --value '{"id": 1}' --partition 0 | jget 'd["data"]["offset"]')"
q $K queue send events e2e-orders --value '{"id": 2}' --key 2
check "kafka peek reads both" 2 "$($K queue peek events e2e-orders | jget 'd["data"]["count"]')"
check "kafka peek joins no group" 0 "$($K queue groups events | jget 'len([g for g in d["data"]["groups"] if "e2e-orders" in g["topics"]])')"
check "kafka describe counts messages" 2 "$($K queue describe events e2e-orders | jget 'd["data"]["messages"]')"
check "kafka purge needs --allow-dangerous" POLICY_BLOCKED "$($K queue purge events e2e-orders | jget 'd["error"]["code"]')"
check "kafka rm needs --allow-dangerous" POLICY_BLOCKED "$($K queue rm events e2e-orders | jget 'd["error"]["code"]')"
check "kafka purge --dry-run counts" 2 "$($K --dry-run queue purge events e2e-orders | jget 'd["data"]["messages"]')"

# a long list is cut at --limit and says so
q $K queue create events e2e-audit --partitions 1 --replicas 1
check "kafka ls -n 1 is cut and says so" "1 True" "$($K queue ls events 'e2e-*' -n 1 | jget '"%d %s" % (d["data"]["count"], d["data"].get("truncated"))')"

# lag follows a real consumer group's committed offsets, and peek moves none
KG() { KDC exec -T kafka /opt/kafka/bin/kafka-consumer-groups.sh --bootstrap-server localhost:9092 --group e2e-billing --topic e2e-orders --reset-offsets --execute "$@" >/dev/null 2>&1; }
KG --to-earliest
check "kafka lag of a group at the start" 2 "$($K queue lag events e2e-billing | jget 'd["data"]["lag"]')"
check "kafka peek leaves the group where it was" 2 "$($K queue peek events e2e-orders >/dev/null; $K queue lag events e2e-billing | jget 'd["data"]["lag"]')"
KG --to-latest
check "kafka lag of a group that read everything" 0 "$($K queue lag events e2e-billing | jget 'd["data"]["lag"]')"
check "kafka groups lists the group's topic" "['e2e-orders']" "$($K queue groups events | jget '[g["topics"] for g in d["data"]["groups"] if g["name"] == "e2e-billing"][0]')"
check "kafka peek --idle is a Kafka flag" 2 "$($K queue peek events e2e-orders --idle 2s | jget 'd["data"]["count"]')"

# a person purges and removes by typing the topic's name; a wrong one stops it
pty() { ptyrun "$1" env NO_COLOR=1 TERM=dumb "$K" -o text "${@:2}" | tr -d '\r'; }
O=$(pty 'wrong\n' queue purge events e2e-orders); RC=$?
check "kafka person: purge names the topic" 1 "$(grep -q 'This deletes every message in e2e-orders' <<<"$O" && echo 1)"
check "kafka person: purge asks for the name" 1 "$(grep -c 'Type the name e2e-orders to continue' <<<"$O")"
check "kafka person: a wrong name stops purge (6)" 6 "$RC"
check "kafka person: the messages are still there" 2 "$($K queue describe events e2e-orders | jget 'd["data"]["messages"]')"
pty 'e2e-orders\n' queue purge events e2e-orders >/dev/null
check "kafka person: the right name purges" 0 "$($K queue describe events e2e-orders | jget 'd["data"]["messages"]')"
pty 'e2e-audit\n' queue rm events e2e-audit >/dev/null
check "kafka person: the right name removes the topic" TOPIC_NOT_FOUND "$($K queue describe events e2e-audit | jget 'd["error"]["code"]')"
q $K queue rm events e2e-orders --allow-dangerous
q $K conn rm events
set -e
