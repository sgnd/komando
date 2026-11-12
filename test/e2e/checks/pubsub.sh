# shellcheck shell=bash
# Google Cloud Pub/Sub through --via bastion, answered by the emulator:
# conn test, a topic and a subscription are created (dry run first),
# messages go in, peek pulls them and gives every one back, and purge and
# rm need --allow-dangerous.
set +e
q $K conn add pubsub1 'pubsub://test-project?endpoint=http://pubsub:8085' --via bastion
for _ in $(seq 1 60); do [ "$($K conn test pubsub1 | jget 'd["data"]["results"][0]["ok"]' 2>/dev/null)" = True ] && break; sleep 1; done
check "pubsub conn test through --via" login "$($K conn test pubsub1 | jget 'd["data"]["results"][0]["detail"]["check"]')"
check "pubsub http endpoint across the network is refused" INSECURE_PROTOCOL "$($K conn add gcp-plain 'pubsub://test-project?endpoint=http://pubsub.example.com:8085' | jget 'd["error"]["code"]')"
check "pubsub info names the project" test-project "$($K queue info pubsub1 | jget 'd["data"]["project"]')"
check "pubsub create --dry-run makes nothing" TOPIC_NOT_FOUND "$($K --dry-run queue create pubsub1 e2e-orders >/dev/null; $K queue describe pubsub1 e2e-orders | jget 'd["error"]["code"]')"
check "pubsub create topic" projects/test-project/topics/e2e-orders "$($K queue create pubsub1 e2e-orders | jget 'd["data"]["full_name"]')"
check "pubsub create twice" TOPIC_EXISTS "$($K queue create pubsub1 e2e-orders | jget 'd["error"]["code"]')"
check "pubsub create subscription" e2e-orders "$($K queue create pubsub1 subscriptions/e2e-billing --config topic=e2e-orders --config ackDeadlineSeconds=20 | jget 'd["data"]["of_topic"]')"
q $K queue send pubsub1 e2e-orders --value '{"id": 1}' --header source=e2e
q $K queue send pubsub1 e2e-orders --value '{"id": 2}' --key k1
check "pubsub peek of a topic points to its subscriptions" SUBSCRIPTION_NOT_FOUND "$($K queue peek pubsub1 e2e-orders | jget 'd["error"]["code"]')"
check "pubsub peek pulls and gives back" "2 True" "$($K queue peek pubsub1 e2e-billing | jget '"%d %s" % (d["data"]["count"], d["data"]["requeued"])')"
check "pubsub peek again sees the same messages" 2 "$($K queue peek pubsub1 e2e-billing | jget 'd["data"]["count"]')"
check "pubsub peek --wait is for Kafka" NOT_SUPPORTED "$($K queue peek pubsub1 e2e-billing --wait 2s | jget 'd["error"]["code"]')"
check "pubsub ls -n 1 is cut and says so" "1 True" "$($K queue create pubsub1 e2e-zz >/dev/null; $K queue ls pubsub1 'e2e-*' -n 1 | jget '"%d %s" % (d["data"]["count"], d["data"].get("truncated"))')"
check "pubsub describe lists the subscription" e2e-billing "$($K queue describe pubsub1 e2e-orders | jget 'd["data"]["subscription_info"][0]["subscription"]')"
check "pubsub groups lists subscriptions" pull "$($K queue groups pubsub1 | jget '[g for g in d["data"]["groups"] if g["name"] == "e2e-billing"][0]["delivery"]')"
check "pubsub lag is not supported" NOT_SUPPORTED "$($K queue lag pubsub1 e2e-billing | jget 'd["error"]["code"]')"
check "pubsub purge needs --allow-dangerous" POLICY_BLOCKED "$($K queue purge pubsub1 e2e-billing | jget 'd["error"]["code"]')"
check "pubsub rm needs --allow-dangerous" POLICY_BLOCKED "$($K queue rm pubsub1 e2e-orders | jget 'd["error"]["code"]')"
check "pubsub purge empties the subscription" 0 "$($K queue purge pubsub1 e2e-billing --allow-dangerous >/dev/null; $K queue peek pubsub1 e2e-billing | jget 'd["data"]["count"]')"
q $K queue rm pubsub1 subscriptions/e2e-billing e2e-orders --allow-dangerous
O=$(ptyrun 'pubsub1\n' env NO_COLOR=1 TERM=dumb "$K" -o text queue rm pubsub1 e2e-zz | tr -d '\r')
check "pubsub person: rm names the topic and removes it" "1 TOPIC_NOT_FOUND" "$(grep -c 'deletes e2e-zz and every message in it' <<<"$O") $($K queue describe pubsub1 e2e-zz | jget 'd["error"]["code"]')"
q $K conn rm pubsub1
set -e
