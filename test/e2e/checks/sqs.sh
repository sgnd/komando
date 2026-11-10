# shellcheck shell=bash
# Amazon SQS through --via bastion, answered by the lab's moto: conn test
# logs in (keys in the URL, then an AWS profile), a queue is created (dry
# run first), messages go in, peek receives them with a visibility timeout
# of 0 and takes none away, and purge and rm need --allow-dangerous.
set +e
echo -n test | $K secret set sqs-secret >/dev/null
printf '[e2e-sqs]\naws_access_key_id = test\naws_secret_access_key = test\n' > "$TMP/aws-sqs-credentials"
SQSENV=(env AWS_SHARED_CREDENTIALS_FILE="$TMP/aws-sqs-credentials" AWS_CONFIG_FILE=/dev/null AWS_EC2_METADATA_DISABLED=true)
q $K conn add sqs 'sqs://test@us-east-1?endpoint=http://moto:5000' --via bastion --password-ref secret:sqs-secret
q $K conn add sqs-profile 'sqs://us-east-1?endpoint=http://moto:5000' --via bastion --option aws_profile=e2e-sqs
check "sqs conn test logs in with keys through --via" login "$($K conn test sqs | jget 'd["data"]["results"][0]["detail"]["check"]')"
check "sqs conn test logs in with an AWS profile" login "$("${SQSENV[@]}" $K conn test sqs-profile | jget 'd["data"]["results"][0]["detail"]["check"]')"
check "sqs http endpoint across the network is refused" INSECURE_PROTOCOL "$($K conn add sqs-plain 'sqs://us-east-1?endpoint=http://sqs.example.com' | jget 'd["error"]["code"]')"
check "sqs info names the region" us-east-1 "$($K queue info sqs | jget 'd["data"]["region"]')"
check "sqs create --dry-run makes nothing" QUEUE_NOT_FOUND "$($K --dry-run queue create sqs e2e-orders >/dev/null; $K queue describe sqs e2e-orders | jget 'd["error"]["code"]')"
check "sqs create" False "$($K queue create sqs e2e-orders --config VisibilityTimeout=60 | jget 'd["data"]["fifo"]')"
check "sqs create twice" QUEUE_EXISTS "$($K queue create sqs e2e-orders | jget 'd["error"]["code"]')"
q $K queue send sqs e2e-orders --value '{"id": 1}' --header source=e2e
q $K queue send sqs e2e-orders --value '{"id": 2}'
check "sqs send to a FIFO queue needs --key" USAGE "$($K queue create sqs e2e-orders.fifo >/dev/null; $K queue send sqs e2e-orders.fifo --value x | jget 'd["error"]["code"]')"
check "sqs send to a FIFO queue with --key" g1 "$($K queue send sqs e2e-orders.fifo --value x --key g1 | jget 'd["data"]["message_group_id"]')"
check "sqs peek receives a sample" 2 "$("${SQSENV[@]}" $K queue peek sqs-profile e2e-orders | jget 'd["data"]["count"]')"
check "sqs peek hides and takes nothing" "2 0" "$($K queue peek sqs e2e-orders >/dev/null; $K queue describe sqs e2e-orders | jget '"%d %d" % (d["data"]["messages"], d["data"]["in_flight"])')"
check "sqs peek --oldest is not supported" NOT_SUPPORTED "$($K queue peek sqs e2e-orders --oldest | jget 'd["error"]["code"]')"
check "sqs groups is not supported" NOT_SUPPORTED "$($K queue groups sqs | jget 'd["error"]["code"]')"
check "sqs ls" 2 "$($K queue ls sqs 'e2e-orders*' | jget 'd["data"]["count"]')"
check "sqs purge needs --allow-dangerous" POLICY_BLOCKED "$($K queue purge sqs e2e-orders | jget 'd["error"]["code"]')"
check "sqs rm needs --allow-dangerous" POLICY_BLOCKED "$($K queue rm sqs e2e-orders | jget 'd["error"]["code"]')"
check "sqs purge --dry-run counts" 2 "$($K --dry-run queue purge sqs e2e-orders | jget 'd["data"]["messages"]')"
q $K queue rm sqs e2e-orders e2e-orders.fifo --allow-dangerous
q $K conn rm sqs
q $K conn rm sqs-profile
set -e
