# shellcheck shell=bash
# AWS paths without an AWS account. komando talks to AWS itself (SDK, SSO
# cache, Session Manager); the lab's moto answers for ECR. For `--ssm` a fake
# `aws` and session-manager-plugin stand in for the CLI (`aws ssm
# start-session` becomes a plain TCP pipe to the lab's SSH server), so the
# CLI path stays tested; without them komando's own client is used.
mkdir -p "$TMP/fakeaws"
cat >"$TMP/fakeaws/aws" <<EOF
#!/bin/sh
# ssm start-session --target ID --document-name AWS-StartSSHSession --parameters portNumber=22
if [ "\$1 \$2" = "ssm start-session" ]; then exec nc 127.0.0.1 $E2E_SSH_DIRECT; fi
echo "fake aws: \$*" >&2; exit 2
EOF
printf '#!/bin/sh\nexit 0\n' > "$TMP/fakeaws/session-manager-plugin"
chmod +x "$TMP/fakeaws/aws" "$TMP/fakeaws/session-manager-plugin"
AWSK() { PATH="$TMP/fakeaws:$PATH" $K "$@"; }

q $K host add t-ssm agent@i-0abc123def --ssm --password-ref secret:agent-pass
check "SSM: login and run a command through aws ssm start-session" direct \
  "$(AWSK exec t-ssm --read-only -- hostname | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "SSM: files over the same path" True "$(AWSK fs ls t-ssm /tmp | jget 'd["ok"]')"
check "SSM: without the aws CLI, komando's own client says what it needs" SSM_FAILED \
  "$(env PATH=/usr/bin:/bin AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_EC2_METADATA_DISABLED=true AWS_ACCESS_KEY_ID= AWS_PROFILE= \
     $K exec t-ssm --read-only -- true | jget 'd["error"]["code"] if "error" in d else d["data"]["results"][0]["error"]["code"]' || true)"
q $K host rm t-ssm

# an SSO profile with no valid login: a person logs in again
cat >"$TMP/aws-sso-config" <<'EOF'
[profile e2e-sso]
sso_session = corp
sso_account_id = 111122223333
sso_role_name = Admin
region = us-east-1
[sso-session corp]
sso_start_url = https://e2e-nowhere.awsapps.com/start
sso_region = us-east-1
EOF
q $K conn add t-aws-expired "s3://backups/e2e?endpoint=http://s3:3900&region=garage" --via bastion --option aws_profile=e2e-sso
check "an SSO profile without a valid login is AWS_LOGIN_REQUIRED" AWS_LOGIN_REQUIRED \
  "$(env AWS_CONFIG_FILE="$TMP/aws-sso-config" AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_EC2_METADATA_DISABLED=true $K storage ls t-aws-expired | jget 'd["error"]["code"]' || true)"
check "the hint says how to log in" True \
  "$(env AWS_CONFIG_FILE="$TMP/aws-sso-config" AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_EC2_METADATA_DISABLED=true $K storage ls t-aws-expired | jget '"komando login aws --profile e2e-sso" in d["error"]["hint"]' || true)"
q $K conn rm t-aws-expired

# komando login aws is for a person: an agent gets NEEDS_PERSON (exit 6) with
# the exact command; a person's dry run shows the sign-in page, logs in to
# nothing, and runs in a real terminal
set +e
AL=$(AWS_CONFIG_FILE="$TMP/aws-sso-config" AWS_SHARED_CREDENTIALS_FILE=/dev/null A login aws --profile e2e-sso </dev/null); RC=$?
set -e
check "login aws: an agent gets NEEDS_PERSON" NEEDS_PERSON "$(jget 'd["error"]["code"]' <<<"$AL" || true)"
check "login aws: exit 6 for the agent" 6 "$RC"
check "login aws: the hint is the person's command" True "$(jget '"`komando login aws --profile e2e-sso`" in d["error"]["hint"]' <<<"$AL" || true)"
check "login aws: an agent's dry run is not blocked" NEEDS_PERSON \
  "$(AWS_CONFIG_FILE="$TMP/aws-sso-config" AWS_SHARED_CREDENTIALS_FILE=/dev/null A --dry-run login aws --profile e2e-sso </dev/null | jget 'd["meta"]["would_be_blocked"]["code"]' || true)"
O=$(ptyrun "" env NO_COLOR=1 TERM=dumb AWS_CONFIG_FILE="$TMP/aws-sso-config" AWS_SHARED_CREDENTIALS_FILE=/dev/null "$K" -o text --dry-run login aws --profile e2e-sso | tr -d '\r')
check "person: login aws --dry-run shows the SSO start page" 1 "$(grep -c 'sso_start_url: https://e2e-nowhere.awsapps.com/start' <<<"$O")"

# import aws-ec2: a server per running EC2 instance, read from moto with the
# profile's keys (the instance is made with curl's own SigV4)
curl -sf --aws-sigv4 "aws:amz:us-east-1:ec2" --user test:test "http://127.0.0.1:$E2E_MOTO/" \
  -d 'Action=RunInstances&Version=2016-11-15&ImageId=ami-12c6146b&MinCount=1&MaxCount=1&TagSpecification.1.ResourceType=instance&TagSpecification.1.Tag.1.Key=Name&TagSpecification.1.Tag.1.Value=e2e-ec2' >/dev/null ||
  echo "  (could not start an instance in moto)"
printf '[profile e2e-ec2]\nregion = us-east-1\nendpoint_url = http://127.0.0.1:%s\n' "$E2E_MOTO" > "$TMP/aws-ec2-config"
printf '[e2e-ec2]\naws_access_key_id = test\naws_secret_access_key = test\n' > "$TMP/credentials"
EC2ENV=(env AWS_CONFIG_FILE="$TMP/aws-ec2-config" AWS_SHARED_CREDENTIALS_FILE="$TMP/credentials" AWS_EC2_METADATA_DISABLED=true AWS_PROFILE=)
check "import aws-ec2 --dry-run finds the instance" True "$("${EC2ENV[@]}" $K import aws-ec2 "$TMP/aws-ec2-config" --dry-run | jget '"e2e-ec2" in json.dumps(d["data"])')"
q "${EC2ENV[@]}" $K import aws-ec2 "$TMP/aws-ec2-config"
check "import aws-ec2 groups it by region" True "$($K host show e2e-ec2 | jget '"us-east-1" in d["data"]["groups"] and d["data"]["labels"]["aws-instance"].startswith("i-")')"
q $K host rm e2e-ec2
rm -f "$TMP/credentials"

# a role assumed from static keys through STS (moto): komando's own STS
# call gives the role's keys, which then list the bucket
curl -sf -X PUT --aws-sigv4 "aws:amz:us-east-1:s3" --user test:test "http://127.0.0.1:$E2E_MOTO/e2e-sts" >/dev/null ||
  curl -sf -X PUT "http://127.0.0.1:$E2E_MOTO/e2e-sts" >/dev/null || echo "  (could not create the e2e-sts bucket in moto)"
printf '[profile e2e-role]\nrole_arn = arn:aws:iam::123456789012:role/e2e\nsource_profile = e2e-src\nregion = us-east-1\n' >"$TMP/aws-role-config"
printf '[e2e-src]\naws_access_key_id = test\naws_secret_access_key = test\n' >"$TMP/aws-role-credentials"
ROLEENV=(env PATH=/usr/bin:/bin AWS_CONFIG_FILE="$TMP/aws-role-config" AWS_SHARED_CREDENTIALS_FILE="$TMP/aws-role-credentials" AWS_EC2_METADATA_DISABLED=true)
q $K conn add t-aws-role "s3://e2e-sts?endpoint=http://127.0.0.1:$E2E_MOTO&region=us-east-1" --option aws_profile=e2e-role
check "STS: a role from source_profile keys lists the bucket (moto)" True \
  "$("${ROLEENV[@]}" AWS_ENDPOINT_URL="http://127.0.0.1:$E2E_MOTO" $K storage ls t-aws-role | jget 'd["ok"] or d["error"]["code"] + ": " + d["error"]["message"]' || true)"
check "STS: a refused role is AWS_FAILED, not a login" AWS_FAILED \
  "$("${ROLEENV[@]}" AWS_ENDPOINT_URL=http://127.0.0.1:1 AWS_MAX_ATTEMPTS=1 $K storage ls t-aws-role | jget 'd["error"]["code"]' || true)"
q $K conn rm t-aws-role

# Amazon ECR: a fresh login from the ECR API (moto here) on every call,
# with the region from the host name and the conn's aws_profile
printf '[e2e]\naws_access_key_id = test\naws_secret_access_key = test\n' > "$TMP/aws-ecr-credentials"
ECRENV=(env PATH=/usr/bin:/bin AWS_SHARED_CREDENTIALS_FILE="$TMP/aws-ecr-credentials" AWS_CONFIG_FILE=/dev/null AWS_ENDPOINT_URL="http://127.0.0.1:$E2E_MOTO" AWS_EC2_METADATA_DISABLED=true)
q $K conn add t-ecr "registry://AWS@123456789012.dkr.ecr.us-east-1.amazonaws.com:5000?tls=false" --via bastion --option aws_profile=e2e
check "ECR: registry ls with a login from the ECR API, no aws CLI" True "$("${ECRENV[@]}" $K registry ls t-ecr | jget 'd["ok"]')"
check "ECR: an unknown profile is named" AWS_PROFILE_NOT_FOUND \
  "$(env PATH=/usr/bin:/bin AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_CONFIG_FILE=/dev/null $K registry ls t-ecr | jget 'd["error"]["code"]' || true)"
q $K conn rm t-ecr
