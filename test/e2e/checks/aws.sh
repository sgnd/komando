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
  "$(env AWS_CONFIG_FILE="$TMP/aws-sso-config" AWS_EC2_METADATA_DISABLED=true $K storage ls t-aws-expired | jget 'd["error"]["code"]' || true)"
check "the hint says how to log in" True \
  "$(env AWS_CONFIG_FILE="$TMP/aws-sso-config" AWS_EC2_METADATA_DISABLED=true $K storage ls t-aws-expired | jget '"komando login aws --profile e2e-sso" in d["error"]["hint"]' || true)"
q $K conn rm t-aws-expired

# Amazon ECR: a fresh login from the ECR API (moto here) on every call,
# with the region from the host name and the conn's aws_profile
printf '[e2e]\naws_access_key_id = test\naws_secret_access_key = test\n' > "$TMP/aws-ecr-credentials"
ECRENV=(env PATH=/usr/bin:/bin AWS_SHARED_CREDENTIALS_FILE="$TMP/aws-ecr-credentials" AWS_CONFIG_FILE=/dev/null AWS_ENDPOINT_URL="http://127.0.0.1:$E2E_MOTO" AWS_EC2_METADATA_DISABLED=true)
q $K conn add t-ecr "registry://AWS@123456789012.dkr.ecr.us-east-1.amazonaws.com:5000?tls=false" --via bastion --option aws_profile=e2e
check "ECR: registry ls with a login from the ECR API, no aws CLI" True "$("${ECRENV[@]}" $K registry ls t-ecr | jget 'd["ok"]')"
check "ECR: an unknown profile is named" AWS_PROFILE_NOT_FOUND \
  "$(env PATH=/usr/bin:/bin AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_CONFIG_FILE=/dev/null $K registry ls t-ecr | jget 'd["error"]["code"]' || true)"
q $K conn rm t-ecr
