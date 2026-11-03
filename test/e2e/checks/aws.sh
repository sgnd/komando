# AWS paths without an AWS account: a fake `aws` stands in for the CLI,
# so komando's side is tested end to end. `aws ssm start-session` becomes a
# plain TCP pipe to the lab's SSH server; `aws configure export-credentials`
# answers like an expired SSO login, and `aws ecr get-login-password` hands
# out a token (the lab registry also answers to an ECR-style name).
mkdir -p "$TMP/fakeaws"
cat >"$TMP/fakeaws/aws" <<EOF
#!/bin/sh
# ssm start-session --target ID --document-name AWS-StartSSHSession --parameters portNumber=22
if [ "\$1 \$2" = "ssm start-session" ]; then exec nc 127.0.0.1 $E2E_SSH_DIRECT; fi
if [ "\$1 \$2" = "ecr get-login-password" ]; then echo "\$*" >>"$TMP/fakeaws/ecr.calls"; echo ecr-token-1; exit 0; fi
if [ "\$1 \$2" = "configure export-credentials" ]; then
  echo "Error when retrieving token from sso: Token has expired and refresh failed" >&2; exit 255
fi
echo "fake aws: \$*" >&2; exit 2
EOF
chmod +x "$TMP/fakeaws/aws"
AWSK() { PATH="$TMP/fakeaws:$PATH" $K "$@"; }

q $K host add t-ssm agent@i-0abc123def --ssm --password-ref secret:agent-pass
check "SSM: login and run a command through aws ssm start-session" direct \
  "$(AWSK exec t-ssm --read-only -- hostname | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "SSM: files over the same path" True "$(AWSK fs ls t-ssm /tmp | jget 'd["ok"]')"
check "SSM: without the aws CLI the error says so" True \
  "$(PATH=/usr/bin:/bin $K exec t-ssm --read-only -- true | jget '"aws" in json.dumps(d["error"]).lower()' || true)"
q $K host rm t-ssm

q $K conn add t-aws-expired "s3://backups/e2e?endpoint=http://s3:3900&region=garage" --via bastion --option aws_profile=e2e
check "an expired SSO login is AWS_LOGIN_REQUIRED" AWS_LOGIN_REQUIRED "$(AWSK storage ls t-aws-expired | jget 'd["error"]["code"]' || true)"
q $K conn rm t-aws-expired

# Amazon ECR: a fresh login from `aws ecr get-login-password` on every call,
# with the region from the host name and the conn's aws_profile
q $K conn add t-ecr "registry://AWS@123456789012.dkr.ecr.us-east-1.amazonaws.com:5000?tls=false" --via bastion --option aws_profile=e2e
check "ECR: registry ls with a login from the aws CLI" True "$(AWSK registry ls t-ecr | jget 'd["ok"]')"
check "ECR: the login asked for the host's region and the conn's profile" True \
  "$(grep -q -- '--region us-east-1' "$TMP/fakeaws/ecr.calls" && grep -q -- '--profile e2e' "$TMP/fakeaws/ecr.calls" && echo True || echo False)"
check "ECR: a fresh login each time (no stored password)" 2 "$(AWSK registry ls t-ecr >/dev/null; wc -l <"$TMP/fakeaws/ecr.calls" | tr -d ' ')"
q $K conn rm t-ecr
