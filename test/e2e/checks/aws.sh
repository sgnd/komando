# AWS paths without an AWS account: a fake `aws` stands in for the CLI,
# so komando's side is tested end to end. `aws ssm start-session` becomes a
# plain TCP pipe to the lab's SSH server; `aws configure export-credentials`
# answers like an expired SSO login.
mkdir -p "$TMP/fakeaws"
cat >"$TMP/fakeaws/aws" <<EOF
#!/bin/sh
# ssm start-session --target ID --document-name AWS-StartSSHSession --parameters portNumber=22
if [ "\$1 \$2" = "ssm start-session" ]; then exec nc 127.0.0.1 $E2E_SSH_DIRECT; fi
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
