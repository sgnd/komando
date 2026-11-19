# shellcheck shell=bash
# host ca: a server whose host certificate a trusted CA signed, for the name
# komando dials, is trusted with no pin; a certificate with no principals
# (ssh-keygen without -n, valid for every name in OpenSSH) is refused. The
# target container serves the certificates, as web.corp.example behind the
# bastion. Host keys are strict here, so a refused certificate cannot fall
# back to a pin made on first use.
TGT="$PROJECT-target-1"
rm -f "$TMP/hostca" "$TMP/hostca.pub" "$TMP/tgt_host.pub"
ssh-keygen -q -t ed25519 -N '' -C lab-host-ca -f "$TMP/hostca"
docker cp "$TGT:/etc/ssh/ssh_host_ed25519_key.pub" "$TMP/tgt_host.pub" >/dev/null
# hostcert [-n NAMES]: sign the target's host key with the lab CA and serve it
hostcert() {
  rm -f "$TMP/tgt_host-cert.pub"
  ssh-keygen -q -s "$TMP/hostca" -h -I lab-web "$@" -V -5m:+1h "$TMP/tgt_host.pub"
  docker cp "$TMP/tgt_host-cert.pub" "$TGT:/etc/ssh/ssh_host_ed25519_key-cert.pub" >/dev/null
  docker exec "$TGT" sh -c 'echo "HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub" >/etc/ssh/sshd_config.d/hostca.conf && kill -HUP 1'
  sleep 1
}
set +e
hostcert -n web.corp.example
ptyrun '' env NO_COLOR=1 TERM=dumb "$K" host ca add lab --key "$TMP/hostca.pub" --hosts '*.corp.example' >/dev/null
check "host ca: a person adds the lab CA" lab "$($K host ca list | jget 'd["data"]["items"][0]["name"]')"
$K host add t-hostca agent@web.corp.example --via bastion --password-ref secret:agent-pass >/dev/null
$K --host-key-policy strict exec t-hostca -- true >/dev/null
check "host ca: a certificate for the dialled name is trusted with no pin" 0 $?
check "host ca: host show names the CA" lab "$($K host show t-hostca | jget 'd["data"]["host_ca"]')"
hostcert
check "host ca: a certificate with no principals is refused" HOSTKEY_UNKNOWN "$($K --host-key-policy strict exec t-hostca -- true | jget 'd["error"]["code"]')"
docker exec "$TGT" sh -c 'rm -f /etc/ssh/sshd_config.d/hostca.conf /etc/ssh/ssh_host_ed25519_key-cert.pub && kill -HUP 1'
$K host rm t-hostca --yes >/dev/null
$K host ca rm lab --yes >/dev/null
set -e
