# shellcheck shell=bash
# Google Cloud Storage, Azure Blob and WebDAV conns, against emulators
# reached through --via bastion: the same upload, list, download and rm
# steps as the other storage kinds. Uses t-e2ecloud/ objects and removes
# them at the end.
set +e

# Azurite checks every Shared Key signature and the SAS of a link (run
# against the real emulator), and makes the "media" container the conn uses.
for _ in $(seq 1 30); do curl -s -o /dev/null "http://127.0.0.1:$E2E_AZURITE/" && break; sleep 1; done
(cd "$ROOT" && KOMANDO_TEST_AZURITE="http://127.0.0.1:$E2E_AZURITE" KOMANDO_TEST_AZURITE_CONTAINER=media \
  go test -count=1 -run '^TestAzurite$' ./internal/storex/ >"$KOMANDO_HOME/azurite.log" 2>&1)
check "azure blob against Azurite (signatures, blocks, SAS link)" 0 $?

# Azurite's published development key (not a secret)
echo -n 'Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==' | $K secret set az-key >/dev/null
q $K conn add cloud-az 'azblob://devstoreaccount1@media/e2e?endpoint=http://azurite:10000/devstoreaccount1' --via bastion --password-ref secret:az-key
q $K conn add cloud-gcs 'gs://media/e2e?endpoint=http://gcs:4443' --via bastion
q $K conn add cloud-dav 'webdav://deploy@webdav:8080/e2e?insecure=1' --via bastion --password-ref secret:files-pass

check "conn test reaches azure blob through --via" True "$($K conn test cloud-az | jget 'd["data"]["results"][0]["ok"]')"
echo e2ecloud > "$TMP/e2ecloud.txt"
for c in cloud-az cloud-gcs cloud-dav; do
  check "$c upload into a folder keeps the name" t-e2ecloud/dir/e2ecloud.txt "$($K storage upload "$c" "$TMP/e2ecloud.txt" t-e2ecloud/dir/ | jget 'd["data"]["key"]')"
  check "$c upload dry-run says it replaces" True "$($K storage upload "$c" "$TMP/e2ecloud.txt" t-e2ecloud/dir/ --dry-run | jget 'd["data"]["replaced"]')"
  check "$c ls lists the folder" "['t-e2ecloud/dir/']" "$($K storage ls "$c" t-e2ecloud/ | jget '[o["key"] for o in d["data"]["objects"]]')"
  $K storage ls "$c" t-e2ecloud/nope/ >/dev/null; check "$c ls of a missing folder" 3 $?
  check "$c download to stdout" e2ecloud "$($K storage download "$c" t-e2ecloud/dir/e2ecloud.txt --to - -o text)"
  check "$c cat" e2ecloud "$($K storage cat "$c" t-e2ecloud/dir/e2ecloud.txt -o text)"
  q $K storage rm "$c" --prefix t-e2ecloud/ --allow-dangerous
  check "$c rm emptied the folder" 0 "$($K storage ls "$c" --recursive | jget 'len([o for o in d["data"]["objects"] if o["key"].startswith("t-e2ecloud/") and not o.get("dir")])')"
done
check "azure link through --via warns" True "$($K storage upload cloud-az "$TMP/e2ecloud.txt" t-e2ecloud/l.txt >/dev/null; $K storage link cloud-az t-e2ecloud/l.txt | jget '"bastion" in d["data"]["warning"]')"
check "webdav has no links" NOT_SUPPORTED "$($K storage upload cloud-dav "$TMP/e2ecloud.txt" t-e2ecloud/l.txt >/dev/null; $K storage link cloud-dav t-e2ecloud/l.txt | jget 'd["error"]["code"]')"
for c in cloud-az cloud-dav; do q $K storage rm "$c" --prefix t-e2ecloud/ --allow-dangerous; done
q $K conn rm cloud-az cloud-gcs cloud-dav
rm -f "$TMP/e2ecloud.txt"
set -e
