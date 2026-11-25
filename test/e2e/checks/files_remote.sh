# shellcheck shell=bash
# Files rows C69, C70, C71 against real servers: storage s3 object create, mv and
# chmod on S3 (Garage), SFTP and FTPS; cp between two servers, a server and
# a bucket, and two conns; --continue on upload, download and cp. Uses
# t-e2eops/ keys and /tmp/e2eops paths, and removes them at the end.
set +e
q $K conn add files-sftp 'sftp://deploy@sftp/uploads' --via bastion --password-ref secret:files-pass
q $K conn add files-ftps 'ftps://deploy@ftps/www?tls=skip-verify' --via bastion --password-ref secret:files-pass
echo e2eops > "$TMP/e2eops.txt"

echo "==> storage s3 object create, mv, chmod"
for c in bucket files-sftp files-ftps; do
  check "$c mkdir --dry-run" True "$($K storage s3 object create "$c" t-e2eops/new/deep --dry-run | jget 'd["data"]["created"] and d["data"]["dry_run"]')"
  check "$c mkdir" True "$($K storage s3 object create "$c" t-e2eops/new/deep | jget 'd["data"]["created"]')"
  check "$c mkdir again" False "$($K storage s3 object create "$c" t-e2eops/new/deep | jget 'd["data"]["created"]')"
  check "$c the empty folder lists" 0 "$($K storage s3 object list "$c" t-e2eops/new/deep/ | jget 'd["data"]["count"]')"
  q $K storage upload "$c" "$TMP/e2eops.txt" t-e2eops/a.txt
  q $K storage upload "$c" "$TMP/e2eops.txt" t-e2eops/b.txt
  check "$c mv --dry-run" True "$($K storage s3 object move "$c" t-e2eops/a.txt t-e2eops/new/ --dry-run | jget 'd["data"]["dry_run"]')"
  check "$c mv --dry-run changes nothing" True "$($K storage s3 object read "$c" t-e2eops/a.txt | jget 'd["ok"]')"
  check "$c mv into a folder" t-e2eops/new/a.txt "$($K storage s3 object move "$c" t-e2eops/a.txt t-e2eops/new/ | jget 'd["data"]["dst"]')"
  check "$c mv took it away" OBJECT_NOT_FOUND "$($K storage s3 object read "$c" t-e2eops/a.txt | jget 'd["error"]["code"]')"
  check "$c mv over a file stops" FILE_EXISTS "$($K storage s3 object move "$c" t-e2eops/b.txt t-e2eops/new/a.txt | jget 'd["error"]["code"]')"
  check "$c mv --overwrite" True "$($K storage s3 object move "$c" t-e2eops/b.txt t-e2eops/new/a.txt --overwrite | jget 'd["data"]["replaced"]')"
  check "$c mv over a file keeps no aside copy" "['t-e2eops/new/a.txt', 't-e2eops/new/deep/']" "$($K storage s3 object list "$c" t-e2eops/new/ | jget 'sorted(o["key"] for o in d["data"]["objects"])')"
done
check "bucket mv is a checked copy" copy_then_delete "$($K storage s3 object move bucket t-e2eops/new/a.txt t-e2eops/c.txt | jget 'd["data"]["method"]')"
check "bucket mv of a folder is refused" STORAGE_UNSUPPORTED "$($K storage s3 object move bucket t-e2eops/new t-e2eops/old | jget 'd["error"]["code"]')"
check "sftp mv of a folder" True "$($K storage s3 object move files-sftp t-e2eops/new t-e2eops/old | jget 'd["data"]["folder"]')"
check "sftp chmod" "0640 0644" "$($K storage sftp object move files-sftp t-e2eops/old/a.txt --mode 0640 | jget 'd["data"]["mode"] + " " + d["data"]["old_mode"]')"
check "sftp chmod again says the new mode" 0640 "$($K storage sftp object move files-sftp t-e2eops/old/a.txt --mode 0600 --dry-run | jget 'd["data"]["old_mode"]')"
check "chmod on a bucket is refused" STORAGE_UNSUPPORTED "$($K storage s3 object move bucket t-e2eops/c.txt --mode 0640 | jget 'd["error"]["code"]')"

echo "==> cp between two remote places"
dd if=/dev/urandom of="$TMP/e2eops.bin" bs=1048576 count=6 2>/dev/null
SUM=$(shasum -a 256 "$TMP/e2eops.bin" | cut -c1-64)
q $K upload direct "$TMP/e2eops.bin" /tmp/e2eops/src.bin -p
check "cp --dry-run names both sides" "direct:/tmp/e2eops/src.bin bastion:/tmp/e2eops/" "$($K cp direct:/tmp/e2eops/src.bin bastion:/tmp/e2eops/ --dry-run | jget 'd["data"]["src"] + " " + d["data"]["dst"]')"
check "cp server to server" "$SUM" "$($K cp direct:/tmp/e2eops/src.bin bastion:/tmp/e2eops/ -p | jget 'd["data"]["results"][0]["sha256"]')"
check "cp server to server arrived" "$SUM" "$($K -o text exec bastion --read-only -- sha256sum /tmp/e2eops/src.bin | cut -c1-64)"
check "cp server to bucket" "$SUM" "$($K cp direct:/tmp/e2eops/src.bin bucket:t-e2eops/src.bin | jget 'd["data"]["results"][0]["sha256"]')"
check "cp bucket to sftp conn" "$SUM" "$($K cp bucket:t-e2eops/src.bin files-sftp:t-e2eops/src.bin | jget 'd["data"]["results"][0]["sha256"]')"
check "cp sftp conn to server" "$SUM" "$($K cp files-sftp:t-e2eops/src.bin direct:/tmp/e2eops/back.bin | jget 'd["data"]["results"][0]["sha256"]')"
check "cp bucket to server arrived" "$SUM" "$($K -o text exec direct --read-only -- sha256sum /tmp/e2eops/back.bin | cut -c1-64)"
mkdir -p "$TMP/e2eops-tree/sub" && echo one > "$TMP/e2eops-tree/a.txt" && echo two > "$TMP/e2eops-tree/sub/b.txt"
q $K upload direct "$TMP/e2eops-tree" /tmp/e2eops/tree -r
check "cp -r server to bucket" 2 "$($K cp -r direct:/tmp/e2eops/tree bucket:t-e2eops/ | jget 'd["data"]["results"][0]["files"]')"
check "cp -r bucket to ftps conn" 2 "$($K cp -r bucket:t-e2eops/tree files-ftps:t-e2eops/ | jget 'd["data"]["results"][0]["files"]')"
check "cp -r arrived" two "$($K storage s3 object read files-ftps t-e2eops/tree/sub/b.txt | jget 'd["data"]["content"].strip()')"

echo "==> --continue"
head -c 2500000 "$TMP/e2eops.bin" > "$TMP/e2eops.part"
q $K upload direct "$TMP/e2eops.part" /tmp/e2eops/cont.bin
check "upload --continue goes on" "2500000 $SUM" "$($K upload direct "$TMP/e2eops.bin" /tmp/e2eops/cont.bin --continue | jget 'str(d["data"]["results"][0]["continued_from_bytes"]) + " " + d["data"]["results"][0]["sha256"]')"
cp "$TMP/e2eops.part" "$TMP/e2eops.down"
check "download --continue goes on" "2500000 $SUM" "$($K download direct /tmp/e2eops/cont.bin --to "$TMP/e2eops.down" --continue | jget 'str(d["data"]["results"][0]["continued_from_bytes"]) + " " + d["data"]["results"][0]["sha256"]')"
check "download --continue got the whole file" "$SUM" "$(shasum -a 256 "$TMP/e2eops.down" | cut -c1-64)"
printf X | dd of="$TMP/e2eops.down" bs=1 seek=10 conv=notrunc 2>/dev/null
check "download --continue refuses a file that differs" RESUME_CONFLICT "$($K download direct /tmp/e2eops/cont.bin --to "$TMP/e2eops.down" --continue | jget 'd["data"]["results"][0]["error"]["code"]')"
q $K upload files-sftp "$TMP/e2eops.part" t-e2eops/cont.bin
check "storage upload --continue to sftp (no shell: read back)" 2500000 "$($K storage upload files-sftp "$TMP/e2eops.bin" t-e2eops/cont.bin --continue | jget 'd["data"]["continued_from_bytes"]')"
q $K upload files-ftps "$TMP/e2eops.part" t-e2eops/cont.bin
check "storage upload --continue to ftps" 2500000 "$($K storage upload files-ftps "$TMP/e2eops.bin" t-e2eops/cont.bin --continue | jget 'd["data"]["continued_from_bytes"]')"
check "storage upload --continue arrived" "$SUM" "$($K cp files-ftps:t-e2eops/cont.bin bucket:t-e2eops/cont-check.bin | jget 'd["data"]["results"][0]["sha256"]')"
q $K upload bucket "$TMP/e2eops.part" t-e2eops/cut.bin
check "upload --continue to a bucket is refused" RESUME_UNSUPPORTED "$($K upload bucket "$TMP/e2eops.bin" t-e2eops/cut.bin --continue | jget 'd["error"]["code"]')"
q $K exec direct -- truncate -s 1000000 /tmp/e2eops/back.bin
check "cp --continue between two remote places" "1000000 $SUM" "$($K cp files-sftp:t-e2eops/src.bin direct:/tmp/e2eops/back.bin --continue | jget 'str(d["data"]["results"][0]["continued_from_bytes"]) + " " + d["data"]["results"][0]["sha256"]')"

echo "==> streams (--to -, upload -)"
check "download --to - from a server is the file" "$SUM" "$($K download direct /tmp/e2eops/src.bin --to - 2>/dev/null | shasum -a 256 | cut -c1-64)"
check "download --to - says the result on stderr" "$SUM" "$($K download direct /tmp/e2eops/src.bin --to - 2>&1 >/dev/null | jget 'd["data"]["sha256"]')"
check "download --to - from a bucket is the file" "$SUM" "$($K download bucket t-e2eops/src.bin --to - 2>/dev/null | shasum -a 256 | cut -c1-64)"
check "download --to - from sftp is the file" "$SUM" "$($K storage download files-sftp t-e2eops/src.bin --to - 2>/dev/null | shasum -a 256 | cut -c1-64)"
check "cp TARGET:PATH - is the file" "$SUM" "$($K cp direct:/tmp/e2eops/src.bin - 2>/dev/null | shasum -a 256 | cut -c1-64)"
check "a missing file: nothing on stdout" 0 "$($K download direct /tmp/e2eops/nope --to - 2>/dev/null | wc -c | tr -d ' ')"
check "a missing file: the error on stderr" PATH_NOT_FOUND "$($K download direct /tmp/e2eops/nope --to - 2>&1 >/dev/null | jget 'd["error"]["code"]' || true)"
check "upload - to a server" "$SUM" "$($K upload direct - /tmp/e2eops/stdin.bin --size "$(wc -c < "$TMP/e2eops.bin" | tr -d ' ')" < "$TMP/e2eops.bin" | jget 'd["data"]["results"][0]["sha256"]')"
check "upload - to a server arrived" "$SUM" "$($K -o text exec direct --read-only -- sha256sum /tmp/e2eops/stdin.bin | cut -c1-64)"
check "upload - with a short stream" SIZE_CONFLICT "$(head -c 1000 "$TMP/e2eops.bin" | $K upload direct - /tmp/e2eops/stdin.bin --size 5000 | jget 'd["data"]["results"][0]["error"]["code"]' || true)"
check "a short stream replaced nothing" "$SUM" "$($K -o text exec direct --read-only -- sha256sum /tmp/e2eops/stdin.bin | cut -c1-64)"
for c in bucket files-sftp files-ftps; do
  check "$c storage upload -" "$SUM" "$($K storage upload "$c" - t-e2eops/stdin.bin < "$TMP/e2eops.bin" | jget 'd["data"]["sha256"]')"
  check "$c storage upload - arrived" "$SUM" "$($K storage download "$c" t-e2eops/stdin.bin --to - 2>/dev/null | shasum -a 256 | cut -c1-64)"
  check "$c storage upload - sending more than --size" SIZE_CONFLICT "$($K storage upload "$c" - t-e2eops/stdin.bin --size 10 < "$TMP/e2eops.bin" | jget 'd["error"]["code"]' || true)"
  check "$c a long stream replaced nothing" "$SUM" "$($K storage download "$c" t-e2eops/stdin.bin --to - 2>/dev/null | shasum -a 256 | cut -c1-64)"
done
check "an agent's stream shows secret values as [hidden]" True "$(printf 'API_TOKEN=s3cr3t-e2e-value\n' | $K upload direct - /tmp/e2eops/app.conf >/dev/null; A download direct /tmp/e2eops/app.conf --to - 2>/dev/null | python3 -c 'import sys; s=sys.stdin.read(); print("s3cr3t-e2e-value" not in s)')"

for c in bucket files-sftp files-ftps; do q $K storage s3 object delete "$c" --prefix t-e2eops/ --allow-dangerous; done
q $K exec direct --allow-dangerous -- rm -rf /tmp/e2eops
q $K exec bastion --allow-dangerous -- rm -rf /tmp/e2eops
q $K conn rm files-sftp files-ftps
rm -rf "$TMP"/e2eops*
set -e
