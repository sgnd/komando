# shellcheck shell=bash
# An SMB share (Samba with signing and encryption required) through --via
# bastion: the same upload, list, download and rm steps as the other storage
# kinds, a wrong share and the missing links. Uses t-e2esmb/ files and
# removes them at the end.
set +e
echo -n deploypass | $K credential password add smb-pass >/dev/null
q $K conn add smb-files 'smb://WORKGROUP;deploy@samba/files/e2e' --via bastion --password-ref secret:smb-pass
q $K conn add smb-noshare 'smb://deploy@samba/nope' --via bastion --password-ref secret:smb-pass
for _ in $(seq 1 30); do [ "$($K conn test smb-files | jget 'd["data"]["results"][0]["ok"]' 2>/dev/null)" = True ] && break; sleep 1; done
check "smb conn test reaches the share through --via" True "$($K conn test smb-files | jget 'd["data"]["results"][0]["ok"]')"
echo e2esmb > "$TMP/e2esmb.txt"
check "smb upload into a folder keeps the name" t-e2esmb/dir/e2esmb.txt "$($K storage upload smb-files "$TMP/e2esmb.txt" t-e2esmb/dir/ | jget 'd["data"]["key"]')"
check "smb upload again replaces" True "$($K storage upload smb-files "$TMP/e2esmb.txt" t-e2esmb/dir/ | jget 'd["data"]["replaced"]')"
check "smb ls lists the folder" "['t-e2esmb/dir/']" "$($K storage ls smb-files t-e2esmb/ | jget '[o["key"] for o in d["data"]["objects"]]')"
$K storage ls smb-files t-e2esmb/nope/ >/dev/null; check "smb ls of a missing folder" 3 $?
check "smb download to stdout" e2esmb "$($K storage download smb-files t-e2esmb/dir/e2esmb.txt --to - -o text)"
check "smb cat" e2esmb "$($K storage cat smb-files t-e2esmb/dir/e2esmb.txt -o text)"
check "smb has no links" NOT_SUPPORTED "$($K storage link smb-files t-e2esmb/dir/e2esmb.txt | jget 'd["error"]["code"]')"
check "smb mkdir" True "$($K storage mkdir smb-files t-e2esmb/empty/deep | jget 'd["data"]["created"]')"
check "smb mv a folder" True "$($K storage mv smb-files t-e2esmb/empty t-e2esmb/emptied | jget 'd["data"]["folder"]')"
check "smb mv --overwrite" True "$($K storage upload smb-files "$TMP/e2esmb.txt" t-e2esmb/b.txt >/dev/null; $K storage mv smb-files t-e2esmb/b.txt t-e2esmb/dir/e2esmb.txt --overwrite | jget 'd["data"]["replaced"]')"
check "smb mv --overwrite leaves no aside file" "['t-e2esmb/dir/e2esmb.txt']" "$($K storage ls smb-files t-e2esmb/dir/ | jget '[o["key"] for o in d["data"]["objects"]]')"
printf 'e2e' > "$TMP/e2esmb.part"
check "smb upload --continue goes on" 3 "$($K storage upload smb-files "$TMP/e2esmb.part" t-e2esmb/c.txt >/dev/null; $K storage upload smb-files "$TMP/e2esmb.txt" t-e2esmb/c.txt --continue | jget 'd["data"]["continued_from_bytes"]')"
check "smb upload --continue arrived" e2esmb "$($K storage cat smb-files t-e2esmb/c.txt -o text)"
check "smb download --continue goes on" 3 "$(cp "$TMP/e2esmb.part" "$TMP/e2esmb.down"; $K storage download smb-files t-e2esmb/c.txt --to "$TMP/e2esmb.down" --continue | jget 'd["data"]["continued_from_bytes"]')"
check "smb rm needs --allow-dangerous" POLICY_BLOCKED "$($K storage rm smb-files t-e2esmb/dir/e2esmb.txt | jget 'd["error"]["code"]')"
q $K storage rm smb-files --prefix t-e2esmb/ --allow-dangerous
check "smb rm emptied the folder" 0 "$($K storage ls smb-files --recursive | jget 'len([o for o in d["data"]["objects"] if o["key"].startswith("t-e2esmb/") and not o.get("dir")])')"
check "smb missing share" BUCKET_NOT_FOUND "$($K storage ls smb-noshare | jget 'd["error"]["code"]')"
q $K conn rm smb-files smb-noshare
rm -f "$TMP/e2esmb.txt" "$TMP/e2esmb.part" "$TMP/e2esmb.down"
set -e
