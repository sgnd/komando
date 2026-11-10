# shellcheck shell=bash
# An SMB share (Samba with signing and encryption required) through --via
# bastion: the same upload, list, download and rm steps as the other storage
# kinds, a wrong share and the missing links. Uses t-e2esmb/ files and
# removes them at the end.
set +e
echo -n deploypass | $K secret set smb-pass >/dev/null
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
check "smb rm needs --allow-dangerous" POLICY_BLOCKED "$($K storage rm smb-files t-e2esmb/dir/e2esmb.txt | jget 'd["error"]["code"]')"
q $K storage rm smb-files --prefix t-e2esmb/ --allow-dangerous
check "smb rm emptied the folder" 0 "$($K storage ls smb-files --recursive | jget 'len([o for o in d["data"]["objects"] if o["key"].startswith("t-e2esmb/") and not o.get("dir")])')"
check "smb missing share" BUCKET_NOT_FOUND "$($K storage ls smb-noshare | jget 'd["error"]["code"]')"
q $K conn rm smb-files smb-noshare
rm -f "$TMP/e2esmb.txt"
set -e
