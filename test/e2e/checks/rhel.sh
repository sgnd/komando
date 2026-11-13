# shellcheck shell=bash
# facts, pkg security and pkg on dnf and yum servers (test/e2e/rhel):
# Rocky Linux 9 (dnf) and Amazon Linux 2 (yum), against the native
# package manager on the same server. The checks start those containers
# themselves and remove them at the end.
R="${ROOT:-$(pwd)}"
# each server has its own port: the same address with another host key is
# a HOSTKEY_MISMATCH, as it should be
for rh in rocky:rockylinux/rockylinux:9:dnf:rocky:supported:${E2E_SSH_ROCKY:-2226} \
          amzn2:amazonlinux:2:yum:amzn:unsupported:${E2E_SSH_AMZN2:-2227}; do
  IFS=: read -r name base1 base2 pm osid support rhel_port <<<"$rh"
  img="komando-e2e-$name"
  box="komando-e2e-$name-$$"
  host="t-$name"
  rx() { docker exec "$box" "$@"; } # rx CMD...: the native command on that server
  # nupd [--security] [-C]: the packages `$pm check-update` lists (it exits 100 when there are some)
  nupd() { { rx "$pm" -q "$@" check-update 2>/dev/null || true; } | awk '/^Obsoleting/{exit} NF == 3 && $1 ~ /\./' | wc -l | tr -d ' '; }
  docker rm -f "$box" >/dev/null 2>&1 || true
  echo "  -- $name ($pm)"
  docker build -q --build-arg BASE="$base1:$base2" -t "$img" "$R/test/e2e/rhel" >/dev/null
  docker run -d --name "$box" -p "127.0.0.1:$rhel_port:22" "$img" >/dev/null
  for _ in $(seq 1 30); do nc -z 127.0.0.1 "$rhel_port" 2>/dev/null && break; sleep 1; done
  q $K host add "$host" "agent@127.0.0.1:$rhel_port" --password-ref secret:agent-pass
  q $K host trust "$host"
  # rd EXPR: EXPR on the server's data (x), or "error CODE" when it failed
  # (a dnf mirror that times out shows as that, not as a Python traceback)
  rd() { jget "(lambda r: (lambda x: $1)(r['data']) if 'data' in r else 'error ' + r['error']['code'])(d['data']['results'][0])"; }
  f() { $K facts "$host" | jget "d['data']['results'][0]['data']$1"; }
  # one version back, so there is always a security update to apply, even
  # once the base image is fully patched
  rx "$pm" -q -y downgrade curl libcurl >/dev/null 2>&1 || true
  # the native counts, read the same way an admin would
  upd=$(nupd -C)
  if [ "$pm" = dnf ]; then secl=$(rx dnf -q -C updateinfo list --security 2>/dev/null || true)
  else secl=$(rx yum -q -C updateinfo list security 2>/dev/null || true); fi
  sec=$(awk 'NF == 3 {print $3}' <<<"$secl" | sort -u | grep -c . || true)
  secpk=$(nupd --security)
  echo "  ($name: $upd pending, $secpk security updates before the patch)"

  check "$name: facts os and package manager" "$osid $pm" "$(f "['os'] + ' ' + d['data']['results'][0]['data']['pkg_manager']")"
  check "$name: facts support status" "$support" "$(f "['os_support']['status']")"
  check "$name: facts pending updates = $pm check-update" "$upd" "$(f "['updates']['total']")"
  if [ "$support" = supported ]; then
    check "$name: facts security updates = $pm updateinfo" "$sec" "$(f "['updates']['security']")"
  else # past end of life: unknown on purpose (0 would look safe), with a warning
    check "$name: facts security updates unknown past end of life" "None True" \
      "$(f "['updates']['security']") $(f "['warnings'] != [] and 'end of life' in d['data']['results'][0]['data']['warnings'][0]")"
  fi
  check "$name: facts reboot_required = needs-restarting -r" \
    "$(rx needs-restarting -r >/dev/null 2>&1; [ $? -eq 1 ] && echo True || echo False)" "$(f "['reboot_required']")"

  psec() { $K pkg security "$host" | jget "d['data']['results'][0]$1"; }
  check "$name: pkg security uses $pm" "$pm" "$(psec "['package_manager']")"
  check "$name: pkg security = $pm check-update --security" "$secpk" "$(psec "['count']")"
  check "$name: pkg security state pending = $pm check-update" "$upd" "$(psec "['state']['pending_updates']")"
  # facts and pkg security read the server's state with the same check
  check "$name: facts and pkg security agree (reboot, restarts, support)" \
    "$(f "['reboot_required'], d['data']['results'][0]['data']['services_need_restart'] or [], d['data']['results'][0]['data']['os_support']['status']")" \
    "$(psec "['state']['reboot_required'], d['data']['results'][0]['state']['services_need_restart'], d['data']['results'][0]['os_support']['status']")"
  if [ "$support" != supported ]; then
    check "$name: pkg security warns past end of life" True "$(psec "['warnings'] != [] and 'empty list' in d['data']['results'][0]['warnings'][-1]")"
  fi
  check "$name: pkg upgrade --security --dry-run changes nothing" "True $secpk" \
    "$($K pkg upgrade "$host" --security --dry-run | jget "str(d['meta'].get('dry_run') and not d['data']['applied'])") $(nupd --security)"
  # the real run: installs only the security updates; afterwards rpm agrees and none are left
  o=$($K pkg upgrade "$host" --security --timeout 15m || true)
  check "$name: pkg upgrade --security works" True "$(jget "d['ok']" <<<"$o")"
  if [ "$secpk" -gt 0 ]; then
    first=$(jget "d['data']['results'][0]['upgraded'][0]['name'] + ' ' + d['data']['results'][0]['upgraded'][0]['version']" <<<"$o")
    pkgname=${first% *}
    check "$name: an upgraded package = rpm -q" "${first#* }" "$(rx rpm -q --qf '%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n' "${pkgname%.*}" | sed 's/^0://' | sort -V | tail -n 1)"
  else
    check "$name: nothing to patch says so" "" "$(jget "d['data']['results'][0].get('method', '')" <<<"$o")"
  fi
  check "$name: no security updates left (native)" 0 "$(nupd --security)"
  check "$name: no security updates left (komando)" 0 "$(psec "['count']")"

  # plain pkg on dnf/yum
  check "$name: pkg installed = rpm -q" "True False" "$($K pkg installed "$host" bash t-norpm | rd "' '.join(str(p['installed']) for p in x)")"
  check "$name: pkg install" installed "$($K pkg install "$host" tree | rd "x['packages'][0]['state']")"
  check "$name: rpm -q sees it" tree "$(rx rpm -q --qf '%{NAME}\n' tree)"
  check "$name: pkg install again changes nothing" False "$($K pkg install "$host" tree | rd "x['changed']")"
  check "$name: pkg rm" removed "$($K pkg rm "$host" tree | rd "x['packages'][0]['state']")"
  set +e; $K pkg rm "$host" openssh-server >/dev/null; check "$name: removing an essential package is blocked" 6 $?; set -e
  check "$name: pkg upgradable = $pm check-update" "$(nupd)" \
    "$($K pkg upgradable "$host" | rd "len(x['packages'])")"

  q $K host rm "$host"
  docker rm -f "$box" >/dev/null 2>&1 || true
done
