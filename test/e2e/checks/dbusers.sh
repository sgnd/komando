# shellcheck shell=bash
# db user / grant / revoke against PostgreSQL and MariaDB, through the
# bastion. The proof that the password (from the vault) is right: the new
# user logs in with it. Self-cleaning.
printf 'Ro-pass-1' | $K secret set dbu-pass >/dev/null
printf 'Ro-pass-2' | $K secret set dbu-pass2 >/dev/null
printf rootpass | $K secret set dbu-root >/dev/null
q $K conn add dbu-pg 'postgres://app@pg:5432/app?sslmode=disable' --via bastion --password-ref secret:pg-pass
q $K db query dbu-pg --write "create table if not exists dbu_t(id int)"
q $K db query dbu-pg --write "insert into dbu_t values (1)"
check "db user add --dry-run hides the password" "True False" \
  "$($K db user add dbu-pg dbu_ro --password-ref secret:dbu-pass --dry-run | jget '"[hidden]" in d["data"]["sql"], "Ro-pass" in json.dumps(d)')"
q $K db user add dbu-pg dbu_ro --password-ref secret:dbu-pass
check "db user ls lists the new user" True "$($K db user ls dbu-pg | jget 'any(u["name"]=="dbu_ro" and u["login"] for u in d["data"]["users"])')"
q $K db grant dbu-pg dbu_ro --privileges SELECT --on table:public.dbu_t
q $K conn add dbu-pg-ro 'postgres://dbu_ro@pg:5432/app?sslmode=disable' --via bastion --password-ref secret:dbu-pass
check "postgres: the new user logs in with the vault password (SCRAM verifier)" 1 "$($K db query dbu-pg-ro 'select count(*) as n from dbu_t' | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "postgres: and may only read what was granted" False "$($K db query dbu-pg-ro --write 'insert into dbu_t values (2)' | jget 'd["ok"]' || true)"
check "db grants shows the table" True "$($K db grants dbu-pg dbu_ro | jget 'any(g["object"]=="public.dbu_t" and "SELECT" in g["privileges"] for g in d["data"]["grants"])')"
q $K db user passwd dbu-pg dbu_ro --password-ref secret:dbu-pass2
check "postgres: after passwd the old password fails" False "$($K db query dbu-pg-ro 'select 1' | jget 'd["ok"]' || true)"
q $K conn edit dbu-pg-ro --password-ref secret:dbu-pass2
check "postgres: and the new one works" 1 "$($K db query dbu-pg-ro 'select 1' | jget 'd["data"]["results"][0]["rows"][0][0]')"
q $K db revoke dbu-pg dbu_ro --privileges SELECT --on table:public.dbu_t
check "db user rm needs --allow-dangerous" 6 "$($K db user rm dbu-pg dbu_ro >/dev/null 2>&1; echo $?)"
q $K db user rm dbu-pg dbu_ro --allow-dangerous
check "db user rm removed it" False "$($K db user ls dbu-pg | jget 'any(u["name"]=="dbu_ro" for u in d["data"]["users"])')"
q $K db query dbu-pg --write --allow-dangerous "drop table dbu_t"
q $K conn rm dbu-pg dbu-pg-ro

# MariaDB: the account is 'user'@'host'; the server is protected (as conn maria), so changes need --yes
q $K conn add dbu-my 'mysql://root@maria:3306/shop' --via bastion --password-ref secret:dbu-root --yes
q $K db user add dbu-my dbu_ro --password-ref secret:dbu-pass --yes
q $K db grant dbu-my dbu_ro --privileges SELECT --on 'shop.*' --yes
q $K conn add dbu-my-ro 'mysql://dbu_ro@maria:3306/shop' --via bastion --password-ref secret:dbu-pass --yes
check "mariadb: the new user logs in with the vault password" 1 "$($K db query dbu-my-ro 'select 1 as n' | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "mariadb: db grants shows SELECT on shop" True "$($K db grants dbu-my dbu_ro | jget 'any("SELECT ON `shop`.*" in g["grant"] for g in d["data"]["grants"])')"
check "mariadb: no write without the grant" False "$($K db query dbu-my-ro --write --yes 'create table dbu_x(id int)' | jget 'd["ok"]' || true)"
q $K db user rm dbu-my dbu_ro --allow-dangerous --yes
check "mariadb: the user is gone" False "$($K db user ls dbu-my | jget 'any(u["name"]=="dbu_ro" for u in d["data"]["users"])')"
q $K conn rm dbu-my dbu-my-ro --yes
check "no db user password in the audit log" 0 "$(audit_text | grep -c 'Ro-pass' || true)"
$K secret rm dbu-pass dbu-pass2 dbu-root >/dev/null 2>&1 || true
