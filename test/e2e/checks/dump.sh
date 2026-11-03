# komando's own dump and restore (no pg_dump, psql, mysqldump or mysql):
# used when a conn is reached directly or through a VPN, as here.
echo "==> built-in dump and restore"
q $K tunnel start bastion -D "127.0.0.1:$E2E_SOCKS"
q $K conn add pg-lab2 'postgres://app@pg:5432/app?sslmode=disable' --via lab --password-ref secret:pg-pass
NOTOOLS=(env PATH=/usr/bin:/bin)
q $K db query pg --write --allow-dangerous "drop schema if exists dumpt cascade"
q $K db query pg --write "create schema dumpt;
create type dumpt.mood as enum ('sad', 'ok', 'happy');
create domain dumpt.pos as int check (value > 0);
create table dumpt.customers (id int generated always as identity primary key, name text not null, mood dumpt.mood default 'ok', score dumpt.pos,
  email text unique, name_upper text generated always as (upper(name)) stored, note text);
create table dumpt.orders (id bigserial primary key, customer_id int not null references dumpt.customers(id), total numeric(10,2) check (total >= 0), made date default current_date);
create index orders_made on dumpt.orders (made);
create table dumpt.events (id int, at date not null) partition by range (at);
create table dumpt.events_2026 partition of dumpt.events for values from ('2026-01-01') to ('2027-01-01');
create function dumpt.touch() returns trigger language plpgsql as \$\$ begin new.note := coalesce(new.note, 'touched; ok'); return new; end; \$\$;
create trigger customers_touch before insert on dumpt.customers for each row execute function dumpt.touch();
create view dumpt.big_orders as select o.id, c.name from dumpt.orders o join dumpt.customers c on c.id = o.customer_id where o.total > 10;
create materialized view dumpt.order_count as select count(*) as n from dumpt.orders;
alter table dumpt.customers enable row level security;
create policy see_all on dumpt.customers for select using (true);
comment on table dumpt.customers is 'people who buy';
comment on column dumpt.customers.name is 'full name, it''s required';
insert into dumpt.customers (name, mood, score, email) values ('Ana', 'happy', 3, 'ana@x'), (E'Bu\tdi\nnew line', 'sad', 1, null), ('Ci ''quote'' \\\\ back', default, null, 'ci@x');
insert into dumpt.orders (customer_id, total, made) values (1, 12.50, '2026-05-01'), (2, 3, '2026-06-02');
insert into dumpt.events values (1, '2026-03-03');
refresh materialized view dumpt.order_count;"
check "built-in dump through a VPN" komando "$("${NOTOOLS[@]}" $K db dump pg-lab2 --to "$TMP/builtin.sql" | jget 'd["data"]["tool"][0]' || true)"
check "the dump holds the data" True "$(grep -q 'COPY "dumpt"."customers"' "$TMP/builtin.sql" && grep -q 'CREATE MATERIALIZED VIEW "dumpt"."order_count"' "$TMP/builtin.sql" && echo True)"
q $K db query pg --write "create database app_copy"
q $K conn add pg-copy 'postgres://app@pg:5432/app_copy?sslmode=disable' --via lab --password-ref secret:pg-pass
"${NOTOOLS[@]}" $K db restore pg-copy --from "$TMP/builtin.sql" --allow-dangerous > "$TMP/restore.json" || true
check "built-in restore" komando "$(jget 'd["data"]["tool"][0]' < "$TMP/restore.json" || true)"
grep -q '"ok":true' "$TMP/restore.json" || { echo "  restore said:"; head -c 1500 "$TMP/restore.json"; echo; }
# the reference: pg_dump on the bastion describes both databases the same way
# (the password comes from the vault through -e, so it never reaches the audit log)
PGD='pg_dump -h pg -U app --schema-only --no-owner --no-acl'
$K exec bastion --read-only -e PGPASSWORD=secret:pg-pass -- "$PGD app | grep -v '^\\\\' | grep -v '^--' | grep -v '^\$'" | jget 'd["data"]["results"][0]["stdout"]' > "$TMP/schema-a.txt"
$K exec bastion --read-only -e PGPASSWORD=secret:pg-pass -- "$PGD app_copy | grep -v '^\\\\' | grep -v '^--' | grep -v '^\$'" | jget 'd["data"]["results"][0]["stdout"]' > "$TMP/schema-b.txt"
check "restored schema equals the original (pg_dump compares)" "" "$(diff "$TMP/schema-a.txt" "$TMP/schema-b.txt" | head -20)"
ROWS="select (select string_agg(name || '|' || coalesce(note,'') || '|' || name_upper, ',' order by id) from dumpt.customers) || (select string_agg(total::text, ',' order by id) from dumpt.orders) || (select n::text from dumpt.order_count) || (select count(*)::text from dumpt.events)"
check "restored rows equal the original" "$($K db query pg "$ROWS" | jget 'd["data"]["results"][0]["rows"][0][0]')" "$($K db query pg-copy "$ROWS" | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "identity continues after restore" 4 "$($K db query pg-copy --write "insert into dumpt.customers (name) values ('Dewi') returning id" | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "--table dumps one table" True "$("${NOTOOLS[@]}" $K db dump pg-lab2 --to "$TMP/one.sql" --table dumpt.orders >/dev/null; grep -q 'CREATE TABLE "dumpt"."orders"' "$TMP/one.sql" && ! grep -q '"customers" (' "$TMP/one.sql" && echo True)"
check "--format custom needs pg_dump" USAGE "$("${NOTOOLS[@]}" $K db dump pg-lab2 --to "$TMP/x.dump" --format custom | jget 'd["error"]["code"]' || true)"
q $K db query pg --write "create aggregate dumpt.mysum(int) (sfunc = int4pl, stype = int)"
check "an object it cannot write stops the dump" DUMP_UNSUPPORTED "$("${NOTOOLS[@]}" $K db dump pg-lab2 --to "$TMP/agg.sql" | jget 'd["error"]["code"]' || true)"
q $K db query pg --write --allow-dangerous "drop schema dumpt cascade"
q $K conn rm pg-copy
q $K db query pg --write --allow-dangerous "drop database app_copy"

# MySQL / MariaDB through the VPN
q $K conn add maria-lab 'mysql://shop@maria:3306/shop' --via lab --password-ref secret:maria-pass
q $K db query maria-lab --write --yes "create table dumpm (id int auto_increment primary key, name varchar(50), raw blob, made datetime, n decimal(8,3))"
q $K db query maria-lab --write --yes "insert into dumpm (name, raw, made, n) values ('it''s; ok', x'00ff10', '2026-01-02 03:04:05', 1.5), (null, null, null, -2.25), ('back\\\\slash\nnew', '', '2026-12-31 23:59:59', 0)"
q $K db query maria-lab --write --yes "create view dumpm_v as select id, name from dumpm"
q $K db query maria-lab --write --yes "create trigger dumpm_t before insert on dumpm for each row set new.n = coalesce(new.n, 7)"
MROWS="select group_concat(concat_ws('|', id, coalesce(name,'NULL'), coalesce(hex(raw),'NULL'), coalesce(made,'NULL'), n) order by id separator ';') from dumpm"
BEFORE=$($K db query maria-lab "$MROWS" | jget 'd["data"]["results"][0]["rows"][0][0]')
check "built-in MySQL dump" komando "$("${NOTOOLS[@]}" $K db dump maria-lab --to "$TMP/maria-builtin.sql" | jget 'd["data"]["tool"][0]' || true)"
q $K db query maria-lab --write --yes --allow-dangerous "drop view dumpm_v"
q $K db query maria-lab --write --yes --allow-dangerous "drop table dumpm"
check "built-in MySQL restore" komando "$("${NOTOOLS[@]}" $K db restore maria-lab --from "$TMP/maria-builtin.sql" --yes --allow-dangerous | jget 'd["data"]["tool"][0]' || true)"
check "MySQL rows survive the round trip" "$BEFORE" "$($K db query maria-lab "$MROWS" | jget 'd["data"]["results"][0]["rows"][0][0]' || true)"
check "the view and trigger came back" "1 7" "$($K db query maria-lab "select count(*) from dumpm_v where id = 1" | jget 'd["data"]["results"][0]["rows"][0][0]') $($K db query maria-lab --write --yes "insert into dumpm (name) values ('t')" >/dev/null; $K db query maria-lab "select n from dumpm where name = 't'" | jget 'str(int(float(d["data"]["results"][0]["rows"][0][0])))')"
q $K db query maria-lab --write --yes --allow-dangerous "drop view dumpm_v"
q $K db query maria-lab --write --yes --allow-dangerous "drop table dumpm"
q $K conn rm maria-lab --yes
q $K conn rm pg-lab2
q $K tunnel stop --all
