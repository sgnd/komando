# shellcheck shell=bash
# Task 09: read a table, then add a row. Sourced by test/sop/lab.sh in the
# e2e lab's `data` area (the `pg` container).
#
# The fixture: a table `orders` with 12 rows, made in the container itself.
# The check reads the table with psql in the container: the row 9001 is
# there or it is not, whatever route (and whatever tree's command) put it.
# komando's own entry for `pg` in the runner's inventory is a separate step
# that depends on how the shell tool reaches the lab (see the README).

psql_pg() { DC exec -T pg psql -U app -d app -v ON_ERROR_STOP=1 -tA "$@"; }

setup_task() {
  psql_pg -c "drop table if exists orders" \
    -c "create table orders (id int primary key, customer text not null, total numeric(10,2) not null)" \
    -c "insert into orders select g, 'customer-' || g, g * 1.5 from generate_series(1, 12) g" >/dev/null
}

check_task() {
  local n
  n="$(psql_pg -c "select count(*) from orders where id = 9001" | tr -d '[:space:]')"
  if [ "$n" = 1 ]; then
    echo "--check-passed"
  fi
}
