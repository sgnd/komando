package dbx

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/driver"
)

// TestDumpRestoreLive dumps a rich schema and restores it into a new
// database. It runs when KOMANDO_PGTEST is a postgres:// URL of a server
// where the user may create databases (make e2e covers it too).
func TestDumpRestoreLive(t *testing.T) {
	base := os.Getenv("KOMANDO_PGTEST")
	if base == "" {
		t.Skip("set KOMANDO_PGTEST=postgres://user:pass@host:port/db to run")
	}
	ctx := context.Background()
	open := func(u string) (*sqlDB, error) {
		tg, err := driver.Parse(u)
		if err != nil {
			return nil, err
		}
		db, err := Open(ctx, u, tg, os.Getenv("KOMANDO_PGTEST_PASSWORD"), nil, false, "test")
		return &sqlDB{db}, err
	}
	src, err := open(base)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	for _, q := range []string{
		"drop schema if exists dumpt cascade", "drop database if exists app_copy", "drop view if exists public.pv", "drop table if exists public.pt",
		// public objects are referred to without a schema name; the dump must still name them in full
		"create table public.pt (id serial primary key, name text); create view public.pv as select id, name from pt; insert into pt (name) values ('p1')",
		`create schema dumpt;
create type dumpt.mood as enum ('sad', 'ok', 'happy');
create domain dumpt.pos as int check (value > 0);
create table dumpt.customers (id int generated always as identity primary key, name text not null, mood dumpt.mood default 'ok', score dumpt.pos,
  email text unique, name_upper text generated always as (upper(name)) stored, note text);
create table dumpt.orders (id bigserial primary key, customer_id int not null references dumpt.customers(id), total numeric(10,2) check (total >= 0), made date default current_date);
create index orders_made on dumpt.orders (made);
create table dumpt.events (id int, at date not null) partition by range (at);
create table dumpt.events_2026 partition of dumpt.events for values from ('2026-01-01') to ('2027-01-01');
create function dumpt.touch() returns trigger language plpgsql as $$ begin new.note := coalesce(new.note, 'touched; ok'); return new; end; $$;
create trigger customers_touch before insert on dumpt.customers for each row execute function dumpt.touch();
create view dumpt.big_orders as select o.id, c.name from dumpt.orders o join dumpt.customers c on c.id = o.customer_id where o.total > 10;
create materialized view dumpt.order_count as select count(*) as n from dumpt.orders;
alter table dumpt.customers enable row level security;
create policy see_all on dumpt.customers for select using (true);
comment on table dumpt.customers is 'people who buy';
insert into dumpt.customers (name, mood, score, email) values ('Ana', 'happy', 3, 'ana@x'), (E'Bu\tdi\nnew', 'sad', 1, null);
insert into dumpt.orders (customer_id, total, made) values (1, 12.50, '2026-05-01');
insert into dumpt.events values (1, '2026-03-03');
refresh materialized view dumpt.order_count;`,
		"create database app_copy",
	} {
		if _, err := src.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q[:20], err)
		}
	}
	var buf bytes.Buffer
	if err := Dump(ctx, src.DB, "postgres", DumpOptions{}, &buf); err != nil {
		t.Fatalf("dump: %v", err)
	}
	if err := driver.CheckRestore("postgres", bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("check: %v", err)
	}
	dst, err := open(strings.Replace(base, "/app?", "/app_copy?", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	if err := Restore(ctx, dst.DB, "postgres", bytes.NewReader(buf.Bytes())); err != nil {
		t.Logf("dump:\n%s", buf.String())
		t.Fatalf("restore: %v", err)
	}
	var got string
	if err := dst.QueryRowContext(ctx, "select string_agg(name || '|' || note, ',' order by id) from dumpt.customers").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "Ana|touched; ok,Bu\tdi\nnew|touched; ok" {
		t.Errorf("rows: %q", got)
	}
	var pv string
	if err := dst.QueryRowContext(ctx, "select name from public.pv").Scan(&pv); err != nil || pv != "p1" {
		t.Errorf("public view: %q %v", pv, err)
	}
	if _, err := dst.ExecContext(ctx, "insert into public.pt (name) values ('p2')"); err != nil {
		t.Errorf("the serial sequence came back: %v", err)
	}
}

type sqlDB struct{ *sql.DB }
