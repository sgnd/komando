# BigQuery conns

Status: **built, 2026-11-10, not yet run against a real project**
(dump and restore, users and grants: not done).

## The question

BigQuery is where many teams keep their analytics, and the questions are
the usual ones: what tables are there, how big, what is running, stop
that job. Two things about BigQuery touch komando's promises:

1. **Every query costs money.** BigQuery bills by the bytes a query reads,
   and a careless `SELECT *` over a big table can cost more than the
   person (or agent) meant to spend. A read is not free just because it
   changes nothing.
2. **There is no read-only session**, and no transaction spans two jobs.
   But BigQuery has something the other kinds lack: a **dry run**
   (`jobs.insert` with `dryRun`), which runs nothing, costs nothing, and
   says what kind of statement BigQuery sees and how many bytes it would
   read.

## Decisions

- **The REST API, komando's own client.** `jobs.insert`,
  `jobs.getQueryResults`, `jobs.cancel`, `datasets.list`, `tables.list`
  and `tables.get`, in `internal/dbx/bigquery*.go`, as a small
  database/sql driver. Not `cloud.google.com/go/bigquery`: it is
  Apache-2.0, but brings gRPC, Arrow, OpenTelemetry and the storage read
  API for a protocol komando needs six calls of. No new dependency: the
  login uses `golang.org/x/oauth2/google`, which komando already has for
  `gs://` conns and `gcp-sm:` secrets.
- **The URL:** `bigquery://PROJECT[/DATASET]?location=EU`. The project is
  the one jobs run in and are billed to; the dataset is the default for
  names without one; `location` is where jobs run (without it BigQuery
  picks from the tables). Other options: `ca=secret:NAME` (a proxy that
  inspects TLS) and `endpoint=URL` (an emulator, or a Private Service
  Connect address). No user in the URL, and `tls=` is refused: it is
  HTTPS with the certificate checked. An `http://` endpoint (an emulator)
  is allowed, and `doctor` flags it when it crosses the network.
- **Login, as for `gs://`.** A service account key (the JSON file) in
  `--password-ref`, or else the application default credentials
  (`gcloud auth application-default login`,
  `GOOGLE_APPLICATION_CREDENTIALS`, the metadata server). gcloud's login is
  sent only to `https://*.googleapis.com`: an endpoint elsewhere gets the
  conn's own key or no login, so a mistyped endpoint cannot collect the
  person's Google token. Tokens are fetched through the same dialer as the
  API (`--via`, a VPN) and with the same CAs. A request waits for its
  token only as long as `--timeout` (or Ctrl-C) allows, a fetch gives up
  after 30 seconds, and a token endpoint that cannot be reached is
  `DB_CONNECT`, not a login to renew (`DB_AUTH`).
- **A dry run before every statement.** The driver dry-runs each
  statement, then:
  - without `--write` (and inside a read-only "transaction", which only
    marks the statements) anything BigQuery does not call `SELECT` is
    refused (`WRITE_REQUIRES_FLAG`), after the classifier's own check of
    the same statement; Google's endpoint must say the statement type, an
    emulator that does not leaves the classifier's rating alone;
  - a `SCRIPT` (BigQuery read several statements where komando saw one)
    is refused, except for `CALL` and `EXECUTE IMMEDIATE`, which BigQuery
    runs as scripts and the classifier rates `sql-opaque`;
  - a query that would read more than `--max-bytes` is refused
    (`DB_BYTES_LIMIT`, exit 6, no approval window: the hint says to ask
    the person).
- **The byte cap.** `--max-bytes` (default 10 GiB, a few cents at
  on-demand prices; `0` is no cap; units are powers of 1024) is checked
  against the dry run's estimate, and every job also carries it as
  `maximumBytesBilled`, so BigQuery stops a job whose estimate was low.
  Each result has `bytes_processed`. `db shell` and `db info`, `activity`
  and `sizes` use the default cap.
- **`--dry-run` is BigQuery's dry run**, for every statement, reads too:
  it runs nothing and is not billed, and the result says what each
  statement would read. (For the other kinds a dry run runs the SQL and
  rolls it back; here that would cost money and undo nothing.)
- **Jobs.** komando names each job (`komando_` and 24 random hex digits),
  so it can always cancel it: a run that times out or is cancelled calls
  `jobs.cancel`. Results are read with `getQueryResults`, which waits up
  to 10 s on the server per call, a page of 1000 rows at a time. 429 and
  5xx answers (and `backendError`, `rateLimitExceeded`) are tried again
  up to three times; `jobs.insert` with the same job ID, where a 409 on a
  retry means the first try made it. Each job has the label
  `komando=<actor>`. `jobTimeoutMs` is the run's `--timeout`.
- **Placeholders** are `?` (`parameterMode: POSITIONAL`), and the `--arg`
  values go as `STRING`: BigQuery does not coerce text to numbers, so
  `CAST(? AS INT64)` says what is meant, where guessing a type from the
  text would get `'007'` wrong.
- **Values.** `INT64` becomes a number (text when JSON cannot hold it
  exactly, as for the other kinds), `NUMERIC` and `BIGNUMERIC` stay text
  with every digit, `TIMESTAMP` (asked for as microseconds,
  `formatOptions.useInt64Timestamp`) is RFC 3339 in UTC, `BYTES` is
  `{"base64": ...}`, `JSON` keeps its shape, a `STRUCT` is an object and
  an `ARRAY` a list. `DATE`, `TIME`, `DATETIME`, `GEOGRAPHY` and
  `INTERVAL` stay as BigQuery writes them.
- **The lexer.** `bigqueryMask` turns GoogleSQL into text the shared lexer
  reads the same way, at the same length: comments (`#`, `--`, `/* */`)
  become spaces, text in `'...'`, `"..."`, `'''...'''` and `"""..."""`
  (with any `r`/`b` prefix) becomes `'xxx'`, and `` `names` `` become
  `"names"` (hidden when they hold a backslash or `"`). Backslash escapes
  count in text and names, not in raw text. Refused (`SQL_HIDDEN_CODE`): a
  raw string with a backslash before a quote (whether it ends the string
  is not documented clearly enough to bet on), a `/*` inside a comment,
  a line comment with a control character or an unusual line break,
  letters outside ASCII outside quotes.
- **Reads:** `SELECT`, `WITH` and `FROM` (pipe syntax, `FROM t |> ...`).
  Everything else needs `--write`, goes alone (`NoTx`), also a first word
  komando does not know. Script statements (`DECLARE`, `SET`, `IF`,
  `LOOP`, `BEGIN ... END`, ...) are refused, as each statement is a job of
  its own and variables would not carry over; `BEGIN`/`COMMIT
  TRANSACTION` are refused like everywhere.
- **Destructive:** besides the general rules (`DROP`, `TRUNCATE`, a
  `DELETE` or `UPDATE` without `WHERE`, `GRANT`, `REVOKE`), `CREATE OR
  REPLACE` (`sql-drop`), `LOAD DATA OVERWRITE` (`sql-truncate`), row
  access policies (`sql-privileges`), capacity commitments, reservations,
  assignments and `ALTER PROJECT`/`ORGANIZATION` (`sql-server-config`:
  they cost money for everyone), `EXPORT DATA` and `EXPORT MODEL`,
  `EXTERNAL_QUERY(...)` and `REMOTE WITH CONNECTION` (`sql-remote`: they
  write or run outside BigQuery), `CALL` and `EXECUTE IMMEDIATE`
  (`sql-opaque`), `CALL BQ.ABORT_SESSION` (`sql-kill`). `MERGE ... WHEN
  MATCHED THEN UPDATE` is a write, not an update without `WHERE`; a
  `MERGE` with `WHEN NOT MATCHED BY SOURCE` keeps the rule, as that
  clause reaches every row the source lacks (all of them for `ON FALSE`).
- **db explain** is the dry run as rows: statement type, bytes it would
  read (and whether that is within the cap), the tables it reads and the
  result's columns. A dry run runs nothing, so explaining a write needs
  no `--write`, except for what reaches elsewhere (`EXTERNAL_QUERY`),
  which keeps its rating. `--analyze` is `NOT_SUPPORTED` (a finished
  job's stages are in `INFORMATION_SCHEMA.JOBS`).
- **Schema from the API**, not from `INFORMATION_SCHEMA`: listing datasets
  and tables and reading a table's metadata is free and needs no location.
  Columns of a `STRUCT` follow it as `parent.child`; the primary key
  (`tableConstraints`), partitioning and clustering show as indexes. A
  listing stops at 10,000 tables.
- **Info, activity, sizes, kill.** `db info` is the project, dataset,
  location, the number of datasets and `SESSION_USER()`. `db activity`
  reads `region-LOCATION.INFORMATION_SCHEMA.JOBS` for jobs that are not
  `DONE` (from the last two days), leaving out its own; the location is the
  URL's, the dataset's or `US`. A job has a text ID, so its `pid` is 53
  bits of the FNV-1a hash of that ID (as for Snowflake). `db kill` finds
  the job by it and calls `jobs.cancel`; there is no `--session` (a
  BigQuery session ends with `CALL BQ.ABORT_SESSION`). `db sizes` reads
  `INFORMATION_SCHEMA.TABLE_STORAGE`. `db locks` is `NOT_SUPPORTED`.
- **Not done:** `db dump` and `restore` (`EXPORT DATA` to Cloud Storage
  and `komando storage` cover a copy; table snapshots keep one inside
  BigQuery), users and grants (Google Cloud IAM; a dataset's grants are in
  `INFORMATION_SCHEMA.OBJECT_PRIVILEGES`). All `NOT_SUPPORTED` with a
  hint, before connecting.

## The emulator

`ghcr.io/goccy/bigquery-emulator:0.8.1` runs here (arm64), but cannot test
komando's checks: a dry run answers 500 (a nil pointer in the emulator),
a dry-run `CREATE TABLE` creates the table, and every job reports
`statementType: SELECT`, an `INSERT` too. So the tests use komando's own
fakes: `internal/dbx/bigquery_test.go` (unit tests, TLS with a private CA,
the token endpoint, `--via` by name) and `test/e2e/bigquery` (the e2e
lab's compose service, through bastion).

## Not verified

No Google Cloud project was available. Built from BigQuery's REST
reference and tested against fakes. Not checked against the real
service:

- that a dry run gives `statementType` for every statement komando
  sends, and `SCRIPT` for `CALL` and `EXECUTE IMMEDIATE`;
- the error reasons komando maps (`accessDenied`, `notFound`,
  `bytesBilledLimitExceeded`, `stopped`, `timeout`, `quotaExceeded`,
  `responseTooLarge`) and their HTTP statuses;
- how raw strings with a backslash before the quote are read (komando
  refuses them), and whether `--` and `#` comments end at `\r`;
- that `region-LOCATION.INFORMATION_SCHEMA.JOBS` and `TABLE_STORAGE`
  have the columns komando reads, and that `INFORMATION_SCHEMA.SCHEMATA`
  (the shell's `\l`) works without a region;
- that `jobTimeoutMs` and `maximumBytesBilled` are taken as sent, and a
  repeated `jobs.insert` with the same ID answers 409.

`internal/dbx/bigquery_live_test.go` runs against a project when
`KOMANDO_BQTEST` (the conn URL, with a dataset the login may create
tables in) is set, with `KOMANDO_BQTEST_KEY` holding a service account
key (or gcloud's login without it). It makes and drops the table
`komando_bq_t`.
