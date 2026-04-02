# Use Guide

## Purpose

`sqltracer.py` lets you inspect PostgreSQL traffic in real time without changing application code. You run it as a local proxy and point your application to the proxy port instead of the database port.

## Requirements

- Python 3.8+ recommended
- terminal with `curses` support
- PostgreSQL accessible over TCP
- PostgreSQL client configured with `sslmode=disable`

## Start the proxy and TUI

Example:

```bash
python3 sqltracer.py \
  --listen 127.0.0.1:5433 \
  --upstream 127.0.0.1:5432
```

Meaning:

- `--listen` is the local address where the proxy accepts client connections
- `--upstream` is the real PostgreSQL server address

## Connect your application

Change the connection string so that the application uses the proxy port:

```text
postgres://user:password@127.0.0.1:5433/appdb?sslmode=disable
```

## Command-line options

```text
--listen      local proxy listen address, default: 127.0.0.1:5433
--upstream    upstream PostgreSQL address, default: 127.0.0.1:5432
--config      path to a config file; when omitted, .sqltracer.yaml is auto-detected
--encrypted-config  path to an encrypted config created by config-encryptor.py
--vault-url   HashiCorp Vault base URL
--vault-path  HashiCorp Vault secret path
--vault-username  Vault username; otherwise VAULT_USERNAME or prompt
--vault-password  Vault password; otherwise VAULT_PASSWORD or prompt
--max-events  number of events kept in memory, default: 1000
--max-connections  maximum number of concurrent proxied connections, default: 200
--slow-ms     slow query threshold in ms, default: 100
--refresh-ms  TUI refresh interval in ms, default: 200
--socket-timeout-seconds  socket I/O timeout, default: 30
--max-startup-packet-bytes  startup packet limit, default: 1048576
--max-protocol-packet-bytes  protocol packet limit, default: 33554432
--no-tui      disable curses UI and print events to stdout
--log-level   DEBUG, INFO, WARNING, ERROR
--log-file    write diagnostic logs to a file; recommended in TUI mode
--dsn         PostgreSQL DSN for EXPLAIN / EXPLAIN ANALYZE
--allow-unsafe-explain-analyze  allow EXPLAIN ANALYZE for non-read-only SQL
--filter      startup structured filter; in --no-tui it affects stdout and file saving
--response-body  response body output in --no-tui: none or preview
--save-file   save captured events to a separate file
--save-format save format: jsonl or json
--save-profile  save detail level: minimal, default, full
--save-response  response body in the saved file: none or preview
--report-file  write aggregated summary report (slow/N+1/error)
--report-format  report format: json or markdown
--report-top  top N items per report section, default: 10
--jsonl-flush-every  flush jsonl buffer every N events, default: 50
--nplus1-threshold  N+1 threshold, default: 5
--nplus1-window     N+1 window in seconds, default: 1.0
--nplus1-cooldown   N+1 alert cooldown in seconds, default: 10.0
```

## Config examples

The repository now contains ready-made configs with a broad parameter set:

- [config-examples/tui-full.yaml](./config-examples/tui-full.yaml) - TUI mode with EXPLAIN, filtering and event saving
- [config-examples/headless-full.yaml](./config-examples/headless-full.yaml) - `--no-tui`, stdout filtering, response preview and full export
- [config-examples/docker-demo.yaml](./config-examples/docker-demo.yaml) - config for the Docker Compose demo

Run them with:

```bash
python3 sqltracer.py --config ./config-examples/tui-full.yaml
python3 sqltracer.py --config ./config-examples/headless-full.yaml
```

## Config sources

Three config loading methods are supported:

1. Plain file
2. Encrypted file
3. HashiCorp Vault

Priority order:

1. `--vault-url` + `--vault-path`
2. `--encrypted-config`
3. `--config` or auto-detected `.sqltracer.yaml`

Encrypted config:

```bash
python3 config-encryptor.py plain-config.json config.enc
python3 sqltracer.py --encrypted-config ./config.enc
```

If `SQLTRACER_CONFIG_PASSWORD` is not set, the password is requested interactively.

Vault config:

```bash
python3 sqltracer.py --vault-url http://127.0.0.1:8200 --vault-path secret/data/sqltracer
```

Vault uses `userpass` auth. Credentials are taken from:

- `--vault-username` / `--vault-password`
- or `VAULT_USERNAME` / `VAULT_PASSWORD`
- or an interactive prompt

## TUI controls

Letter hotkeys now work:

- in both Latin and Russian keyboard layouts
- regardless of `CapsLock`
- without relying on `Shift` for primary actions

Commands that previously depended on letter case now have separate dedicated keys.

- `q` or `Esc` - ask for exit confirmation
- `j` or `Down` - move down
- `k` or `Up` - move up
- `g` or `Home` - jump to the first event
- `u` or `End` - jump to the latest event and enable follow
- `Enter` - open the inspector for the selected query / transaction
- `/` or `.` - start text search
- `f` - start structured filter input
- `s` - toggle list sort by time or duration
- `a` - open analytics view
- `t` - open timeline view
- `space` - pause / resume live updates
- `v` - collapse or expand the selected transaction
- `Left` / `Right` - collapse / expand the selected transaction
- `x` - EXPLAIN selected query
- `y` - EXPLAIN ANALYZE selected query
- `e` / `r` - edit selected query, then EXPLAIN / ANALYZE
- `c` / `b` - copy query / query with bound args
- `o` - export the selected query response into a separate JSON file
- `w` / `d` - export visible events to JSON / Markdown
- `z` - clear visible history
- in `analytics` view: `h` / `l` - horizontal scroll, `s` - cycle sort metric
- in `timeline` view: `m` - switch `query` / `tx` mode, `c` - copy the selected row
- in query `inspector`: `p` / `n` - switch response preview pages

## What you see in the UI

Top panel:

- proxy listen and upstream addresses
- active connection count
- total captured event count
- total errors
- total slow queries
- total N+1 flagged events
- mode: `LIVE` or `PAUSED`

Event table:

- sequence number
- time
- operation type
- duration in milliseconds
- affected rows
- status
- compact query text
- transaction summary rows when the list is not in flat mode

Details panel:

- event id
- connection id
- transaction id
- full query text
- bind arguments
- response preview with columns and sampled rows
- normalized query
- N+1 / slow markers, scope and distinct-argument count
- PostgreSQL error text, if any

Inspector:

- dedicated full-screen view for a query or transaction
- vertical and horizontal scrolling
- for a query it shows the bound query, transaction context and response preview
- for a transaction it shows the summary and detailed blocks for every event
- from the inspector you can copy content and run EXPLAIN
- if `EXPLAIN` is unavailable because the program was started without `--dsn` / `DATABASE_URL`, a modal dialog is shown

Response preview behavior:

- only the first few rows are stored
- preview size is limited in bytes
- very long cells are truncated
- very long queries and bind values are also truncated before storing
- in inspector you can page through preview (`p`/`n`) and export selected response to JSON (`o`)

Structured filter now supports logical expressions:

- `and`, `or`, `not`
- parentheses: `( ... )`
- quoted values: `query:"select * from users"`

Supported fields and examples:

- `d>100ms`, `duration<=1s`
- `rows>10`
- `error`, `slow`, `n+1`, `nplus1`
- `tx`, `notx`, `tx:abcd`, `conn:deadbeef`
- `op:select`, `op:begin`, `op:execute`
- `query:users`, `norm:"select * from users where id = ?"`
- `arg:alice@example.com`, `error:column`, `status:error`
- `scope:tx`, `col:email`, `table:users`
- a bare token or quoted string still works as a text match

Examples:

- `op:select and d>50ms and not error`
- `(table:users or table:orders) and rows>0`
- `n+1 and scope:conn and not slow`

## What N+1 detector is and why it matters

The `N+1 detector` identifies the pattern where the application executes many very similar `SELECT` queries in a row, usually changing only bind values (for example, `WHERE id = $1` inside a loop).

Why it matters:

- it is a common performance anti-pattern in ORM/service code
- instead of one batch query or a `JOIN`, the app performs dozens/hundreds of tiny DB round-trips
- this increases latency, PostgreSQL load, and end-to-end API response time

How it works in `sqltracer`:

- queries are normalized into templates (`normalized_query`)
- repeated hits are counted in a sliding time window, scoped by transaction/connection
- detection uses both hit count and argument diversity (`distinct args`)
- when threshold is exceeded, events are flagged as `N+1` and surfaced in header/notice

How to use it in practice:

- inspect `N+1` together with `slow` in analytics/timeline
- check scope to understand whether it is local to one transaction or broader per connection
- after optimization (batch loading / join / prefetch), compare N+1 counts before/after

Analytics view:

- groups events by normalized query
- shows count, total, average, p95, max, rows, error count, slow count, N+1 count, and connection/tx spread
- supports sorting and horizontal scrolling

Timeline view:

- supports `query` and `tx` modes
- renders visible query events or transactions on a shared time axis
- highlights error / slow / N+1 rows
- useful for spotting overlap, long-running transactions and burst patterns

EXPLAIN support:

- requires `--dsn` or `DATABASE_URL`
- requires `psycopg` installed in the runtime environment
- for prepared queries it uses `PREPARE ... EXECUTE ...` with reconstructed arguments
- `EXPLAIN ANALYZE` runs inside a transaction followed by `ROLLBACK` to avoid leaving changes behind

## Config file

The script automatically looks for `.sqltracer.yaml` in the current directory. You can also point to an explicit file:

```bash
python3 sqltracer.py --config ./demo.sqltracer.yaml
```

CLI flags override config file values.

A small YAML subset is supported without external dependencies. Example:

```yaml
driver: postgres
listen: "127.0.0.1:5433"
upstream: "127.0.0.1:5432"
max_events: 2000
slow_threshold: 75ms
refresh_ms: 150
log_level: INFO
log_file: ./sqltracer.log
dsn_env: DATABASE_URL
nplus1:
  threshold: 4
  window: 2s
  cooldown: 15s
```

## Headless mode

Use this mode when you want plain stdout output instead of curses:

```bash
python3 sqltracer.py --no-tui
python3 sqltracer.py --no-tui --filter 'error or slow or nplus1'
python3 sqltracer.py --no-tui --response-body preview
python3 sqltracer.py --no-tui --save-file ./sqltracer.jsonl
python3 sqltracer.py --log-file ./sqltracer.log
```

In `--no-tui` mode:

- response size is always printed: row count and bytes
- response body output is controlled by `--response-body none|preview`
- filtering uses the same structured filter language as the TUI

For file saving:

- `--save-file` works in both TUI and `--no-tui`
- the default format is `jsonl`
- `--save-profile` controls metadata detail level
- `--save-response` controls whether response preview is saved

## Docker Compose demo

The repository also contains a ready-made integration demo:

- [docker-compose.yaml](./docker-compose.yaml)
- [Dockerfile](./Dockerfile)
- [demo_pg_client.py](./demo_pg_client.py)
- [postgres-init.sql](./docker/postgres-init.sql)

Start the full stack:

```bash
docker compose up --build
```

What it does:

- starts PostgreSQL with demo tables
- starts `sqltracer.py` in `--no-tui` mode on port `5433`
- starts a Python client that connects to `proxy:5433` and runs inserts, selects, committed and rolled back transactions, a slow query and an expected SQL error

Useful commands:

```bash
docker compose logs -f proxy
docker compose logs -f client
docker compose down -v
```

## Current protocol support

The script currently handles these PostgreSQL messages for inspection:

- `Query`
- `Parse`
- `Describe`
- `Bind`
- `Execute`
- `ParameterDescription`
- `CommandComplete`
- `ErrorResponse`
- `ReadyForQuery`

## Known limitations

- SSL/GSS requests are declined intentionally.
- Some advanced pipelining cases may not be reconstructed perfectly.
- The program does not change, optimize or block SQL. It only relays and observes.
- There is no persistent storage for captured events.
