# sqltracer

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](./CHANGELOG.md)

`sqltracer` is a Python 3 implementation of a PostgreSQL SQL traffic viewer.

It works as a TCP proxy between your application and PostgreSQL and shows captured activity in a terminal UI:

- SQL queries sent through the proxy
- prepared statement executions
- bind arguments when they are available
- response preview for result sets
- transactions: `BEGIN`, `COMMIT`, `ROLLBACK`
- transaction collapse / expand in the list
- dedicated query / transaction inspector
- query duration
- affected row count from `CommandComplete`
- PostgreSQL errors
- slow query highlighting
- improved N+1 detection with scope and distinct-argument tracking
- EXPLAIN / EXPLAIN ANALYZE
- search, extended structured filter, analytics and timeline views
- export, clipboard copy and query editing before EXPLAIN
- summary report (slow/N+1/error) in `json` or `markdown` for headless/TUI runs
- page-through response preview in inspector and selected-response JSON export

## Scope

Current version is intentionally limited to PostgreSQL only. The main runtime entrypoint is `sqltracer.py`, with helper modules split into separate files:

- main runtime: `sqltracer.py`
- config sources: `sqltracer_config_sources.py`
- packet I/O helpers: `sqltracer_packetio.py`
- language: Python 3
- dependencies: Python standard library, optional `psycopg` for EXPLAIN and `cryptography` for encrypted config
- UI: `curses` TUI
- config: plain file, encrypted file, or HashiCorp Vault

## Important limitations

- SSL and GSS encryption requests are declined on purpose, because encrypted traffic cannot be inspected at the proxy level.
- Your PostgreSQL client must connect through the proxy with `sslmode=disable`.
- The implementation focuses on the common PostgreSQL wire protocol flow and is not a full replacement for a production database proxy.
- There is no web UI.
- PostgreSQL only. MySQL and TiDB are not implemented.
- `EXPLAIN ANALYZE` is read-only by default; use `--allow-unsafe-explain-analyze` for potentially unsafe statements.

## Quick start

Start PostgreSQL normally on `127.0.0.1:5432`, then run:

```bash
python3 sqltracer.py --listen 127.0.0.1:5433 --upstream 127.0.0.1:5432
```

Point your application to the proxy port:

```text
postgres://user:password@127.0.0.1:5433/dbname?sslmode=disable
```

After that, every query going through the proxy will appear in the TUI.

## Headless mode

If you do not want to open the TUI, run:

```bash
python3 sqltracer.py --no-tui --listen 127.0.0.1:5433 --upstream 127.0.0.1:5432
python3 sqltracer.py --no-tui --filter 'error or slow' --response-body preview
python3 sqltracer.py --save-file ./sqltracer.jsonl --save-format jsonl
python3 sqltracer.py --no-tui --report-file ./sqltracer-report.md --report-format markdown
```

In that mode the program prints captured events to stdout. You can also filter the stream, include a bounded response preview and save captured events to `jsonl` or `json`.

## Config sources

Three config sources are supported:

- plain file: auto-load `.sqltracer.yaml` or pass `--config`
- encrypted file: `--encrypted-config`, compatible with [config-encryptor.py](./config-encryptor.py)
- HashiCorp Vault: `--vault-url` + `--vault-path` using `userpass` auth

Priority order:

- Vault
- encrypted config
- plain file

## Files

- `sqltracer.py` - proxy server and TUI in one Python file
- `sqltracer_config_sources.py` - config source providers (plain/encrypted/Vault)
- `sqltracer_packetio.py` - PostgreSQL packet reading with safety limits
- `config-examples/tui-full.yaml` - full config example for TUI mode
- `config-examples/headless-full.yaml` - full config example for `--no-tui` and file saving
- `config-examples/docker-demo.yaml` - config example for the Docker Compose demo
- `README.md` - short English overview
- `README-ru.md` - short Russian overview
- `UserGuide.md` - English usage guide
- `UserGuide-ru.md` - Russian usage guide

## License

MIT License. See [LICENSE](LICENSE).

## Author

**Tarasov Dmitry**
- Email: dtarasov7@gmail.com

## Attribution
Parts of this code were generated with assistance
