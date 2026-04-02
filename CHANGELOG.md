# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-04-02

First public release of `sqltracer` (PostgreSQL-focused).

### Added

- Single-file PostgreSQL SQL traffic proxy/viewer: `sqltracer.py`.
- TUI mode with query list, query/transaction inspector, analytics view, timeline view, and transaction collapse/expand.
- Headless mode with filter support and configurable response preview output.
- EXPLAIN / EXPLAIN ANALYZE workflow (including edit-before-run).
- Query export/copy/edit features and summary report export (`json` / `markdown`).
- Structured filter language and improved N+1 detection.
- Config loading from plain file, encrypted file, and HashiCorp Vault.
- Docker Compose demo and PostgreSQL demo client.

### Security

- Remote bind protection (`--allow-remote-listen`) and optional client allowlist (`--client-allowlist`).
- Vault HTTPS-by-default enforcement (`--allow-insecure-vault-http` for explicit override).
- CLI secret guard for `--vault-password` (`--allow-cli-secrets` required).
- Per-connection in-flight queue limit (`--max-pending-events-per-connection`).
- Bounded in-memory caches for filter AST and N+1 tracking.
- Export/report/save files are written with private permissions (`0600`).
