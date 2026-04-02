# Журнал изменений

В этом файле фиксируются заметные изменения проекта.

## [1.0.0] - 2026-04-02

Первый публичный релиз `sqltracer` (фокус на PostgreSQL).

### Добавлено

- Однофайловый прокси/просмотрщик SQL-трафика PostgreSQL: `sqltracer.py`.
- TUI-режим: список запросов, inspector запросов/транзакций, analytics view, timeline view, сворачивание/разворачивание транзакций.
- Headless-режим с фильтрацией и управляемым выводом preview ответа.
- EXPLAIN / EXPLAIN ANALYZE (в том числе сценарий edit-before-run).
- Экспорт/copy/edit запросов и export summary report (`json` / `markdown`).
- Structured filter language и улучшенный N+1 detector.
- Загрузка конфига из plain файла, encrypted файла и HashiCorp Vault.
- Docker Compose стенд и demo-клиент PostgreSQL.

### Безопасность

- Защита от случайного remote-bind (`--allow-remote-listen`) и allowlist клиентов (`--client-allowlist`).
- Для Vault по умолчанию только HTTPS (`--allow-insecure-vault-http` только явным флагом).
- Защита от утечки секрета через CLI для `--vault-password` (нужен `--allow-cli-secrets`).
- Лимит in-flight очереди на соединение (`--max-pending-events-per-connection`).
- Ограниченные in-memory кэши для filter AST и N+1 tracking.
- Файлы save/export/report пишутся с приватными правами (`0600`).
