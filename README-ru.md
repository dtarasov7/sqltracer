# sqltracer

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](./CHANGELOG-ru.md)

![sqltracer screenshot](images/sqltracer.png)

`sqltracer` - это реализация на Python 3 просмотрщика SQL-трафика для PostgreSQL.

Программа работает как TCP-прокси между приложением и PostgreSQL и показывает в TUI:

- SQL-запросы, проходящие через прокси
- выполнения prepared statements
- bind-аргументы, если их удалось восстановить
- preview ответа для result set
- транзакции: `BEGIN`, `COMMIT`, `ROLLBACK`
- сворачивание и разворачивание транзакций в списке
- отдельный inspector для query и transaction
- длительность запросов
- число затронутых строк из `CommandComplete`
- ошибки PostgreSQL
- подсветку медленных запросов
- улучшенную детекцию N+1 с учетом scope и разных аргументов
- EXPLAIN / EXPLAIN ANALYZE
- search, расширенный structured filter, analytics и timeline view
- экспорт, copy в clipboard и редактирование запроса перед EXPLAIN
- summary report (slow/N+1/error) в `json` или `markdown` для headless/TUI сценариев
- page-through preview ответа в inspector и export выбранного response в отдельный JSON

## Что входит в текущую версию

Текущая версия специально ограничена PostgreSQL. Основная точка входа - `sqltracer.py`, а вспомогательная логика вынесена в отдельные файлы:

- основной runtime: `sqltracer.py`
- источники конфигурации: `sqltracer_config_sources.py`
- packet I/O helpers: `sqltracer_packetio.py`
- язык: Python 3
- зависимости: стандартная библиотека Python, опционально `psycopg` для EXPLAIN и `cryptography` для encrypted config
- интерфейс: `curses` TUI
- конфиг: plain file, encrypted file или HashiCorp Vault

## Важные ограничения

- Запросы на SSL и GSS шифрование намеренно отклоняются, потому что зашифрованный трафик нельзя анализировать на уровне прокси.
- Клиент PostgreSQL должен подключаться к прокси с `sslmode=disable`.
- Реализация покрывает типовой сценарий PostgreSQL wire protocol, но не претендует на роль полнофункционального production-прокси.
- Пока нет web UI.
- Поддерживается только PostgreSQL. MySQL и TiDB не реализованы.
- `EXPLAIN ANALYZE` по умолчанию ограничен read-only запросами; для потенциально небезопасных сценариев нужен `--allow-unsafe-explain-analyze`.

## Быстрый старт

Запустите PostgreSQL как обычно на `127.0.0.1:5432`, затем:

```bash
python3 sqltracer.py --listen 127.0.0.1:5433 --upstream 127.0.0.1:5432
```

После этого направьте приложение не в сам PostgreSQL, а в прокси:

```text
postgres://user:password@127.0.0.1:5433/dbname?sslmode=disable
```

Все запросы, проходящие через прокси, будут появляться в TUI.

## Режим без TUI

Если TUI не нужен, можно запустить:

```bash
python3 sqltracer.py --no-tui --listen 127.0.0.1:5433 --upstream 127.0.0.1:5432
python3 sqltracer.py --no-tui --filter 'error or slow' --response-body preview
python3 sqltracer.py --save-file ./sqltracer.jsonl --save-format jsonl
python3 sqltracer.py --no-tui --report-file ./sqltracer-report.md --report-format markdown
```

В этом режиме события печатаются в stdout. Также можно фильтровать поток, включать preview ответа и сохранять события в `jsonl` или `json`.

## Источники конфигурации

Поддерживаются три способа загрузки конфигурации:

- обычный файл: автозагрузка `.sqltracer.yaml` или `--config`
- зашифрованный файл: `--encrypted-config`, формат совместим с [config-encryptor.py](./config-encryptor.py)
- HashiCorp Vault: `--vault-url` + `--vault-path`, аутентификация через `userpass`

Приоритет такой:

- Vault
- encrypted config
- plain file

## Файлы

- `sqltracer.py` - прокси и TUI в одном Python-файле
- `sqltracer_config_sources.py` - провайдеры конфигурации (plain/encrypted/Vault)
- `sqltracer_packetio.py` - чтение PostgreSQL-пакетов с защитными лимитами
- `config-examples/tui-full.yaml` - полный пример конфига для TUI-режима
- `config-examples/headless-full.yaml` - полный пример конфига для `--no-tui` и сохранения в файл
- `config-examples/docker-demo.yaml` - пример конфига для Docker Compose стенда
- `README.md` - краткое описание на английском
- `README-ru.md` - краткое описание на русском
- `UserGuide.md` - подробное руководство на английском
- `UserGuide-ru.md` - подробное руководство на русском

## License

MIT License. See [LICENSE](LICENSE).

## Автор

**Tarasov Dmitry**
- Email: dtarasov7@gmail.com

## Атрибуция
Части этого кода были сгенерированы с помощью ИИ
