# Руководство по использованию

## Назначение

`sqltracer.py` позволяет смотреть PostgreSQL-трафик в реальном времени без изменения кода приложения. Скрипт запускается как локальный прокси, а приложение подключается не напрямую к базе, а к порту прокси.

## Требования

- Python 3.8+ желательно
- терминал с поддержкой `curses`
- PostgreSQL, доступный по TCP
- клиент PostgreSQL должен использовать `sslmode=disable`

## Запуск прокси и TUI

Пример:

```bash
python3 sqltracer.py \
  --listen 127.0.0.1:5433 \
  --upstream 127.0.0.1:5432
```

Значение параметров:

- `--listen` - локальный адрес, где прокси принимает подключения клиента
- `--upstream` - адрес настоящего сервера PostgreSQL

## Подключение приложения

Нужно изменить строку подключения так, чтобы приложение шло в прокси-порт:

```text
postgres://user:password@127.0.0.1:5433/appdb?sslmode=disable
```

## Параметры командной строки

```text
--listen      локальный адрес прокси, по умолчанию: 127.0.0.1:5433
--upstream    адрес PostgreSQL, по умолчанию: 127.0.0.1:5432
--config      путь к config file; если не задан, автоматически ищется .sqltracer.yaml
--encrypted-config  путь к зашифрованному конфигу, созданному через config-encryptor.py
--vault-url   базовый URL HashiCorp Vault
--vault-path  путь к secret в HashiCorp Vault
--vault-username  имя пользователя Vault; иначе VAULT_USERNAME или prompt
--vault-password  пароль Vault; иначе VAULT_PASSWORD или prompt
--max-events  сколько событий хранить в памяти, по умолчанию: 1000
--max-connections  максимум одновременных проксируемых подключений, по умолчанию: 200
--slow-ms     порог медленного запроса в мс, по умолчанию: 100
--refresh-ms  интервал обновления TUI в мс, по умолчанию: 200
--socket-timeout-seconds  таймаут сокетного I/O, по умолчанию: 30
--max-startup-packet-bytes  лимит startup packet, по умолчанию: 1048576
--max-protocol-packet-bytes  лимит protocol packet, по умолчанию: 33554432
--no-tui      отключить curses UI и печатать события в stdout
--log-level   DEBUG, INFO, WARNING, ERROR
--log-file    писать диагностические логи в файл; рекомендуется для TUI
--dsn         PostgreSQL DSN для EXPLAIN / EXPLAIN ANALYZE
--allow-unsafe-explain-analyze  разрешить EXPLAIN ANALYZE для non-read-only SQL
--filter      стартовый structured filter; в --no-tui влияет на stdout и сохранение
--response-body  тело ответа в --no-tui: none или preview
--save-file   сохранять события в отдельный файл
--save-format формат сохранения: jsonl или json
--save-profile  полнота сохранения: minimal, default, full
--save-response  тело ответа в файле: none или preview
--report-file  сохранить агрегированный summary report (slow/N+1/error)
--report-format  формат report-файла: json или markdown
--report-top  топ N элементов в каждом разделе report, по умолчанию: 10
--jsonl-flush-every  сбрасывать буфер jsonl после N событий, по умолчанию: 50
--nplus1-threshold  порог N+1, по умолчанию: 5
--nplus1-window     окно N+1 в секундах, по умолчанию: 1.0
--nplus1-cooldown   cooldown алерта N+1 в секундах, по умолчанию: 10.0
```

## Примеры конфигов

В репозитории добавлены готовые конфиги с максимальным набором параметров:

- [config-examples/tui-full.yaml](./config-examples/tui-full.yaml) - TUI-режим, EXPLAIN, фильтр и сохранение событий
- [config-examples/headless-full.yaml](./config-examples/headless-full.yaml) - `--no-tui`, фильтрация stdout, preview ответа и полный экспорт
- [config-examples/docker-demo.yaml](./config-examples/docker-demo.yaml) - запуск внутри Docker Compose стенда

Запуск:

```bash
python3 sqltracer.py --config ./config-examples/tui-full.yaml
python3 sqltracer.py --config ./config-examples/headless-full.yaml
```

## Источники конфигурации

Поддерживаются три способа:

1. Plain file
2. Encrypted file
3. HashiCorp Vault

Приоритет выбора:

1. `--vault-url` + `--vault-path`
2. `--encrypted-config`
3. `--config` или автопоиск `.sqltracer.yaml`

Encrypted config:

```bash
python3 config-encryptor.py plain-config.json config.enc
python3 sqltracer.py --encrypted-config ./config.enc
```

Если переменная `SQLTRACER_CONFIG_PASSWORD` не задана, пароль будет запрошен интерактивно.

Vault config:

```bash
python3 sqltracer.py --vault-url http://127.0.0.1:8200 --vault-path secret/data/sqltracer
```

Для Vault используется `userpass` auth. Логин/пароль берутся из:

- `--vault-username` / `--vault-password`
- или `VAULT_USERNAME` / `VAULT_PASSWORD`
- или интерактивного prompt

## Управление в TUI

Буквенные hotkey работают:

- в латинской и русской раскладке
- без зависимости от `CapsLock`
- без зависимости от зажатого `Shift` для основных действий

Для команд, которые раньше различались только регистром, добавлены отдельные клавиши, не зависящие от `Shift`.

- `q` или `Esc` - запросить подтверждение выхода
- `j` или `Down` - вниз
- `k` или `Up` - вверх
- `g` или `Home` - перейти к первому событию
- `u` или `End` - перейти к последнему событию и включить follow
- `Enter` - открыть inspector для выбранного query / transaction
- `/` или `.` - начать text search
- `f` - начать ввод structured filter
- `s` - переключить сортировку списка по времени или длительности
- `a` - открыть analytics view
- `t` - открыть timeline view
- `space` - пауза / продолжение live-обновления
- `v` - свернуть или развернуть выбранную транзакцию
- `Left` / `Right` - свернуть / развернуть выбранную транзакцию
- `x` - EXPLAIN выбранного запроса
- `y` - EXPLAIN ANALYZE выбранного запроса
- `e` / `r` - отредактировать запрос и затем EXPLAIN / ANALYZE
- `c` / `b` - скопировать query / query с подставленными bind-аргументами
- `o` - экспортировать response выбранного запроса в отдельный JSON
- `w` / `d` - экспортировать видимые события в JSON / Markdown
- `z` - очистить видимую историю
- в `analytics` view: `h` / `l` - горизонтальная прокрутка, `s` - смена метрики сортировки
- в `timeline` view: `m` - переключение режима `query` / `tx`, `c` - copy выбранной строки
- в `inspector` для query: `p` / `n` - переключение страниц preview ответа

## Что видно в интерфейсе

Верхняя строка:

- адрес прослушивания прокси и адрес upstream PostgreSQL
- число активных соединений
- общее число пойманных событий
- число ошибок
- число медленных запросов
- число событий, помеченных как N+1
- режим `LIVE` или `PAUSED`

Таблица событий:

- порядковый номер
- время
- тип операции
- длительность в миллисекундах
- число затронутых строк
- статус
- короткий текст запроса
- transaction summary rows, если список не в flat-режиме

Панель деталей:

- id события
- id соединения
- id транзакции
- полный текст запроса
- bind-аргументы
- preview ответа с колонками и выборкой строк
- normalized query
- маркеры N+1 / slow, scope и число distinct args
- текст ошибки PostgreSQL, если она была

Inspector:

- отдельный полноэкранный view для query или transaction
- вертикальная и горизонтальная прокрутка
- для query показывает bound query, transaction context и preview ответа
- для transaction показывает summary и подробные блоки по каждому событию
- из inspector можно делать copy и запускать EXPLAIN
- если `EXPLAIN` недоступен из-за запуска без `--dsn` / `DATABASE_URL`, показывается модальное окно

Поведение preview ответа:

- сохраняются только первые несколько строк
- общий объем preview ограничен по байтам
- слишком длинные ячейки обрезаются
- очень длинные запросы и bind-значения тоже обрезаются перед сохранением
- в inspector preview можно листать по страницам (`p`/`n`) и экспортировать выбранный response в JSON (`o`)

Structured filter теперь поддерживает логические выражения:

- `and`, `or`, `not`
- скобки: `( ... )`
- quoted values: `query:"select * from users"`

Поддерживаемые поля и примеры:

- `d>100ms`, `duration<=1s`
- `rows>10`
- `error`, `slow`, `n+1`, `nplus1`
- `tx`, `notx`, `tx:abcd`, `conn:deadbeef`
- `op:select`, `op:begin`, `op:execute`
- `query:users`, `norm:"select * from users where id = ?"`
- `arg:alice@example.com`, `error:column`, `status:error`
- `scope:tx`, `col:email`, `table:users`
- bare token or quoted string still works as text match

Примеры:

- `op:select and d>50ms and not error`
- `(table:users or table:orders) and rows>0`
- `n+1 and scope:conn and not slow`

## Что такое N+1 detector и зачем он нужен

`N+1 detector` ищет паттерн, когда приложение выполняет много похожих `SELECT`-запросов подряд, отличающихся в основном параметрами (например, `WHERE id = $1` в цикле).

Почему это важно:

- это типичный источник деградации производительности в ORM/сервисном коде
- вместо одного батч-запроса или `JOIN` приложение делает десятки/сотни мелких round-trip к БД
- растут latency, нагрузка на PostgreSQL и общее время ответа API

Как это работает в `sqltracer`:

- запросы нормализуются до шаблона (`normalized_query`)
- в скользящем временном окне считаются повторы по scope (обычно transaction или connection)
- учитывается не только число повторов, но и разнообразие аргументов (`distinct args`)
- при превышении порога событие помечается как `N+1`, а в верхней панели/notice появляется сигнал

Как использовать на практике:

- смотреть связку `N+1` + `slow` в analytics/timeline
- проверять scope: проблема внутри одной транзакции или по соединению в целом
- после фикса (batch loading / join / prefetch) сравнить число `N+1`-событий до и после

Analytics view:

- группирует события по normalized query
- показывает count, total, average, p95, max, rows, error count, slow count, N+1 count, число connection/tx
- поддерживает сортировку и горизонтальную прокрутку

Timeline view:

- умеет режимы `query` и `tx`
- рисует видимые query-события или транзакции на общей временной шкале
- подсвечивает error / slow / N+1
- полезен для поиска пересечений, длинных транзакций и burst-patterns

Поддержка EXPLAIN:

- требует `--dsn` или `DATABASE_URL`
- требует установленный `psycopg` в runtime-среде
- для prepared queries использует `PREPARE ... EXECUTE ...` с восстановленными аргументами
- `EXPLAIN ANALYZE` выполняется в транзакции с последующим `ROLLBACK`, чтобы не оставлять изменения

## Config file

Скрипт автоматически ищет `.sqltracer.yaml` в текущем каталоге. Можно указать и явный путь:

```bash
python3 sqltracer.py --config ./demo.sqltracer.yaml
```

CLI-флаги имеют приоритет над config file.

Поддерживается простой YAML-подмножество без внешних зависимостей. Пример:

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

## Режим без TUI

Если нужен только поток событий в stdout:

```bash
python3 sqltracer.py --no-tui
python3 sqltracer.py --no-tui --filter 'error or slow or nplus1'
python3 sqltracer.py --no-tui --response-body preview
python3 sqltracer.py --no-tui --save-file ./sqltracer.jsonl
python3 sqltracer.py --log-file ./sqltracer.log
```

В `--no-tui`:

- размер ответа выводится всегда: число строк и байты
- тело ответа управляется через `--response-body none|preview`
- фильтрация использует тот же structured filter, что и TUI

Для сохранения событий:

- `--save-file` работает и в TUI, и в `--no-tui`
- по умолчанию формат `jsonl`
- `--save-profile` управляет полнотой метаданных
- `--save-response` управляет сохранением preview ответа

## Docker Compose стенд

В репозитории добавлен готовый интеграционный пример:

- [docker-compose.yaml](./docker-compose.yaml)
- [Dockerfile](./Dockerfile)
- [demo_pg_client.py](./demo_pg_client.py)
- [postgres-init.sql](./docker/postgres-init.sql)

Поднять весь стенд можно так:

```bash
docker compose up --build
```

Что делает стенд:

- поднимает PostgreSQL с демонстрационными таблицами
- запускает `sqltracer.py` в режиме `--no-tui` на порту `5433`
- запускает Python-клиент, который подключается к `proxy:5433` и выполняет вставки, выборки, транзакцию с commit, транзакцию с rollback, медленный запрос и ожидаемую SQL-ошибку

Полезные команды:

```bash
docker compose logs -f proxy
docker compose logs -f client
docker compose down -v
```

## Поддерживаемые сообщения протокола

Сейчас скрипт анализирует такие сообщения PostgreSQL:

- `Query`
- `Parse`
- `Describe`
- `Bind`
- `Execute`
- `ParameterDescription`
- `CommandComplete`
- `ErrorResponse`
- `ReadyForQuery`

## Известные ограничения

- Запросы SSL/GSS намеренно отклоняются.
- Некоторые сложные случаи с pipelining могут восстанавливаться не идеально.
- Скрипт не меняет SQL, не оптимизирует его и не блокирует, а только ретранслирует и показывает.
- Постоянного хранилища для событий пока нет.
