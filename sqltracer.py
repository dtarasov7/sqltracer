#!/usr/bin/env python3
"""
Single-file PostgreSQL SQL traffic viewer with a curses TUI.

The script acts as a transparent TCP proxy between a PostgreSQL client and
server, captures SQL messages from the PostgreSQL wire protocol and renders
them in real time inside a terminal UI.

Current scope intentionally stays narrow:
- PostgreSQL only
- plain TCP only; SSL/GSS are declined so traffic remains inspectable
- one-file implementation; `psycopg` is optional for EXPLAIN, `cryptography` is optional for encrypted config
"""

from __future__ import annotations

import argparse
import contextlib
import curses
import datetime as dt
import ipaddress
import json
import logging
import math
import os
import re
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Dict, List, Optional, Set, Tuple, Union

import sqltracer_config_sources as config_sources
import sqltracer_packetio as packetio

__version__="1.0.0"
__author__="Tarasov Dmitry"

LOGGER = logging.getLogger("sqltracer")

SSL_REQUEST_CODE = 80877103
GSSENC_REQUEST_CODE = 80877104

AUTH_OK = 0
AUTH_SASL_FINAL = 12

POSTGRES_EPOCH_UNIX = 946684800
OID_TIMESTAMP = 1114
OID_TIMESTAMPTZ = 1184
OID_BOOL = 16
OID_BYTEA = 17
OID_INT8 = 20
OID_INT2 = 21
OID_INT4 = 23
OID_OID = 26
OID_UUID = 2950

SELECT_LIKE_PREFIXES = (
    "SELECT",
    "SHOW",
    "WITH",
    "VALUES",
    "EXPLAIN",
    "FETCH",
)

MAX_QUERY_CHARS = 20000
MAX_ARG_CHARS = 1000
MAX_RESPONSE_ROWS = 5
MAX_RESPONSE_BYTES = 8192
MAX_RESPONSE_CELL_CHARS = 200
MAX_NOTICE_CHARS = 300
DEFAULT_NPLUS1_THRESHOLD = 5
DEFAULT_NPLUS1_WINDOW_SECONDS = 1.0
DEFAULT_NPLUS1_COOLDOWN_SECONDS = 10.0
DEFAULT_SOCKET_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_CONNECTIONS = 200
DEFAULT_MAX_STARTUP_PACKET_BYTES = 1024 * 1024
DEFAULT_MAX_PROTOCOL_PACKET_BYTES = 32 * 1024 * 1024
DEFAULT_JSONL_FLUSH_EVERY = 50
DEFAULT_FILTER_AST_CACHE_SIZE = 256
DEFAULT_NPLUS1_MAX_TRACKED_KEYS = 5000
DEFAULT_MAX_PENDING_EVENTS_PER_CONNECTION = 1024

RE_DURATION = re.compile(r"^d([><])(\d+(?:\.\d+)?)(us|µs|ms|s|m)$", re.IGNORECASE)
RE_PLACEHOLDER = re.compile(r"\$(\d+)")
RE_FIELD_COMPARISON = re.compile(r"^([a-zA-Z_][a-zA-Z0-9_+\-]*)(:|>=|<=|!=|=|>|<)(.+)$")
RE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
RE_NUMERIC_LITERAL = re.compile(r"^[+-]?\d+(?:\.\d+)?$")
RE_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

FILTER_AST_CACHE: Dict[str, FilterNode] = {}

KEY_QUIT = ("q", "й")
KEY_DOWN = ("j", "о")
KEY_UP = ("k", "л")
KEY_HOME_ALIAS = ("g", "п")
KEY_FOLLOW = ("u", "г")
KEY_SEARCH = ("/", "?", ".", ",")
KEY_FILTER = ("f", "а")
KEY_SORT = ("s", "ы")
KEY_ANALYTICS = ("a", "ф")
KEY_TIMELINE = ("t", "е")
KEY_TX_TOGGLE = ("v", "м")
KEY_CLEAR = ("z", "я")
KEY_COPY = ("c", "с")
KEY_COPY_BOUND = ("b", "и")
KEY_EXPORT_JSON = ("w", "ц")
KEY_EXPORT_MARKDOWN = ("d", "в")
KEY_EXPLAIN = ("x", "ч")
KEY_EXPLAIN_ANALYZE = ("y", "н")
KEY_EDIT_EXPLAIN = ("e", "у")
KEY_EDIT_ANALYZE = ("r", "к")
KEY_TIMELINE_MODE = ("m", "ь")
KEY_SCROLL_LEFT = ("h", "р")
KEY_SCROLL_RIGHT = ("l", "д")
KEY_RESPONSE_PAGE_PREV = ("p", "з")
KEY_RESPONSE_PAGE_NEXT = ("n", "т")
KEY_EXPORT_RESPONSE = ("o", "щ")

INSPECTOR_RESPONSE_PAGE_SIZE = 3


@dataclass
class QueryEvent:
    """EN: Immutable captured query event shown in UI and exports.
    RU: Неизменяемое событие запроса для UI и экспорта.
    """

    event_id: str
    sequence: int
    connection_id: str
    operation: str
    query: str
    args: List[str]
    started_at: dt.datetime
    duration_ms: float
    rows_affected: int
    error: str
    tx_id: str
    status_tag: str
    slow: bool
    n_plus_1: bool
    n_plus_1_scope: str
    n_plus_1_hits: int
    n_plus_1_distinct_args: int
    normalized_query: str
    response_columns: List[str]
    response_rows: List[List[str]]
    response_total_rows: int
    response_total_bytes: int
    response_truncated: bool


@dataclass
class PendingEvent:
    """EN: In-flight query data collected before CommandComplete/ErrorResponse.
    RU: Данные выполняемого запроса до получения CommandComplete/ErrorResponse.
    """

    event_id: str
    connection_id: str
    operation: str
    query: str
    args: List[str]
    started_at: dt.datetime
    tx_id: str
    response_columns: List[str] = field(default_factory=list)
    response_rows: List[List[str]] = field(default_factory=list)
    response_total_rows: int = 0
    response_total_bytes: int = 0
    response_preview_bytes: int = 0
    response_truncated: bool = False
    started_perf: float = field(default_factory=time.perf_counter)


@dataclass
class AnalyticsRow:
    """EN: Aggregated metrics for a normalized query template.
    RU: Агрегированные метрики для нормализованного шаблона запроса.
    """

    query: str
    sample_query: str
    count: int
    total_duration_ms: float
    avg_duration_ms: float
    p95_duration_ms: float
    max_duration_ms: float
    total_rows: int
    error_count: int
    slow_count: int
    n_plus_1_count: int
    connection_count: int
    transaction_count: int


@dataclass
class TxSummary:
    """EN: Derived transaction-level summary built from visible events.
    RU: Сводка по транзакции, вычисленная из видимых событий.
    """

    tx_id: str
    connection_id: str
    started_at: dt.datetime
    finished_at: dt.datetime
    duration_ms: float
    rows_affected: int
    event_count: int
    error_count: int
    slow_count: int
    n_plus_1_count: int
    first_sequence: int
    query_preview: str


@dataclass
class DisplayRow:
    """EN: Render row model for list view (event row or transaction group row).
    RU: Модель строки списка (событие или группа транзакции).
    """

    kind: str
    event_index: int = -1
    tx_id: str = ""
    tx_event_indices: List[int] = field(default_factory=list)
    collapsed: bool = False


@dataclass
class TimelineRow:
    """EN: Render row model for timeline mode.
    RU: Модель строки для режима timeline.
    """

    kind: str
    label: str
    started_at: dt.datetime
    duration_ms: float
    summary: str
    event_index: int = -1
    tx_id: str = ""
    error: bool = False
    slow: bool = False
    n_plus_1: bool = False


@dataclass
class FilterPredicate:
    """EN: Single predicate parsed from structured filter query.
    RU: Одиночный предикат, распарсенный из structured filter.
    """

    field_name: str
    operator: str = ""
    value: str = ""
    number: float = 0.0


@dataclass
class FilterNode:
    """EN: AST node for structured filter expressions.
    RU: Узел AST для выражений structured filter.
    """

    kind: str
    predicate: Optional[FilterPredicate] = None
    children: List["FilterNode"] = field(default_factory=list)


@dataclass
class ExplainResult:
    """EN: EXPLAIN/EXPLAIN ANALYZE execution result for UI presentation.
    RU: Результат EXPLAIN/EXPLAIN ANALYZE для отображения в UI.
    """

    title: str
    content: str
    error: str = ""


@dataclass
class ConfigSettings:
    """EN: Effective runtime settings after config + CLI merge.
    RU: Итоговые настройки запуска после объединения config + CLI.
    """

    listen: str
    upstream: str
    max_events: int
    max_connections: int
    slow_ms: float
    refresh_ms: int
    socket_timeout_seconds: float
    max_startup_packet_bytes: int
    max_protocol_packet_bytes: int
    max_pending_events_per_connection: int
    no_tui: bool
    log_level: str
    log_file: str
    allow_remote_listen: bool
    client_allowlist: str
    dsn: str
    allow_unsafe_explain_analyze: bool
    filter_query: str
    response_body: str
    save_file: str
    save_format: str
    save_profile: str
    save_response: str
    report_file: str
    report_format: str
    report_top: int
    jsonl_flush_every: int
    nplus1_threshold: int
    nplus1_window: float
    nplus1_cooldown: float
    nplus1_max_tracked_keys: int
    config_path: str = ""


@dataclass
class NPlusOneResult:
    """EN: N+1 detector decision for one event.
    RU: Результат детектора N+1 для одного события.
    """

    matched: bool
    alert: bool
    count: int
    distinct_args: int
    scope: str


class NPlusOneDetector:
    """EN: Sliding-window detector for repeated SELECT-like patterns.
    RU: Детектор повторяющихся SELECT-паттернов на скользящем окне.
    """

    def __init__(
        self,
        threshold: int,
        window_seconds: float,
        cooldown_seconds: float,
        max_tracked_keys: int,
    ) -> None:
        """EN: Initialize detector thresholds and state.
        RU: Инициализировать пороги и внутреннее состояние детектора.

        Args:
            threshold (int): EN: Minimal hit count to consider N+1.
                RU: Минимум повторов для признака N+1.
            window_seconds (float): EN: Sliding window size.
                RU: Размер скользящего окна.
            cooldown_seconds (float): EN: Alert cooldown per query template.
                RU: Интервал между алертами по одному шаблону.
        """
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.max_tracked_keys = max(1, max_tracked_keys)
        self._queries: Dict[Tuple[str, str], Deque[Tuple[float, str]]] = {}
        self._last_alert: Dict[Tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def record(self, normalized_query: str, scope: str, args_signature: str, event_time: float) -> NPlusOneResult:
        """EN: Record one query hit and return current N+1 evaluation.
        RU: Учесть одно попадание запроса и вернуть оценку N+1.

        Args:
            normalized_query (str): EN: Query template used as key.
                RU: Шаблон запроса для ключа.
            scope (str): EN: Scope key (transaction/connection).
                RU: Область анализа (транзакция/соединение).
            args_signature (str): EN: Arguments fingerprint for distinct count.
                RU: Отпечаток аргументов для distinct-подсчета.
            event_time (float): EN: Event unix timestamp (seconds).
                RU: Время события (unix timestamp, секунды).

        Returns:
            NPlusOneResult: EN: match/alert state and counters.
                RU: Флаги match/alert и счетчики.
        """
        if self.threshold <= 0 or not normalized_query:
            return NPlusOneResult(False, False, 0, 0, scope)

        with self._lock:
            key = (scope, normalized_query)
            if key not in self._queries and len(self._queries) >= self.max_tracked_keys:
                oldest_key = next(iter(self._queries))
                self._queries.pop(oldest_key, None)
                self._last_alert.pop(oldest_key, None)
            hits = self._queries.setdefault(key, deque())
            cutoff = event_time - self.window_seconds
            # EN: Keep only hits inside the configured time window.
            # RU: Оставляем только попадания внутри заданного окна времени.
            while hits and hits[0][0] < cutoff:
                hits.popleft()
            hits.append((event_time, args_signature))
            count = len(hits)
            distinct_args = len({signature for _, signature in hits if signature}) or 0
            matched = count >= self.threshold and distinct_args >= min(2, self.threshold)
            if not matched:
                return NPlusOneResult(False, False, count, distinct_args, scope)

            last_alert = self._last_alert.get(key, 0.0)
            alert = event_time - last_alert >= self.cooldown_seconds
            if alert:
                self._last_alert[key] = event_time
            return NPlusOneResult(True, alert, count, distinct_args, scope)


class EventStore:
    """EN: Thread-safe event buffer and aggregate counters for UI/sinks.
    RU: Потокобезопасное хранилище событий и агрегированных счетчиков.
    """

    def __init__(
        self,
        max_events: int,
        slow_ms: float,
        nplus1_threshold: int,
        nplus1_window_seconds: float,
        nplus1_cooldown_seconds: float,
        nplus1_max_tracked_keys: int,
    ) -> None:
        """EN: Create bounded event store and detector settings.
        RU: Создать ограниченное хранилище событий и параметры детектора.

        Args:
            max_events (int): EN: Max events kept in memory.
                RU: Максимум событий в памяти.
            slow_ms (float): EN: Slow-query threshold in milliseconds.
                RU: Порог медленного запроса в миллисекундах.
            nplus1_threshold (int): EN: N+1 hit threshold.
                RU: Порог повторов N+1.
            nplus1_window_seconds (float): EN: Sliding window duration.
                RU: Длительность скользящего окна.
            nplus1_cooldown_seconds (float): EN: Cooldown between alerts.
                RU: Интервал между алертами.
        """
        self._events: Deque[QueryEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._sequence = 0
        self._active_connections = 0
        self._total_captured = 0
        self._error_count = 0
        self._slow_count = 0
        self._nplus1_count = 0
        self._slow_ms = slow_ms
        self._notices: Deque[str] = deque(maxlen=20)
        self._nplus1_detector = NPlusOneDetector(
            threshold=nplus1_threshold,
            window_seconds=nplus1_window_seconds,
            cooldown_seconds=nplus1_cooldown_seconds,
            max_tracked_keys=nplus1_max_tracked_keys,
        )

    def connection_opened(self) -> None:
        with self._condition:
            self._active_connections += 1
            self._condition.notify_all()

    def connection_closed(self) -> None:
        with self._condition:
            self._active_connections = max(0, self._active_connections - 1)
            self._condition.notify_all()

    def add(self, pending: PendingEvent, rows_affected: int, error: str, status_tag: str) -> None:
        duration_ms = (time.perf_counter() - pending.started_perf) * 1000.0
        slow = duration_ms >= self._slow_ms if self._slow_ms > 0 else False
        normalized_query = normalize_sql(pending.query)
        nplus1_result = NPlusOneResult(False, False, 0, 0, "")
        if is_nplus1_candidate(pending.operation, pending.query):
            nplus1_result = self._nplus1_detector.record(
                normalized_query=normalized_query,
                scope=pending.tx_id or pending.connection_id,
                args_signature="|".join(pending.args) if pending.args else pending.query,
                event_time=pending.started_at.timestamp(),
            )
        with self._condition:
            self._sequence += 1
            event = QueryEvent(
                event_id=pending.event_id,
                sequence=self._sequence,
                connection_id=pending.connection_id,
                operation=pending.operation,
                query=pending.query,
                args=list(pending.args),
                started_at=pending.started_at,
                duration_ms=duration_ms,
                rows_affected=rows_affected,
                error=error,
                tx_id=pending.tx_id,
                status_tag=status_tag,
                slow=slow,
                n_plus_1=nplus1_result.matched,
                n_plus_1_scope=nplus1_result.scope,
                n_plus_1_hits=nplus1_result.count,
                n_plus_1_distinct_args=nplus1_result.distinct_args,
                normalized_query=normalized_query,
                response_columns=list(pending.response_columns),
                response_rows=[list(row) for row in pending.response_rows],
                response_total_rows=pending.response_total_rows,
                response_total_bytes=pending.response_total_bytes,
                response_truncated=pending.response_truncated,
            )
            self._events.append(event)
            self._total_captured += 1
            if error:
                self._error_count += 1
            if slow:
                self._slow_count += 1
            if nplus1_result.matched:
                self._nplus1_count += 1
            if nplus1_result.alert:
                self._notices.append(
                    truncate_text(
                        f"N+1 detected in {nplus1_result.scope} "
                        f"({nplus1_result.count} hits, {nplus1_result.distinct_args} distinct args): "
                        f"{compact_query(normalized_query, 160)}",
                        MAX_NOTICE_CHARS,
                    )
                )
            self._condition.notify_all()

    def add_notice(self, message: str) -> None:
        clean = truncate_text(" ".join(sanitize_for_terminal(message).split()), MAX_NOTICE_CHARS)
        with self._condition:
            self._notices.append(clean)
            self._condition.notify_all()

    def clear(self) -> None:
        with self._condition:
            self._events.clear()
            self._condition.notify_all()

    def snapshot(self) -> Tuple[List[QueryEvent], Dict[str, int], int]:
        with self._lock:
            events = list(self._events)
            stats = {
                "active_connections": self._active_connections,
                "total_captured": self._total_captured,
                "error_count": self._error_count,
                "slow_count": self._slow_count,
                "nplus1_count": self._nplus1_count,
                "last_notice": self._notices[-1] if self._notices else "",
            }
            return events, stats, self._sequence

    def wait_for_change(self, last_sequence: int, timeout: float) -> int:
        with self._condition:
            if self._sequence <= last_sequence:
                self._condition.wait(timeout)
            return self._sequence


class PostgresProxy:
    """EN: TCP proxy accepting client connections and spawning handlers.
    RU: TCP-прокси, принимающий клиентские подключения и запускающий обработчики.
    """

    def __init__(
        self,
        listen_address: str,
        upstream_address: str,
        store: EventStore,
        max_connections: int,
        socket_timeout_seconds: float,
        max_startup_packet_bytes: int,
        max_protocol_packet_bytes: int,
        max_pending_events_per_connection: int,
        client_allowlist_networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]],
    ) -> None:
        self.listen_host, self.listen_port = parse_host_port(listen_address)
        self.upstream_host, self.upstream_port = parse_host_port(upstream_address)
        self.listen_address = listen_address
        self.upstream_address = upstream_address
        self.store = store
        self.max_connections = max_connections
        self.socket_timeout_seconds = socket_timeout_seconds
        self.max_startup_packet_bytes = max_startup_packet_bytes
        self.max_protocol_packet_bytes = max_protocol_packet_bytes
        self.max_pending_events_per_connection = max_pending_events_per_connection
        self.client_allowlist_networks = list(client_allowlist_networks)
        self._listener: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._connections: Set["PostgresProxyConnection"] = set()
        self._connections_lock = threading.Lock()

    def start(self) -> None:
        listener = socket.create_server((self.listen_host, self.listen_port), reuse_port=False)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener = listener
        self._accept_thread = threading.Thread(target=self._accept_loop, name="sqltracer-accept", daemon=True)
        self._accept_thread.start()
        LOGGER.info("proxy listening on %s and forwarding to %s", self.listen_address, self.upstream_address)
        self.store.add_notice(f"Listening on {self.listen_address}; upstream {self.upstream_address}")

    def stop(self) -> None:
        self._stop_event.set()
        if self._listener is not None:
            with contextlib.suppress(OSError):
                self._listener.close()
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=1.0)
        with self._connections_lock:
            connections = list(self._connections)
        for connection in connections:
            connection.close()
        for connection in connections:
            connection.join(timeout=1.0)

    def _accept_loop(self) -> None:
        assert self._listener is not None
        while not self._stop_event.is_set():
            try:
                client_sock, client_addr = self._listener.accept()
            except OSError:
                if not self._stop_event.is_set():
                    LOGGER.exception("listener accept failed")
                    self.store.add_notice("Listener accept failed. See log file for details.")
                return
            client_host = str(client_addr[0]) if client_addr else ""
            if not is_client_allowed(client_host, self.client_allowlist_networks):
                self.store.add_notice(f"Connection refused from {client_host}: not in client allowlist")
                with contextlib.suppress(OSError):
                    client_sock.shutdown(socket.SHUT_RDWR)
                with contextlib.suppress(OSError):
                    client_sock.close()
                continue
            with self._connections_lock:
                active_count = len(self._connections)
            if active_count >= self.max_connections:
                self.store.add_notice(
                    f"Connection refused: max_connections limit reached ({self.max_connections})"
                )
                with contextlib.suppress(OSError):
                    client_sock.shutdown(socket.SHUT_RDWR)
                with contextlib.suppress(OSError):
                    client_sock.close()
                continue
            connection = PostgresProxyConnection(
                client_sock=client_sock,
                client_addr=client_addr,
                upstream_host=self.upstream_host,
                upstream_port=self.upstream_port,
                store=self.store,
                on_close=self._remove_connection,
                socket_timeout_seconds=self.socket_timeout_seconds,
                max_startup_packet_bytes=self.max_startup_packet_bytes,
                max_protocol_packet_bytes=self.max_protocol_packet_bytes,
                max_pending_events_per_connection=self.max_pending_events_per_connection,
            )
            with self._connections_lock:
                self._connections.add(connection)
            connection.start()

    def _remove_connection(self, connection: "PostgresProxyConnection") -> None:
        with self._connections_lock:
            self._connections.discard(connection)


class PostgresProxyConnection:
    """EN: Per-connection PostgreSQL protocol relay with SQL event capture.
    RU: Обработчик одного подключения с ретрансляцией протокола и захватом SQL.
    """

    def __init__(
        self,
        client_sock: socket.socket,
        client_addr: Union[Tuple[str, int], Tuple[str, int, int, int]],
        upstream_host: str,
        upstream_port: int,
        store: EventStore,
        on_close: Callable[["PostgresProxyConnection"], None],
        socket_timeout_seconds: float,
        max_startup_packet_bytes: int,
        max_protocol_packet_bytes: int,
        max_pending_events_per_connection: int,
    ) -> None:
        self.client_sock = client_sock
        self.client_addr = client_addr
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.store = store
        self.on_close = on_close
        self.socket_timeout_seconds = socket_timeout_seconds
        self.max_startup_packet_bytes = max_startup_packet_bytes
        self.max_protocol_packet_bytes = max_protocol_packet_bytes
        self.max_pending_events_per_connection = max(1, max_pending_events_per_connection)
        self.connection_id = uuid.uuid4().hex[:8]
        self._thread = threading.Thread(target=self._run, name=f"pg-conn-{self.connection_id}", daemon=True)
        self._close_once = threading.Event()
        self._state_lock = threading.Lock()

        self.upstream_sock: Optional[socket.socket] = None
        self._prepared_statements: Dict[str, str] = {}
        self._prepared_statement_oids: Dict[str, List[int]] = {}
        self._last_parse_query = ""
        self._last_param_oids: List[int] = []
        self._last_bind_args: List[str] = []
        self._last_bind_statement = ""
        self._pending_describes: Deque[str] = deque()
        self._pending_events: Deque[PendingEvent] = deque()
        self._active_tx_id = ""
        self._event_counter = 0

    def __hash__(self) -> int:
        return hash(self.connection_id)

    def start(self) -> None:
        self.store.connection_opened()
        self._thread.start()

    def join(self, timeout: Optional[float] = None) -> None:
        self._thread.join(timeout=timeout)

    def close(self) -> None:
        if self._close_once.is_set():
            return
        self._close_once.set()
        with contextlib.suppress(OSError):
            self.client_sock.shutdown(socket.SHUT_RDWR)
        with contextlib.suppress(OSError):
            self.client_sock.close()
        if self.upstream_sock is not None:
            with contextlib.suppress(OSError):
                self.upstream_sock.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                self.upstream_sock.close()

    def _run(self) -> None:
        try:
            self.client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.client_sock.settimeout(self.socket_timeout_seconds)
            upstream_sock = socket.create_connection((self.upstream_host, self.upstream_port))
            upstream_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            upstream_sock.settimeout(self.socket_timeout_seconds)
            self.upstream_sock = upstream_sock
            self._relay_startup()

            client_thread = threading.Thread(target=self._client_to_server_loop, daemon=True)
            server_thread = threading.Thread(target=self._server_to_client_loop, daemon=True)
            client_thread.start()
            server_thread.start()
            client_thread.join()
            server_thread.join()
        except Exception as exc:  # pragma: no cover - defensive guard for runtime wiring
            LOGGER.warning("connection %s failed: %s", self.connection_id, exc)
            self.store.add_notice(
                f"Connection {self.connection_id} failed for upstream {self.upstream_host}:{self.upstream_port}: {exc}"
            )
        finally:
            self._flush_pending("connection closed")
            self.close()
            self.store.connection_closed()
            self.on_close(self)

    def _relay_startup(self) -> None:
        assert self.upstream_sock is not None
        while True:
            startup_message = packetio.read_startup_message(self.client_sock, self.max_startup_packet_bytes)
            if len(startup_message) == 8:
                request_code = struct.unpack("!I", startup_message[4:8])[0]
                if request_code == SSL_REQUEST_CODE:
                    self.client_sock.sendall(b"N")
                    continue
                if request_code == GSSENC_REQUEST_CODE:
                    self.client_sock.sendall(b"N")
                    continue
            self.upstream_sock.sendall(startup_message)
            break

        while True:
            message = packetio.read_protocol_message(self.upstream_sock, self.max_protocol_packet_bytes)
            self.client_sock.sendall(message)
            msg_type = message[:1]
            payload = message[5:]
            if msg_type == b"Z":
                return
            if msg_type == b"E":
                raise RuntimeError("authentication failed")
            if msg_type == b"R" and len(payload) >= 4:
                auth_type = struct.unpack("!I", payload[:4])[0]
                if auth_type not in (AUTH_OK, AUTH_SASL_FINAL):
                    response = packetio.read_protocol_message(self.client_sock, self.max_protocol_packet_bytes)
                    self.upstream_sock.sendall(response)

    def _client_to_server_loop(self) -> None:
        assert self.upstream_sock is not None
        while not self._close_once.is_set():
            try:
                message = packetio.read_protocol_message(self.client_sock, self.max_protocol_packet_bytes)
            except (ConnectionError, OSError):
                return
            self._handle_client_message(message[:1], message[5:])
            try:
                self.upstream_sock.sendall(message)
            except OSError:
                return

    def _server_to_client_loop(self) -> None:
        assert self.upstream_sock is not None
        while not self._close_once.is_set():
            try:
                message = packetio.read_protocol_message(self.upstream_sock, self.max_protocol_packet_bytes)
            except (ConnectionError, OSError):
                return
            self._handle_server_message(message[:1], message[5:])
            try:
                self.client_sock.sendall(message)
            except OSError:
                return

    def _handle_client_message(self, msg_type: bytes, payload: bytes) -> None:
        if msg_type == b"Q":
            query = decode_cstring_payload(payload)
            operation = infer_simple_operation(query)
            tx_id, operation = self._detect_transaction(query, operation)
            self._queue_pending_event(operation, query, [], tx_id)
            return

        if msg_type == b"P":
            statement_name, offset = read_cstring(payload, 0)
            query, offset = read_cstring(payload, offset)
            param_count = read_uint16(payload, offset)
            offset += 2
            param_oids = []
            if param_count:
                fmt = "!" + ("I" * param_count)
                param_oids = list(struct.unpack_from(fmt, payload, offset))
            with self._state_lock:
                self._last_parse_query = query
                self._last_param_oids = param_oids
                self._prepared_statements[statement_name] = query
                if statement_name:
                    self._prepared_statement_oids[statement_name] = list(param_oids)
            return

        if msg_type == b"D":
            if not payload:
                return
            object_type = payload[:1]
            name, _ = read_cstring(payload, 1)
            if object_type == b"S":
                with self._state_lock:
                    self._pending_describes.append(name)
            return

        if msg_type == b"B":
            self._handle_bind(payload)
            return

        if msg_type == b"E":
            with self._state_lock:
                query = self._last_parse_query
                if self._last_bind_statement:
                    query = self._prepared_statements.get(self._last_bind_statement, query)
                args = list(self._last_bind_args)
            operation = "Execute"
            tx_id, operation = self._detect_transaction(query, operation)
            self._queue_pending_event(operation, query, args, tx_id)

    def _handle_bind(self, payload: bytes) -> None:
        _portal, offset = read_cstring(payload, 0)
        statement_name, offset = read_cstring(payload, offset)
        format_code_count = read_uint16(payload, offset)
        offset += 2
        format_codes: List[int] = []
        if format_code_count:
            fmt = "!" + ("h" * format_code_count)
            format_codes = list(struct.unpack_from(fmt, payload, offset))
            offset += 2 * format_code_count
        param_count = read_uint16(payload, offset)
        offset += 2

        with self._state_lock:
            param_oids = list(self._last_param_oids)
            if statement_name:
                param_oids = list(self._prepared_statement_oids.get(statement_name, param_oids))

        args: List[str] = []
        for index in range(param_count):
            param_length = read_int32(payload, offset)
            offset += 4
            if param_length == -1:
                args.append("NULL")
                continue
            raw = payload[offset : offset + param_length]
            offset += param_length
            oid = param_oids[index] if index < len(param_oids) else 0
            is_binary = parameter_uses_binary_format(format_codes, index)
            args.append(decode_parameter(raw, oid, is_binary))

        with self._state_lock:
            self._last_bind_statement = statement_name
            self._last_bind_args = args

    def _handle_server_message(self, msg_type: bytes, payload: bytes) -> None:
        if msg_type == b"T":
            self._store_row_description(payload)
            return

        if msg_type == b"D":
            self._store_data_row(payload)
            return

        if msg_type == b"t":
            parameter_count = read_uint16(payload, 0)
            oids: List[int] = []
            if parameter_count:
                fmt = "!" + ("I" * parameter_count)
                oids = list(struct.unpack_from(fmt, payload, 2))
            with self._state_lock:
                if not self._pending_describes:
                    return
                statement_name = self._pending_describes.popleft()
                if statement_name:
                    self._prepared_statement_oids[statement_name] = oids
                else:
                    self._last_param_oids = oids
            return

        if msg_type == b"C":
            command_tag = decode_cstring_payload(payload)
            self._finish_pending(rows_affected=parse_rows_affected(command_tag), error="", status_tag=command_tag)
            return

        if msg_type == b"E":
            error_message = parse_error_response(payload)
            self._finish_pending(rows_affected=0, error=error_message, status_tag="ERROR")
            return

        if msg_type == b"Z":
            with self._state_lock:
                self._pending_describes.clear()

    def _queue_pending_event(self, operation: str, query: str, args: List[str], tx_id: str) -> None:
        if not query:
            return
        pending = PendingEvent(
            event_id=self._next_event_id(),
            connection_id=self.connection_id,
            operation=operation,
            query=truncate_text(query, MAX_QUERY_CHARS),
            args=[truncate_text(arg, MAX_ARG_CHARS) for arg in args],
            started_at=dt.datetime.now(dt.timezone.utc),
            tx_id=tx_id,
        )
        with self._state_lock:
            if len(self._pending_events) >= self.max_pending_events_per_connection:
                raise RuntimeError(
                    f"pending query limit exceeded ({self.max_pending_events_per_connection}) for connection {self.connection_id}"
                )
            self._pending_events.append(pending)

    def _finish_pending(self, rows_affected: int, error: str, status_tag: str) -> None:
        with self._state_lock:
            if not self._pending_events:
                return
            pending = self._pending_events.popleft()
        self.store.add(pending, rows_affected=rows_affected, error=error, status_tag=status_tag)

    def _flush_pending(self, reason: str) -> None:
        with self._state_lock:
            pending = list(self._pending_events)
            self._pending_events.clear()
            self._pending_describes.clear()
        for item in pending:
            self.store.add(item, rows_affected=0, error=reason, status_tag="DISCONNECTED")

    def _next_event_id(self) -> str:
        with self._state_lock:
            self._event_counter += 1
            return f"{self.connection_id}-{self._event_counter}"

    def _store_row_description(self, payload: bytes) -> None:
        columns = parse_row_description(payload)
        with self._state_lock:
            if not self._pending_events:
                return
            self._pending_events[0].response_columns = [truncate_text(name, MAX_RESPONSE_CELL_CHARS) for name in columns]

    def _store_data_row(self, payload: bytes) -> None:
        row = parse_data_row(payload)
        with self._state_lock:
            if not self._pending_events:
                return
            pending = self._pending_events[0]
            pending.response_total_rows += 1
            pending.response_total_bytes += sum(len(value) for value in row if value is not None)
            if pending.response_truncated:
                return

            normalized_row = [truncate_text(decode_result_value(value), MAX_RESPONSE_CELL_CHARS) for value in row]
            serialized_size = sum(len(item.encode("utf-8", errors="replace")) for item in normalized_row)
            projected_rows = len(pending.response_rows) + 1
            projected_bytes = pending.response_preview_bytes + serialized_size

            # EN: Keep preview bounded by row count and byte size to avoid UI/memory blowups.
            # RU: Ограничиваем preview по числу строк и байтам, чтобы не перегружать UI/память.
            if projected_rows > MAX_RESPONSE_ROWS or projected_bytes > MAX_RESPONSE_BYTES:
                pending.response_truncated = True
                return

            pending.response_rows.append(normalized_row)
            pending.response_preview_bytes = projected_bytes

    def _detect_transaction(self, query: str, default_operation: str) -> Tuple[str, str]:
        normalized = query.strip().upper()
        with self._state_lock:
            if normalized.startswith("BEGIN"):
                self._active_tx_id = str(uuid.uuid4())
                return self._active_tx_id, "BEGIN"
            if normalized.startswith("COMMIT"):
                tx_id = self._active_tx_id
                self._active_tx_id = ""
                return tx_id, "COMMIT"
            if normalized.startswith("ROLLBACK"):
                tx_id = self._active_tx_id
                self._active_tx_id = ""
                return tx_id, "ROLLBACK"
            return self._active_tx_id, default_operation


class CursesApp:
    """EN: Main curses application with list/analytics/timeline/inspector views.
    RU: Основное curses-приложение с режимами list/analytics/timeline/inspector.
    """

    def __init__(
        self,
        store: EventStore,
        proxy: PostgresProxy,
        refresh_ms: int,
        listen: str,
        upstream: str,
        explain_dsn: str,
        allow_unsafe_explain_analyze: bool,
        initial_filter: str = "",
    ) -> None:
        self.store = store
        self.proxy = proxy
        self.refresh_ms = refresh_ms
        self.listen = listen
        self.upstream = upstream
        self.explain_dsn = explain_dsn
        self.allow_unsafe_explain_analyze = allow_unsafe_explain_analyze

        self.view = "list"
        self.cursor = 0
        self.follow = True
        self.paused = False
        self.last_sequence = 0
        self.search_query = ""
        self.filter_query = initial_filter
        self.input_mode = ""
        self.input_buffer = ""
        self.sort_mode = "time"
        self.collapsed_txs: Dict[str, bool] = {}
        self.analytics_cursor = 0
        self.analytics_hscroll = 0
        self.analytics_sort_mode = "total"
        self.timeline_mode = "query"
        self.timeline_cursor = 0
        self.inspector_row: Optional[DisplayRow] = None
        self.inspector_scroll = 0
        self.inspector_hscroll = 0
        self.inspector_response_page = 0
        self.modal_mode = ""
        self.modal_title = ""
        self.modal_lines: List[str] = []
        self.explain_result: Optional[ExplainResult] = None
        self.explain_scroll = 0
        self.explain_hscroll = 0
        self.explain_return_view = "list"
        self.explain_last_query = ""
        self.explain_last_args: List[str] = []
        self.explain_last_analyze = False

    def run(self) -> None:
        curses.wrapper(self._main)

    def _main(self, stdscr) -> None:
        init_colors()
        stdscr.keypad(True)
        stdscr.timeout(self.refresh_ms)
        with contextlib.suppress(curses.error):
            curses.curs_set(0)

        while True:
            events, stats, sequence = self.store.snapshot()
            filter_ast = compile_filter(self.filter_query) if self.filter_query else None
            visible_indices = self._visible_event_indices(events, filter_ast)
            tx_summaries = self._build_tx_summaries(events, visible_indices)
            display_rows = self._build_display_rows(events, visible_indices, tx_summaries)
            analytics_rows = self._build_analytics_rows(events, visible_indices)
            timeline_rows = self._build_timeline_rows(events, visible_indices, tx_summaries)

            if not self.paused and sequence != self.last_sequence:
                self.last_sequence = sequence
                if self.follow and self.view == "list" and display_rows:
                    self.cursor = len(display_rows) - 1

            self._clamp_state(display_rows, analytics_rows, timeline_rows)
            self._render(stdscr, events, stats, display_rows, tx_summaries, analytics_rows, timeline_rows)

            try:
                key = stdscr.get_wch()
            except curses.error:
                continue
            if self._handle_key(stdscr, key, events, display_rows, tx_summaries, analytics_rows, timeline_rows):
                return

    def _handle_key(
        self,
        stdscr,
        key: Union[int, str],
        events: List[QueryEvent],
        display_rows: List[DisplayRow],
        tx_summaries: Dict[str, TxSummary],
        analytics_rows: List[AnalyticsRow],
        timeline_rows: List[TimelineRow],
    ) -> bool:
        if self.modal_lines:
            return self._handle_modal_key(key)
        if self.input_mode:
            return self._handle_input_key(key)

        if self.view == "analytics":
            return self._handle_analytics_key(key, analytics_rows)
        if self.view == "timeline":
            return self._handle_timeline_key(key, timeline_rows)
        if self.view == "inspector":
            return self._handle_inspector_key(stdscr, key, events, tx_summaries)
        if self.view == "explain":
            return self._handle_explain_key(stdscr, key)
        return self._handle_list_key(stdscr, key, events, display_rows, tx_summaries)

    def _handle_input_key(self, key: Union[int, str]) -> bool:
        if key_is_escape(key):
            self.input_mode = ""
            self.input_buffer = ""
            return False
        if key_is_enter(key):
            if self.input_mode == "search":
                self.search_query = self.input_buffer.strip()
            elif self.input_mode == "filter":
                self.filter_query = self.input_buffer.strip()
            self.input_mode = ""
            self.input_buffer = ""
            self.cursor = 0
            self.follow = False
            return False
        if key_is_backspace(key):
            self.input_buffer = self.input_buffer[:-1]
            return False
        if isinstance(key, str) and key.isprintable():
            self.input_buffer += key
        return False

    def _handle_modal_key(self, key: Union[int, str]) -> bool:
        if self.modal_mode == "confirm_exit":
            if key_is_enter(key) or key_matches(key, *KEY_QUIT, "y", "н"):
                return True
            if key_is_escape(key) or key_matches(key, "n", "т"):
                self._clear_modal()
            return False
        self._clear_modal()
        return False

    def _handle_list_key(
        self,
        stdscr,
        key: Union[int, str],
        events: List[QueryEvent],
        display_rows: List[DisplayRow],
        tx_summaries: Dict[str, TxSummary],
    ) -> bool:
        selected_row = self._selected_row(display_rows)
        selected_event = self._selected_event(events, selected_row)

        if key_matches(key, *KEY_QUIT):
            self._confirm_exit()
            return False
        if key_is_escape(key):
            if self.search_query or self.filter_query:
                self.search_query = ""
                self.filter_query = ""
                self.cursor = 0
            else:
                self._confirm_exit()
            return False
        if key in (curses.KEY_DOWN,) or key_matches(key, *KEY_DOWN):
            if display_rows:
                self.cursor = min(len(display_rows) - 1, self.cursor + 1)
                self.follow = self.cursor == len(display_rows) - 1
            return False
        if key in (curses.KEY_UP,) or key_matches(key, *KEY_UP):
            if display_rows:
                self.cursor = max(0, self.cursor - 1)
                self.follow = False
            return False
        if key in (curses.KEY_HOME,) or key_matches(key, *KEY_HOME_ALIAS):
            self.cursor = 0
            self.follow = False
            return False
        if key in (curses.KEY_END,):
            if display_rows:
                self.cursor = len(display_rows) - 1
            self.follow = False
            return False
        if key_matches(key, *KEY_SEARCH):
            self.input_mode = "search"
            self.input_buffer = self.search_query
            return False
        if key_matches(key, *KEY_FILTER):
            self.input_mode = "filter"
            self.input_buffer = self.filter_query
            return False
        if key_matches(key, *KEY_SORT):
            self.sort_mode = "duration" if self.sort_mode == "time" else "time"
            self.cursor = 0
            self.follow = False
            return False
        if key_matches(key, *KEY_ANALYTICS):
            self.view = "analytics"
            self.analytics_cursor = 0
            self.analytics_hscroll = 0
            return False
        if key_matches(key, *KEY_TIMELINE):
            self.view = "timeline"
            self.timeline_cursor = 0
            return False
        if key_matches(key, *KEY_FOLLOW):
            if display_rows:
                self.cursor = len(display_rows) - 1
            self.follow = True
            return False
        if key == " ":
            self.paused = not self.paused
            self.store.add_notice("Paused" if self.paused else "Live updates resumed")
            return False
        if key_matches(key, *KEY_TX_TOGGLE):
            if not self._transactions_grouped():
                self.store.add_notice("Transaction collapse is available only in grouped time view")
                return False
            if self._toggle_selected_tx(selected_row, tx_summaries):
                self.follow = False
            return False
        if key in (curses.KEY_LEFT,):
            if not self._transactions_grouped():
                return False
            if self._set_selected_tx_collapsed(selected_row, tx_summaries, True):
                self.follow = False
            return False
        if key in (curses.KEY_RIGHT,):
            if not self._transactions_grouped():
                return False
            if self._set_selected_tx_collapsed(selected_row, tx_summaries, False):
                self.follow = False
            return False
        if key_matches(key, *KEY_CLEAR):
            self.store.clear()
            self.cursor = 0
            self.follow = True
            self.last_sequence = 0
            return False
        if key_matches(key, *KEY_COPY):
            if selected_event is not None:
                copy_text = selected_event.query
                if copy_to_clipboard(copy_text):
                    self.store.add_notice("Query copied to clipboard")
                else:
                    self.store.add_notice("Clipboard unavailable; query not copied")
            return False
        if key_matches(key, *KEY_COPY_BOUND):
            if selected_event is not None:
                copy_text = bind_query_preview(selected_event.query, selected_event.args)
                if copy_to_clipboard(copy_text):
                    self.store.add_notice("Bound query copied to clipboard")
                else:
                    self.store.add_notice("Clipboard unavailable; bound query not copied")
            return False
        if key_matches(key, *KEY_EXPORT_RESPONSE):
            if selected_event is None:
                self.store.add_notice("No event selected for response export")
                return False
            path = write_response_export_file(selected_event)
            self.store.add_notice(f"Response exported to {path}")
            return False
        if key_matches(key, *KEY_EXPORT_JSON):
            self._export_events(events, display_rows, "json")
            return False
        if key_matches(key, *KEY_EXPORT_MARKDOWN):
            self._export_events(events, display_rows, "markdown")
            return False
        if any(
            key_matches(key, *aliases)
            for aliases in (KEY_EXPLAIN, KEY_EXPLAIN_ANALYZE, KEY_EDIT_EXPLAIN, KEY_EDIT_ANALYZE)
        ):
            analyze = key_matches(key, *KEY_EXPLAIN_ANALYZE) or key_matches(key, *KEY_EDIT_ANALYZE)
            edit = key_matches(key, *KEY_EDIT_EXPLAIN) or key_matches(key, *KEY_EDIT_ANALYZE)
            if selected_event is not None:
                self._open_explain(stdscr, selected_event, analyze, edit)
            return False
        if key_is_enter(key):
            self._open_inspector(selected_row)
            return False
        return False

    def _handle_analytics_key(self, key: Union[int, str], rows: List[AnalyticsRow]) -> bool:
        if key_matches(key, *KEY_QUIT):
            self.view = "list"
            return False
        if key in (curses.KEY_DOWN,) or key_matches(key, *KEY_DOWN):
            if rows:
                self.analytics_cursor = min(len(rows) - 1, self.analytics_cursor + 1)
            return False
        if key in (curses.KEY_UP,) or key_matches(key, *KEY_UP):
            if rows:
                self.analytics_cursor = max(0, self.analytics_cursor - 1)
            return False
        if key in (curses.KEY_NPAGE, 4):
            self.analytics_cursor = min(len(rows) - 1, self.analytics_cursor + max(1, len(rows) // 4))
            return False
        if key in (curses.KEY_PPAGE, 21):
            self.analytics_cursor = max(0, self.analytics_cursor - max(1, len(rows) // 4))
            return False
        if key in (curses.KEY_LEFT,) or key_matches(key, *KEY_SCROLL_LEFT):
            self.analytics_hscroll = max(0, self.analytics_hscroll - 2)
            return False
        if key in (curses.KEY_RIGHT,) or key_matches(key, *KEY_SCROLL_RIGHT):
            self.analytics_hscroll += 2
            return False
        if key_matches(key, *KEY_SORT):
            self.analytics_sort_mode = next_analytics_sort_mode(self.analytics_sort_mode)
            self.analytics_cursor = 0
            return False
        if key_matches(key, *KEY_COPY) and rows:
            row = rows[self.analytics_cursor]
            if copy_to_clipboard(row.query):
                self.store.add_notice("Normalized query copied to clipboard")
            else:
                self.store.add_notice("Clipboard unavailable; analytics query not copied")
            return False
        if key_matches(key, *KEY_EXPORT_JSON):
            self._export_current_view("json")
            return False
        if key_matches(key, *KEY_EXPORT_MARKDOWN):
            self._export_current_view("markdown")
            return False
        return False

    def _handle_timeline_key(self, key: Union[int, str], timeline_rows: List[TimelineRow]) -> bool:
        page = 5
        max_cursor = max(0, len(timeline_rows) - 1)
        if key_matches(key, *KEY_QUIT):
            self.view = "list"
            return False
        if key_matches(key, *KEY_TIMELINE_MODE):
            self.timeline_mode = "tx" if self.timeline_mode == "query" else "query"
            self.timeline_cursor = 0
            return False
        if key in (curses.KEY_DOWN,) or key_matches(key, *KEY_DOWN):
            self.timeline_cursor = min(max_cursor, self.timeline_cursor + 1)
            return False
        if key in (curses.KEY_UP,) or key_matches(key, *KEY_UP):
            self.timeline_cursor = max(0, self.timeline_cursor - 1)
            return False
        if key in (curses.KEY_NPAGE, 4):
            self.timeline_cursor = min(max_cursor, self.timeline_cursor + page)
            return False
        if key in (curses.KEY_PPAGE, 21):
            self.timeline_cursor = max(0, self.timeline_cursor - page)
            return False
        if key_matches(key, *KEY_COPY) and timeline_rows:
            row = timeline_rows[self.timeline_cursor]
            text = row.summary if row.kind == "tx" else row.label
            if copy_to_clipboard(text):
                self.store.add_notice("Timeline row copied to clipboard")
            else:
                self.store.add_notice("Clipboard unavailable; timeline row not copied")
            return False
        return False

    def _handle_explain_key(self, stdscr, key: Union[int, str]) -> bool:
        content_lines = self._explain_lines()
        if key_matches(key, *KEY_QUIT):
            self.view = self.explain_return_view
            return False
        if key in (curses.KEY_DOWN,) or key_matches(key, *KEY_DOWN):
            self.explain_scroll = min(max(len(content_lines) - 1, 0), self.explain_scroll + 1)
            return False
        if key in (curses.KEY_UP,) or key_matches(key, *KEY_UP):
            self.explain_scroll = max(0, self.explain_scroll - 1)
            return False
        if key in (curses.KEY_LEFT,) or key_matches(key, *KEY_SCROLL_LEFT):
            self.explain_hscroll = max(0, self.explain_hscroll - 2)
            return False
        if key in (curses.KEY_RIGHT,) or key_matches(key, *KEY_SCROLL_RIGHT):
            self.explain_hscroll += 2
            return False
        if key in (curses.KEY_NPAGE, 4):
            self.explain_scroll = min(max(len(content_lines) - 1, 0), self.explain_scroll + 10)
            return False
        if key in (curses.KEY_PPAGE, 21):
            self.explain_scroll = max(0, self.explain_scroll - 10)
            return False
        if key_matches(key, *KEY_COPY) and self.explain_result is not None:
            if copy_to_clipboard(self.explain_result.content):
                self.store.add_notice("Explain plan copied to clipboard")
            else:
                self.store.add_notice("Clipboard unavailable; plan not copied")
            return False
        if (key_matches(key, *KEY_EDIT_EXPLAIN) or key_matches(key, *KEY_EDIT_ANALYZE)) and self.explain_last_query:
            analyze = key_matches(key, *KEY_EDIT_ANALYZE)
            if not self._ensure_explain_available():
                return False
            edited_query = open_external_editor(stdscr, self.explain_last_query, analyze)
            if edited_query:
                if (
                    analyze
                    and not self.allow_unsafe_explain_analyze
                    and not is_explain_analyze_read_only(edited_query)
                ):
                    self._show_modal(
                        "EXPLAIN ANALYZE blocked",
                        [
                            "Blocked for non-read-only statement.",
                            "Use EXPLAIN or start with --allow-unsafe-explain-analyze.",
                        ],
                    )
                    return False
                self._run_explain(edited_query, self.explain_last_args, analyze)
            return False
        return False

    def _handle_inspector_key(
        self,
        stdscr,
        key: Union[int, str],
        events: List[QueryEvent],
        tx_summaries: Dict[str, TxSummary],
    ) -> bool:
        content_lines = self._inspector_lines(events, tx_summaries)
        selected_event = self._inspector_selected_event(events)
        if key_matches(key, *KEY_QUIT):
            self.view = "list"
            return False
        if key in (curses.KEY_DOWN,) or key_matches(key, *KEY_DOWN):
            self.inspector_scroll = min(max(len(content_lines) - 1, 0), self.inspector_scroll + 1)
            return False
        if key in (curses.KEY_UP,) or key_matches(key, *KEY_UP):
            self.inspector_scroll = max(0, self.inspector_scroll - 1)
            return False
        if key in (curses.KEY_LEFT,) or key_matches(key, *KEY_SCROLL_LEFT):
            self.inspector_hscroll = max(0, self.inspector_hscroll - 2)
            return False
        if key in (curses.KEY_RIGHT,) or key_matches(key, *KEY_SCROLL_RIGHT):
            self.inspector_hscroll += 2
            return False
        if key in (curses.KEY_NPAGE, 4):
            self.inspector_scroll = min(max(len(content_lines) - 1, 0), self.inspector_scroll + 10)
            return False
        if key in (curses.KEY_PPAGE, 21):
            self.inspector_scroll = max(0, self.inspector_scroll - 10)
            return False
        if key_matches(key, *KEY_RESPONSE_PAGE_PREV):
            if self.inspector_row is None or self.inspector_row.kind != "event" or selected_event is None:
                self.store.add_notice("Response paging is available only in query inspector")
                return False
            page_count = response_preview_page_count(selected_event, INSPECTOR_RESPONSE_PAGE_SIZE)
            if page_count <= 1:
                self.store.add_notice("Only one response preview page is available")
                return False
            self.inspector_response_page = max(0, self.inspector_response_page - 1)
            self.inspector_scroll = 0
            return False
        if key_matches(key, *KEY_RESPONSE_PAGE_NEXT):
            if self.inspector_row is None or self.inspector_row.kind != "event" or selected_event is None:
                self.store.add_notice("Response paging is available only in query inspector")
                return False
            page_count = response_preview_page_count(selected_event, INSPECTOR_RESPONSE_PAGE_SIZE)
            if page_count <= 1:
                self.store.add_notice("Only one response preview page is available")
                return False
            self.inspector_response_page = min(page_count - 1, self.inspector_response_page + 1)
            self.inspector_scroll = 0
            return False
        if key_matches(key, *KEY_EXPORT_RESPONSE):
            if selected_event is None:
                self.store.add_notice("No query selected for response export")
                return False
            path = write_response_export_file(selected_event)
            self.store.add_notice(f"Response exported to {path}")
            return False
        if key_matches(key, *KEY_COPY):
            text = self._inspector_copy_text(events, tx_summaries, bound=False)
            if text and copy_to_clipboard(text):
                self.store.add_notice("Inspector content copied to clipboard")
            else:
                self.store.add_notice("Clipboard unavailable; inspector content not copied")
            return False
        if key_matches(key, *KEY_COPY_BOUND):
            text = self._inspector_copy_text(events, tx_summaries, bound=True)
            if text and copy_to_clipboard(text):
                self.store.add_notice("Inspector bound query copied to clipboard")
            else:
                self.store.add_notice("Clipboard unavailable; bound query not copied")
            return False
        if any(
            key_matches(key, *aliases)
            for aliases in (KEY_EXPLAIN, KEY_EXPLAIN_ANALYZE, KEY_EDIT_EXPLAIN, KEY_EDIT_ANALYZE)
        ):
            analyze = key_matches(key, *KEY_EXPLAIN_ANALYZE) or key_matches(key, *KEY_EDIT_ANALYZE)
            edit = key_matches(key, *KEY_EDIT_EXPLAIN) or key_matches(key, *KEY_EDIT_ANALYZE)
            if selected_event is not None:
                self._open_explain(stdscr, selected_event, analyze, edit)
            else:
                self._show_modal("EXPLAIN unavailable", ["Selected transaction has no query suitable for EXPLAIN."])
            return False
        if key == " ":
            if self._toggle_selected_tx(self.inspector_row, tx_summaries):
                self.store.add_notice("Transaction toggle applied; return to list to see the grouping change")
            return False
        return False

    def _render(
        self,
        stdscr,
        events: List[QueryEvent],
        stats: Dict[str, int],
        display_rows: List[DisplayRow],
        tx_summaries: Dict[str, TxSummary],
        analytics_rows: List[AnalyticsRow],
        timeline_rows: List[TimelineRow],
    ) -> None:
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        if height < 12 or width < 60:
            draw_line(stdscr, 0, 0, "Terminal is too small. Need at least 60x12.", width, curses.A_BOLD)
            stdscr.refresh()
            return

        if self.view == "analytics":
            self._render_analytics(stdscr, width, height, stats, analytics_rows)
        elif self.view == "timeline":
            self._render_timeline(stdscr, width, height, stats, timeline_rows)
        elif self.view == "inspector":
            self._render_inspector(stdscr, width, height, stats, events, tx_summaries)
        elif self.view == "explain":
            self._render_explain(stdscr, width, height, stats)
        else:
            self._render_list(stdscr, width, height, stats, events, display_rows, tx_summaries)
        if self.modal_lines:
            self._render_modal(stdscr, width, height)
        stdscr.refresh()

    def _render_list(
        self,
        stdscr,
        width: int,
        height: int,
        stats: Dict[str, int],
        events: List[QueryEvent],
        display_rows: List[DisplayRow],
        tx_summaries: Dict[str, TxSummary],
    ) -> None:
        has_notice = bool(stats.get("last_notice"))
        header_rows = 3 if has_notice else 2
        list_height = max(header_rows + 4, int(height * 0.55))
        detail_start = list_height + 1
        footer_row = height - 1
        selected_row = self._selected_row(display_rows)

        header = (
            f" sqltracer | listen {self.listen} -> {self.upstream} | "
            f"active {stats['active_connections']} | total {stats['total_captured']} | "
            f"errors {stats['error_count']} | slow {stats['slow_count']} | n+1 {stats['nplus1_count']} | "
            f"view {len(display_rows)}/{len(events)} | sort {self.sort_mode} | "
            f"{'GROUPED' if self._transactions_grouped() else 'FLAT'} | "
            f"{'PAUSED' if self.paused else 'LIVE'}{' | FOLLOW' if self.follow else ''}"
        )
        draw_line(stdscr, 0, 0, header, width, curses.A_REVERSE)
        if has_notice:
            draw_line(stdscr, 1, 0, " notice: " + stats["last_notice"], width, curses.color_pair(2) | curses.A_BOLD)

        columns = f"{'#':>4}  {'Time':<10} {'Kind':<10} {'ms':>8} {'Rows':>7} {'Status':<8} Query"
        draw_line(stdscr, header_rows - 1, 0, columns, width, curses.A_BOLD)

        row_count = max(1, list_height - header_rows - 1)
        if display_rows:
            start = max(0, self.cursor - row_count // 2)
            end = min(len(display_rows), start + row_count)
            start = max(0, end - row_count)
            screen_row = header_rows
            for screen_pos, visible_pos in enumerate(range(start, end)):
                row = display_rows[visible_pos]
                attr = style_for_display_row(row, events, tx_summaries)
                if visible_pos == self.cursor:
                    attr |= curses.A_REVERSE
                draw_line(
                    stdscr,
                    screen_row + screen_pos,
                    0,
                    format_display_row(row, events, tx_summaries, grouped=self._transactions_grouped()),
                    width,
                    attr,
                )
        else:
            draw_line(stdscr, header_rows + 1, 0, "No visible events. Adjust search/filter or generate traffic.", width, 0)

        stdscr.hline(list_height, 0, "-", width)
        draw_line(stdscr, detail_start, 0, " Details ", width, curses.A_BOLD)
        detail_lines = build_detail_lines(selected_row, events, tx_summaries, width)
        for offset, line in enumerate(detail_lines, start=detail_start + 1):
            if offset >= footer_row:
                break
            draw_line(stdscr, offset, 0, line, width, 0)

        footer = self._footer_text()
        draw_line(stdscr, footer_row, 0, footer, width, curses.A_REVERSE)

    def _render_analytics(self, stdscr, width: int, height: int, stats: Dict[str, int], rows: List[AnalyticsRow]) -> None:
        draw_line(
            stdscr,
            0,
            0,
            f" Analytics | sort {self.analytics_sort_mode} | rows {len(rows)} | notice {stats.get('last_notice', '')}",
            width,
            curses.A_REVERSE,
        )
        header = " #    Cnt    Avg     P95     Max    Total  Rows Err Slw N+1 Conn Tx Query"
        draw_line(stdscr, 1, 0, header, width, curses.A_BOLD)
        visible_rows = max(1, height - 5)
        start = max(0, self.analytics_cursor - visible_rows // 2)
        end = min(len(rows), start + visible_rows)
        start = max(0, end - visible_rows)
        for screen_row, row_index in enumerate(range(start, end), start=2):
            row = rows[row_index]
            query = apply_hscroll(row.query, self.analytics_hscroll)
            text = (
                f"{row_index + 1:>4} "
                f"{row.count:>6} "
                f"{format_ms(row.avg_duration_ms):>7} "
                f"{format_ms(row.p95_duration_ms):>7} "
                f"{format_ms(row.max_duration_ms):>7} "
                f"{format_ms(row.total_duration_ms):>8} "
                f"{row.total_rows:>5} "
                f"{row.error_count:>3} "
                f"{row.slow_count:>3} "
                f"{row.n_plus_1_count:>3} "
                f"{row.connection_count:>4} "
                f"{row.transaction_count:>2} "
                f"{query}"
            )
            attr = curses.A_REVERSE if row_index == self.analytics_cursor else 0
            draw_line(stdscr, screen_row, 0, text, width, attr)
        if rows:
            selected = rows[self.analytics_cursor]
            detail = (
                f" sample: {compact_query(selected.sample_query or selected.query, max(20, width - 10))}"
            )
            draw_line(stdscr, height - 2, 0, detail, width, 0)
        footer = " q back | j/k move | s sort | h/l scroll | c copy | w json | d md "
        draw_line(stdscr, height - 1, 0, footer, width, curses.A_REVERSE)

    def _render_timeline(
        self,
        stdscr,
        width: int,
        height: int,
        stats: Dict[str, int],
        timeline_rows: List[TimelineRow],
    ) -> None:
        draw_line(
            stdscr,
            0,
            0,
            f" Timeline | mode {self.timeline_mode} | rows {len(timeline_rows)} | notice {stats.get('last_notice', '')}",
            width,
            curses.A_REVERSE,
        )
        if not timeline_rows:
            draw_line(stdscr, 2, 0, "No query events to show in timeline.", width, 0)
            draw_line(stdscr, height - 1, 0, " q back ", width, curses.A_REVERSE)
            return

        label_width = min(40, max(20, width // 3))
        chart_width = max(10, width - label_width - 2)
        visible_rows = max(1, height - 5)
        start = max(0, self.timeline_cursor - visible_rows // 2)
        end = min(len(timeline_rows), start + visible_rows)
        start = max(0, end - visible_rows)
        min_ts = min(row.started_at.timestamp() for row in timeline_rows)
        max_ts = max(row.started_at.timestamp() + (row.duration_ms / 1000.0) for row in timeline_rows)
        span = max(max_ts - min_ts, 0.001)

        axis = " " * label_width + "|" + render_timeline_axis(span, chart_width)
        draw_line(stdscr, 1, 0, axis, width, curses.A_BOLD)

        for screen_row, index in enumerate(range(start, end), start=2):
            row = timeline_rows[index]
            label = compact_query(row.label, label_width - 1).ljust(label_width)
            start_pos = int(((row.started_at.timestamp() - min_ts) / span) * max(chart_width - 1, 1))
            bar_width = max(1, int(math.ceil((row.duration_ms / 1000.0) / span * chart_width)))
            bar_end = min(chart_width, start_pos + bar_width)
            bar = " " * start_pos + ("#" * max(1, bar_end - start_pos))
            attr = style_for_timeline_row(row)
            if index == self.timeline_cursor:
                attr |= curses.A_REVERSE
            draw_line(stdscr, screen_row, 0, label + "|" + bar, width, attr)

        selected = timeline_rows[self.timeline_cursor]
        draw_line(stdscr, height - 2, 0, selected.summary, width, 0)
        footer = " q back | j/k move | PgUp/PgDn page | m mode | c copy "
        draw_line(stdscr, height - 1, 0, footer, width, curses.A_REVERSE)

    def _render_explain(self, stdscr, width: int, height: int, stats: Dict[str, int]) -> None:
        title = self.explain_result.title if self.explain_result else "Explain"
        draw_line(
            stdscr,
            0,
            0,
            f" {title} | notice {stats.get('last_notice', '')}",
            width,
            curses.A_REVERSE,
        )
        lines = self._explain_lines()
        visible_rows = max(1, height - 3)
        start = min(self.explain_scroll, max(0, len(lines) - visible_rows))
        end = min(len(lines), start + visible_rows)
        for screen_row, line_index in enumerate(range(start, end), start=1):
            draw_line(stdscr, screen_row, 0, apply_hscroll(lines[line_index], self.explain_hscroll), width, 0)
        footer = " q back | j/k scroll | h/l horiz | c copy | e edit | r edit+analyze "
        draw_line(stdscr, height - 1, 0, footer, width, curses.A_REVERSE)

    def _render_inspector(
        self,
        stdscr,
        width: int,
        height: int,
        stats: Dict[str, int],
        events: List[QueryEvent],
        tx_summaries: Dict[str, TxSummary],
    ) -> None:
        title = "Transaction Inspector" if self.inspector_row and self.inspector_row.kind == "tx" else "Query Inspector"
        draw_line(
            stdscr,
            0,
            0,
            f" {title} | notice {stats.get('last_notice', '')}",
            width,
            curses.A_REVERSE,
        )
        lines = self._inspector_lines(events, tx_summaries)
        visible_rows = max(1, height - 3)
        start = min(self.inspector_scroll, max(0, len(lines) - visible_rows))
        end = min(len(lines), start + visible_rows)
        for screen_row, line_index in enumerate(range(start, end), start=1):
            draw_line(stdscr, screen_row, 0, apply_hscroll(lines[line_index], self.inspector_hscroll), width, 0)
        footer = (
            " q back | j/k scroll | h/l horiz | p/n resp-page | o resp-json | "
            "c/b copy | x/y explain | e/r edit | v tx-toggle "
        )
        draw_line(stdscr, height - 1, 0, footer, width, curses.A_REVERSE)

    def _render_modal(self, stdscr, width: int, height: int) -> None:
        prompt = (
            "Enter/q: exit | Esc/n: cancel"
            if self.modal_mode == "confirm_exit"
            else "Press any key to close."
        )
        lines = [self.modal_title] + self.modal_lines + ["", prompt]
        box_width = min(max(len(max(lines, key=len)) + 4, 30), max(20, width - 4))
        box_height = min(len(lines) + 2, max(6, height - 4))
        top = max(1, (height - box_height) // 2)
        left = max(2, (width - box_width) // 2)
        for row in range(box_height):
            draw_line(stdscr, top + row, left, " " * box_width, width, curses.A_REVERSE)
        border = "+" + "-" * max(0, box_width - 2) + "+"
        draw_line(stdscr, top, left, border, width, curses.A_REVERSE)
        draw_line(stdscr, top + box_height - 1, left, border, width, curses.A_REVERSE)
        for row in range(1, box_height - 1):
            inner = "|" + " " * max(0, box_width - 2) + "|"
            draw_line(stdscr, top + row, left, inner, width, curses.A_REVERSE)
        for index, line in enumerate(lines[: box_height - 2], start=1):
            draw_line(
                stdscr,
                top + index,
                left + 2,
                line,
                width,
                curses.A_REVERSE | curses.A_BOLD if index == 1 else curses.A_REVERSE,
            )

    def _footer_text(self) -> str:
        if self.input_mode == "search":
            return f" search: {self.input_buffer}"
        if self.input_mode == "filter":
            return f" filter: {self.input_buffer}"
        return (
            " q quit | / or . search | f filter | s sort | enter inspect | a analytics | t timeline | "
            "x explain | y analyze | e edit | r edit+analyze | c copy | b bound | o resp-json | "
            "w json | d md | u follow | space pause | v tx-collapse | z clear "
        )

    def _visible_event_indices(self, events: List[QueryEvent], filter_ast: Optional[FilterNode]) -> List[int]:
        indices = [
            index
            for index, event in enumerate(events)
            if matches_event(event, self.search_query, filter_ast)
        ]
        if self.sort_mode == "duration":
            indices.sort(key=lambda idx: (-events[idx].duration_ms, events[idx].sequence))
        else:
            indices.sort(key=lambda idx: events[idx].sequence)
        return indices

    def _selected_row(self, display_rows: List[DisplayRow]) -> Optional[DisplayRow]:
        if not display_rows:
            return None
        self.cursor = max(0, min(self.cursor, len(display_rows) - 1))
        return display_rows[self.cursor]

    def _selected_event(self, events: List[QueryEvent], row: Optional[DisplayRow]) -> Optional[QueryEvent]:
        if row is None or row.kind != "event" or row.event_index < 0 or row.event_index >= len(events):
            return None
        return events[row.event_index]

    def _open_inspector(self, row: Optional[DisplayRow]) -> None:
        if row is None:
            return
        self.inspector_row = row
        self.inspector_scroll = 0
        self.inspector_hscroll = 0
        self.inspector_response_page = 0
        self.view = "inspector"

    def _inspector_selected_event(self, events: List[QueryEvent]) -> Optional[QueryEvent]:
        row = self.inspector_row
        if row is None:
            return None
        if row.kind == "event" and row.event_index >= 0:
            if row.event_index >= len(events):
                return None
            return events[row.event_index]
        for index in row.tx_event_indices:
            if index < 0 or index >= len(events):
                continue
            event = events[index]
            if event.query and event.operation not in ("BEGIN", "COMMIT", "ROLLBACK"):
                return event
        return None

    def _inspector_lines(self, events: List[QueryEvent], tx_summaries: Dict[str, TxSummary]) -> List[str]:
        row = self.inspector_row
        if row is None:
            return ["No inspector target selected."]
        if row.kind == "tx":
            return build_tx_inspector_lines(tx_summaries.get(row.tx_id), events, row.tx_event_indices)
        if row.event_index < 0 or row.event_index >= len(events):
            return ["No inspector target selected."]
        event = events[row.event_index]
        page_count = response_preview_page_count(event, INSPECTOR_RESPONSE_PAGE_SIZE)
        self.inspector_response_page = max(0, min(self.inspector_response_page, page_count - 1))
        return build_event_inspector_lines(
            event,
            events,
            response_page=self.inspector_response_page,
            response_page_size=INSPECTOR_RESPONSE_PAGE_SIZE,
        )

    def _inspector_copy_text(
        self,
        events: List[QueryEvent],
        tx_summaries: Dict[str, TxSummary],
        bound: bool,
    ) -> str:
        row = self.inspector_row
        if row is None:
            return ""
        if row.kind == "tx":
            summary = tx_summaries.get(row.tx_id)
            if summary is None:
                return ""
            if bound:
                event = self._inspector_selected_event(events)
                if event is None:
                    return ""
                return bind_query_preview(event.query, event.args)
            return "\n".join(build_tx_inspector_lines(summary, events, row.tx_event_indices))
        if row.event_index < 0 or row.event_index >= len(events):
            return ""
        event = events[row.event_index]
        return bind_query_preview(event.query, event.args) if bound else event.query

    def _transactions_grouped(self) -> bool:
        return self.sort_mode == "time" and not self.search_query and not self.filter_query

    def _build_tx_summaries(self, events: List[QueryEvent], visible_indices: List[int]) -> Dict[str, TxSummary]:
        grouped: Dict[str, List[QueryEvent]] = {}
        for index in visible_indices:
            event = events[index]
            if event.tx_id:
                grouped.setdefault(event.tx_id, []).append(event)

        summaries: Dict[str, TxSummary] = {}
        for tx_id, group in grouped.items():
            first = min(group, key=lambda item: item.sequence)
            started_at = min(item.started_at for item in group)
            finished_at = max(item.started_at + dt.timedelta(milliseconds=item.duration_ms) for item in group)
            summaries[tx_id] = TxSummary(
                tx_id=tx_id,
                connection_id=first.connection_id,
                started_at=started_at,
                finished_at=finished_at,
                duration_ms=max((finished_at - started_at).total_seconds() * 1000.0, 0.0),
                rows_affected=sum(item.rows_affected for item in group),
                event_count=len(group),
                error_count=sum(1 for item in group if item.error),
                slow_count=sum(1 for item in group if item.slow),
                n_plus_1_count=sum(1 for item in group if item.n_plus_1),
                first_sequence=first.sequence,
                query_preview=compact_query(
                    "; ".join(item.query for item in group if item.query) or "(transaction)",
                    120,
                ),
            )
        return summaries

    def _build_display_rows(
        self,
        events: List[QueryEvent],
        visible_indices: List[int],
        tx_summaries: Dict[str, TxSummary],
    ) -> List[DisplayRow]:
        if not self._transactions_grouped():
            return [
                DisplayRow(kind="event", event_index=index, tx_id=events[index].tx_id)
                for index in visible_indices
            ]

        first_by_tx: Dict[str, int] = {}
        tx_members: Dict[str, List[int]] = {}
        for index in visible_indices:
            tx_id = events[index].tx_id
            if not tx_id:
                continue
            first_by_tx.setdefault(tx_id, index)
            tx_members.setdefault(tx_id, []).append(index)

        rows: List[DisplayRow] = []
        for index in visible_indices:
            event = events[index]
            tx_id = event.tx_id
            if tx_id and tx_id in tx_summaries:
                if index != first_by_tx[tx_id]:
                    continue
                collapsed = self.collapsed_txs.get(tx_id, False)
                rows.append(
                    DisplayRow(kind="tx", tx_id=tx_id, tx_event_indices=list(tx_members[tx_id]), collapsed=collapsed)
                )
                if not collapsed:
                    rows.extend(DisplayRow(kind="event", event_index=item, tx_id=tx_id) for item in tx_members[tx_id])
                continue
            rows.append(DisplayRow(kind="event", event_index=index, tx_id=tx_id))
        return rows

    def _build_analytics_rows(self, events: List[QueryEvent], visible_indices: List[int]) -> List[AnalyticsRow]:
        grouped: Dict[str, List[QueryEvent]] = {}
        for index in visible_indices:
            event = events[index]
            if event.operation in ("BEGIN", "COMMIT", "ROLLBACK"):
                continue
            if not event.normalized_query:
                continue
            grouped.setdefault(event.normalized_query, []).append(event)

        rows: List[AnalyticsRow] = []
        for normalized_query, group in grouped.items():
            durations = sorted(item.duration_ms for item in group)
            total = sum(durations)
            rows.append(
                AnalyticsRow(
                    query=normalized_query,
                    sample_query=next((item.query for item in group if item.query), normalized_query),
                    count=len(group),
                    total_duration_ms=total,
                    avg_duration_ms=total / len(group),
                    p95_duration_ms=percentile_ms(durations, 0.95),
                    max_duration_ms=durations[-1],
                    total_rows=sum(item.rows_affected for item in group),
                    error_count=sum(1 for item in group if item.error),
                    slow_count=sum(1 for item in group if item.slow),
                    n_plus_1_count=sum(1 for item in group if item.n_plus_1),
                    connection_count=len({item.connection_id for item in group}),
                    transaction_count=len({item.tx_id for item in group if item.tx_id}),
                )
            )
        sort_analytics_rows(rows, self.analytics_sort_mode)
        return rows

    def _build_timeline_rows(
        self,
        events: List[QueryEvent],
        visible_indices: List[int],
        tx_summaries: Dict[str, TxSummary],
    ) -> List[TimelineRow]:
        if self.timeline_mode == "tx":
            rows = [
                TimelineRow(
                    kind="tx",
                    label=f"tx {summary.tx_id[:8]} ({summary.event_count} stmt)",
                    started_at=summary.started_at,
                    duration_ms=summary.duration_ms,
                    summary=(
                        f"tx={summary.tx_id} conn={summary.connection_id} events={summary.event_count} "
                        f"rows={summary.rows_affected} errors={summary.error_count} "
                        f"slow={summary.slow_count} n+1={summary.n_plus_1_count} "
                        f"preview={summary.query_preview}"
                    ),
                    tx_id=summary.tx_id,
                    error=summary.error_count > 0,
                    slow=summary.slow_count > 0,
                    n_plus_1=summary.n_plus_1_count > 0,
                )
                for summary in sorted(tx_summaries.values(), key=lambda item: item.first_sequence)
            ]
            return rows

        rows: List[TimelineRow] = []
        for index in visible_indices:
            event = events[index]
            if event.operation in ("BEGIN", "COMMIT", "ROLLBACK"):
                continue
            rows.append(
                TimelineRow(
                    kind="event",
                    label=event.query or event.operation,
                    started_at=event.started_at,
                    duration_ms=event.duration_ms,
                    summary=(
                        f"seq={event.sequence} op={event.operation} conn={event.connection_id} tx={event.tx_id or '-'} "
                        f"dur={event.duration_ms:.2f}ms rows={event.rows_affected} "
                        f"status={event_status(event)}"
                    ),
                    event_index=index,
                    tx_id=event.tx_id,
                    error=bool(event.error),
                    slow=event.slow,
                    n_plus_1=event.n_plus_1,
                )
            )
        return rows

    def _toggle_selected_tx(self, row: Optional[DisplayRow], tx_summaries: Dict[str, TxSummary]) -> bool:
        return self._set_selected_tx_collapsed(row, tx_summaries, None)

    def _set_selected_tx_collapsed(
        self,
        row: Optional[DisplayRow],
        tx_summaries: Dict[str, TxSummary],
        collapsed: Optional[bool],
    ) -> bool:
        if row is None or not row.tx_id or row.tx_id not in tx_summaries:
            return False
        tx_id = row.tx_id
        if collapsed is None:
            new_state = not self.collapsed_txs.get(tx_id, False)
        else:
            new_state = collapsed
        if self.collapsed_txs.get(tx_id, False) == new_state:
            return False
        self.collapsed_txs[tx_id] = new_state
        state = "collapsed" if self.collapsed_txs[tx_id] else "expanded"
        self.store.add_notice(f"Transaction {tx_id[:8]} {state}")
        return True

    def _clamp_state(
        self,
        display_rows: List[DisplayRow],
        analytics_rows: List[AnalyticsRow],
        timeline_rows: List[TimelineRow],
    ) -> None:
        if self.view == "list":
            self.cursor = max(0, min(self.cursor, max(len(display_rows) - 1, 0)))
        elif self.view == "analytics":
            self.analytics_cursor = max(0, min(self.analytics_cursor, max(len(analytics_rows) - 1, 0)))
        elif self.view == "timeline":
            self.timeline_cursor = max(0, min(self.timeline_cursor, max(len(timeline_rows) - 1, 0)))

    def _open_explain(self, stdscr, event: QueryEvent, analyze: bool, edit: bool) -> None:
        if not self._ensure_explain_available():
            return
        self.explain_return_view = self.view
        query = event.query
        if edit:
            edited_query = open_external_editor(stdscr, query, analyze)
            if not edited_query:
                self.store.add_notice("Explain canceled")
                return
            query = edited_query
        if (
            analyze
            and not self.allow_unsafe_explain_analyze
            and not is_explain_analyze_read_only(query)
        ):
            self._show_modal(
                "EXPLAIN ANALYZE blocked",
                [
                    "Blocked for non-read-only statement.",
                    "Use EXPLAIN or start with --allow-unsafe-explain-analyze.",
                ],
            )
            return
        self._run_explain(query, event.args, analyze)

    def _run_explain(self, query: str, args: List[str], analyze: bool) -> None:
        self.explain_last_query = query
        self.explain_last_args = list(args)
        self.explain_last_analyze = analyze
        title = "EXPLAIN ANALYZE" if analyze else "EXPLAIN"
        try:
            content = execute_explain(self.explain_dsn, query, args, analyze)
            self.explain_result = ExplainResult(title=title, content=content)
            self.view = "explain"
            self.explain_scroll = 0
            self.explain_hscroll = 0
            self.store.add_notice(f"{title} completed")
        except Exception as exc:
            self.explain_result = ExplainResult(title=title, content="", error=str(exc))
            self.view = "explain"
            self.explain_scroll = 0
            self.explain_hscroll = 0
            self.store.add_notice(f"{title} failed: {exc}")

    def _ensure_explain_available(self) -> bool:
        reason = explain_unavailable_reason(self.explain_dsn)
        if reason is None:
            return True
        self._show_modal("EXPLAIN unavailable", wrap_text(reason, 70))
        return False

    def _show_modal(self, title: str, lines: List[str]) -> None:
        self.modal_mode = "info"
        self.modal_title = title
        self.modal_lines = lines

    def _confirm_exit(self) -> None:
        self.modal_mode = "confirm_exit"
        self.modal_title = "Exit sqltracer?"
        self.modal_lines = [
            "Press Enter or q to exit.",
            "Press Esc or n to stay in the program.",
        ]

    def _clear_modal(self) -> None:
        self.modal_mode = ""
        self.modal_title = ""
        self.modal_lines = []

    def _explain_lines(self) -> List[str]:
        if self.explain_result is None:
            return ["No explain result."]
        if self.explain_result.error:
            return [f"Error: {self.explain_result.error}"]
        return self.explain_result.content.splitlines() or ["(empty)"]

    def _export_events(self, events: List[QueryEvent], display_rows: List[DisplayRow], fmt: str) -> None:
        selected_events = [
            events[row.event_index]
            for row in display_rows
            if row.kind == "event" and row.event_index >= 0
        ]
        path = write_export_file(selected_events, self.search_query, self.filter_query, fmt)
        self.store.add_notice(f"Exported {len(selected_events)} events to {path}")

    def _export_current_view(self, fmt: str) -> None:
        events, _, _ = self.store.snapshot()
        filter_ast = compile_filter(self.filter_query) if self.filter_query else None
        visible_indices = self._visible_event_indices(events, filter_ast)
        tx_summaries = self._build_tx_summaries(events, visible_indices)
        display_rows = self._build_display_rows(events, visible_indices, tx_summaries)
        self._export_events(events, display_rows, fmt)


def event_matches_filter(event: QueryEvent, filter_ast: Optional[FilterNode]) -> bool:
    """EN: Check whether event satisfies compiled structured filter AST.
    RU: Проверить, проходит ли событие через compiled structured filter AST.

    Args:
        event (QueryEvent): EN: Captured event to evaluate. RU: Проверяемое событие.
        filter_ast (Optional[FilterNode]): EN: Parsed filter AST or None.
            RU: Распарсенный AST фильтра или None.

    Returns:
        bool: EN: True when event should be visible/processed.
            RU: True, если событие нужно показывать/обрабатывать.
    """
    if filter_ast is None:
        return True
    return evaluate_filter(filter_ast, event)


def summarize_response_preview(event: QueryEvent) -> List[str]:
    """EN: Render compact response preview lines for no-TUI output.
    RU: Сформировать компактные строки preview ответа для no-TUI.

    Args:
        event (QueryEvent): EN: Event with response metadata/preview rows.
            RU: Событие с метаданными ответа и preview-строками.

    Returns:
        List[str]: EN: Human-readable preview lines.
            RU: Строки preview в читаемом виде.
    """
    lines = [f"response_size: rows={event.response_total_rows} bytes={event.response_total_bytes}"]
    if event.response_columns:
        lines.append("columns: " + " | ".join(sanitize_for_terminal(column) for column in event.response_columns))
    if event.response_rows:
        for index, row in enumerate(event.response_rows, start=1):
            lines.append(f"row {index}: {' | '.join(sanitize_for_terminal(item) for item in row)}")
    else:
        lines.append("rows: (no preview rows)")
    if event.response_total_rows:
        suffix = " [truncated]" if event.response_truncated else ""
        lines.append(f"preview: {len(event.response_rows)} of {event.response_total_rows}{suffix}")
    elif event.response_truncated:
        lines.append("preview: truncated")
    return lines


def response_preview_page_count(event: QueryEvent, page_size: int) -> int:
    """EN: Compute number of preview pages for inspector response section.
    RU: Вычислить число страниц preview в response-секции инспектора.

    Args:
        event (QueryEvent): EN: Event carrying preview rows.
            RU: Событие с preview-строками.
        page_size (int): EN: Rows per page. RU: Количество строк на страницу.

    Returns:
        int: EN: Total pages, minimum 1. RU: Всего страниц, минимум 1.
    """
    size = max(1, page_size)
    if not event.response_rows:
        return 1
    return max(1, math.ceil(len(event.response_rows) / size))


def response_preview_page_slice(event: QueryEvent, page: int, page_size: int) -> Tuple[List[List[str]], int, int, int]:
    """EN: Return one bounded response preview page.
    RU: Вернуть одну ограниченную страницу preview ответа.

    Args:
        event (QueryEvent): EN: Event with preview rows. RU: Событие с preview-строками.
        page (int): EN: Requested zero-based page. RU: Запрошенная страница (с нуля).
        page_size (int): EN: Rows per page. RU: Строк на страницу.

    Returns:
        Tuple[List[List[str]], int, int, int]:
            EN: (rows, bounded_page, total_pages, start_index).
            RU: (строки, ограниченная_страница, всего_страниц, стартовый_индекс).
    """
    size = max(1, page_size)
    pages = response_preview_page_count(event, size)
    bounded_page = max(0, min(page, pages - 1))
    start = bounded_page * size
    end = min(len(event.response_rows), start + size)
    return event.response_rows[start:end], bounded_page, pages, start


def build_response_export_payload(event: QueryEvent) -> Dict[str, object]:
    """EN: Build JSON-serializable payload for selected response export.
    RU: Собрать JSON-структуру для экспорта выбранного ответа.

    Args:
        event (QueryEvent): EN: Event to export. RU: Событие для экспорта.

    Returns:
        Dict[str, object]: EN: Export payload with event and response blocks.
            RU: Данные экспорта с блоками event и response.
    """
    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "event": {
            "event_id": event.event_id,
            "sequence": event.sequence,
            "time": event.started_at.isoformat(),
            "connection_id": event.connection_id,
            "tx_id": event.tx_id,
            "operation": event.operation,
            "status": event.status_tag or event_status(event),
            "duration_ms": event.duration_ms,
            "rows_affected": event.rows_affected,
            "query": event.query,
            "args": list(event.args),
            "error": event.error,
            "slow": event.slow,
            "n_plus_1": event.n_plus_1,
            "n_plus_1_hits": event.n_plus_1_hits,
            "n_plus_1_distinct_args": event.n_plus_1_distinct_args,
        },
        "response": {
            "rows_total": event.response_total_rows,
            "bytes_total": event.response_total_bytes,
            "truncated": event.response_truncated,
            "columns": list(event.response_columns),
            "preview_rows": [list(row) for row in event.response_rows],
            "preview_count": len(event.response_rows),
        },
    }


def build_event_record(event: QueryEvent, profile: str, response_mode: str) -> Dict[str, object]:
    """EN: Convert event into file-sink record by profile/response level.
    RU: Преобразовать событие в запись для file-sink по профилю и response-режиму.

    Args:
        event (QueryEvent): EN: Source event. RU: Исходное событие.
        profile (str): EN: Record detail level (minimal/default/full).
            RU: Уровень детализации записи (minimal/default/full).
        response_mode (str): EN: Response inclusion mode (none/preview).
            RU: Режим включения response (none/preview).

    Returns:
        Dict[str, object]: EN: JSON-serializable event record.
            RU: JSON-сериализуемая запись события.
    """
    response: Dict[str, object] = {
        "rows": event.response_total_rows,
        "bytes": event.response_total_bytes,
    }
    if response_mode == "preview":
        response.update(
            {
                "columns": list(event.response_columns),
                "preview_rows": [list(row) for row in event.response_rows],
                "preview_count": len(event.response_rows),
                "truncated": event.response_truncated,
            }
        )

    record: Dict[str, object] = {
        "time": event.started_at.isoformat(),
        "operation": event.operation,
        "query": event.query,
        "duration_ms": event.duration_ms,
        "rows_affected": event.rows_affected,
        "status": event.status_tag or "OK",
        "response": response,
    }
    if profile in ("default", "full"):
        record.update(
            {
                "connection_id": event.connection_id,
                "tx_id": event.tx_id,
                "args": list(event.args),
                "error": event.error,
                "slow": event.slow,
                "n_plus_1": event.n_plus_1,
                "n_plus_1_scope": event.n_plus_1_scope,
                "n_plus_1_hits": event.n_plus_1_hits,
                "n_plus_1_distinct_args": event.n_plus_1_distinct_args,
                "normalized_query": event.normalized_query,
            }
        )
    if profile == "full":
        record.update(
            {
                "event_id": event.event_id,
                "sequence": event.sequence,
                "response_truncated": event.response_truncated,
                "response_columns": list(event.response_columns),
            }
        )
    return record


def build_report_event_snapshot(event: QueryEvent) -> Dict[str, object]:
    return {
        "sequence": event.sequence,
        "time": event.started_at.isoformat(),
        "connection_id": event.connection_id,
        "tx_id": event.tx_id or "",
        "operation": event.operation,
        "status": event.status_tag or event_status(event),
        "duration_ms": round(event.duration_ms, 3),
        "rows_affected": event.rows_affected,
        "response_rows": event.response_total_rows,
        "response_bytes": event.response_total_bytes,
        "error": event.error,
        "slow": event.slow,
        "n_plus_1": event.n_plus_1,
        "n_plus_1_hits": event.n_plus_1_hits,
        "n_plus_1_distinct_args": event.n_plus_1_distinct_args,
        "query": compact_query(event.query, 300),
    }


def serialize_report_query_stat(stat: Dict[str, object]) -> Dict[str, object]:
    return {
        "query": str(stat.get("query", "")),
        "sample_query": str(stat.get("sample_query", "")),
        "count": int(stat.get("count", 0)),
        "total_duration_ms": round(float(stat.get("total_duration_ms", 0.0)), 3),
        "avg_duration_ms": round(float(stat.get("avg_duration_ms", 0.0)), 3),
        "max_duration_ms": round(float(stat.get("max_duration_ms", 0.0)), 3),
        "error_count": int(stat.get("error_count", 0)),
        "slow_count": int(stat.get("slow_count", 0)),
        "n_plus_1_count": int(stat.get("n_plus_1_count", 0)),
        "total_rows": int(stat.get("total_rows", 0)),
        "total_response_bytes": int(stat.get("total_response_bytes", 0)),
    }


class StdoutEventSink:
    """EN: Print captured events to stdout in headless mode.
    RU: Печатать захваченные события в stdout в headless-режиме.
    """

    def __init__(self, filter_query: str, response_mode: str) -> None:
        self.filter_query = filter_query.strip()
        self.filter_ast = compile_filter(self.filter_query) if self.filter_query else None
        self.response_mode = response_mode

    def handle(self, event: QueryEvent) -> None:
        if not event_matches_filter(event, self.filter_ast):
            return
        markers: List[str] = []
        if event.error:
            markers.append("ERROR")
        if event.n_plus_1:
            markers.append(f"N+1[{event.n_plus_1_hits}/{event.n_plus_1_distinct_args}]")
        if event.slow:
            markers.append("SLOW")
        status = sanitize_for_terminal(",".join(markers) if markers else (event.status_tag or "OK"))
        print(
            f"[{format_time(event.started_at)}] {event.operation:<8} "
            f"{event.duration_ms:8.2f} ms rows={event.rows_affected:<5} "
            f"resp_rows={event.response_total_rows:<5} resp_bytes={event.response_total_bytes:<7} "
            f"conn={event.connection_id} status={status} query={compact_query(event.query, 120)}",
            flush=True,
        )
        if self.response_mode == "preview":
            for line in summarize_response_preview(event):
                print(f"    {line}", flush=True)

    def close(self) -> None:
        return None


def open_private_text_file(path: str, mode: str):
    if mode == "a":
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    elif mode == "w":
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    else:
        raise ValueError(f"unsupported file mode: {mode}")
    file_descriptor = os.open(path, flags, 0o600)
    handle = os.fdopen(file_descriptor, mode, encoding="utf-8", newline="\n")
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)
    return handle


class FileEventSink:
    """EN: Persist captured events to JSONL/JSON with filtering and profiles.
    RU: Сохранять события в JSONL/JSON с фильтрацией и профилями.
    """

    def __init__(
        self,
        path: str,
        fmt: str,
        profile: str,
        response_mode: str,
        filter_query: str,
        flush_every: int,
    ) -> None:
        self.path = os.path.abspath(path)
        self.fmt = fmt
        self.profile = profile
        self.response_mode = response_mode
        self.filter_query = filter_query.strip()
        self.filter_ast = compile_filter(self.filter_query) if self.filter_query else None
        self.flush_every = flush_every
        self._pending_writes = 0
        self._records: List[Dict[str, object]] = []
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._handle = None
        if self.fmt == "jsonl":
            self._handle = open_private_text_file(self.path, "a")

    def handle(self, event: QueryEvent) -> None:
        if not event_matches_filter(event, self.filter_ast):
            return
        record = build_event_record(event, self.profile, self.response_mode)
        if self.fmt == "jsonl":
            assert self._handle is not None
            self._handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._pending_writes += 1
            if self._pending_writes >= self.flush_every:
                self._handle.flush()
                self._pending_writes = 0
            return
        self._records.append(record)

    def close(self) -> None:
        if self.fmt == "jsonl":
            if self._handle is not None:
                if self._pending_writes:
                    self._handle.flush()
                self._handle.close()
            return
        payload = {
            "captured": len(self._records),
            "filter": self.filter_query,
            "profile": self.profile,
            "response_body": self.response_mode,
            "queries": self._records,
        }
        with open_private_text_file(self.path, "w") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
            handle.write("\n")


class SummaryReportSink:
    """EN: Build aggregated slow/N+1/error report and write it on shutdown.
    RU: Строить агрегированный отчет slow/N+1/error и писать его при завершении.
    """

    def __init__(self, path: str, fmt: str, top_n: int, filter_query: str) -> None:
        self.path = os.path.abspath(path)
        self.fmt = fmt
        self.top_n = max(1, top_n)
        self.filter_query = filter_query.strip()
        self.filter_ast = compile_filter(self.filter_query) if self.filter_query else None
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)

        self._total_events = 0
        self._total_errors = 0
        self._total_slow = 0
        self._total_nplus1 = 0
        self._total_duration_ms = 0.0
        self._total_rows = 0
        self._total_response_bytes = 0
        self._operations: Dict[str, int] = {}
        self._query_stats: Dict[str, Dict[str, object]] = {}
        self._top_slow_events: List[Dict[str, object]] = []
        self._top_nplus1_events: List[Dict[str, object]] = []
        self._top_error_events: List[Dict[str, object]] = []

    def handle(self, event: QueryEvent) -> None:
        if not event_matches_filter(event, self.filter_ast):
            return

        self._total_events += 1
        self._total_duration_ms += event.duration_ms
        self._total_rows += event.rows_affected
        self._total_response_bytes += event.response_total_bytes

        if event.error:
            self._total_errors += 1
        if event.slow:
            self._total_slow += 1
        if event.n_plus_1:
            self._total_nplus1 += 1

        op = event.operation or "Unknown"
        self._operations[op] = self._operations.get(op, 0) + 1

        key = event.normalized_query or normalize_sql(event.query) or "(empty query)"
        stat = self._query_stats.get(key)
        if stat is None:
            stat = {
                "query": key,
                "sample_query": event.query or key,
                "count": 0,
                "total_duration_ms": 0.0,
                "max_duration_ms": 0.0,
                "error_count": 0,
                "slow_count": 0,
                "n_plus_1_count": 0,
                "total_rows": 0,
                "total_response_bytes": 0,
            }
            self._query_stats[key] = stat
        stat["count"] = int(stat["count"]) + 1
        stat["total_duration_ms"] = float(stat["total_duration_ms"]) + event.duration_ms
        stat["max_duration_ms"] = max(float(stat["max_duration_ms"]), event.duration_ms)
        stat["error_count"] = int(stat["error_count"]) + (1 if event.error else 0)
        stat["slow_count"] = int(stat["slow_count"]) + (1 if event.slow else 0)
        stat["n_plus_1_count"] = int(stat["n_plus_1_count"]) + (1 if event.n_plus_1 else 0)
        stat["total_rows"] = int(stat["total_rows"]) + event.rows_affected
        stat["total_response_bytes"] = int(stat["total_response_bytes"]) + event.response_total_bytes

        snapshot = build_report_event_snapshot(event)
        if event.slow:
            self._push_top_event(self._top_slow_events, snapshot, key_name="duration_ms")
        if event.n_plus_1:
            self._push_top_event(self._top_nplus1_events, snapshot, key_name="n_plus_1_hits")
        if event.error:
            self._push_top_event(self._top_error_events, snapshot, key_name="duration_ms")

    def close(self) -> None:
        payload = self._build_payload()
        if self.fmt == "markdown":
            content = render_summary_report_markdown(payload)
            with open_private_text_file(self.path, "w") as handle:
                handle.write(content)
            return
        with open_private_text_file(self.path, "w") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
            handle.write("\n")

    def _push_top_event(self, bucket: List[Dict[str, object]], snapshot: Dict[str, object], key_name: str) -> None:
        bucket.append(snapshot)
        bucket.sort(
            key=lambda item: (
                float(item.get(key_name, 0.0)),
                float(item.get("duration_ms", 0.0)),
                int(item.get("sequence", 0)),
            ),
            reverse=True,
        )
        if len(bucket) > self.top_n:
            del bucket[self.top_n :]

    def _build_payload(self) -> Dict[str, object]:
        operations = dict(sorted(self._operations.items(), key=lambda item: (-item[1], item[0])))

        query_stats = list(self._query_stats.values())
        for stat in query_stats:
            count = max(1, int(stat["count"]))
            stat["avg_duration_ms"] = float(stat["total_duration_ms"]) / count

        slow_queries = [
            serialize_report_query_stat(item)
            for item in sorted(
                (entry for entry in query_stats if int(entry["slow_count"]) > 0),
                key=lambda entry: (
                    int(entry["slow_count"]),
                    float(entry["total_duration_ms"]),
                    float(entry["max_duration_ms"]),
                    int(entry["count"]),
                ),
                reverse=True,
            )[: self.top_n]
        ]
        nplus1_queries = [
            serialize_report_query_stat(item)
            for item in sorted(
                (entry for entry in query_stats if int(entry["n_plus_1_count"]) > 0),
                key=lambda entry: (
                    int(entry["n_plus_1_count"]),
                    int(entry["count"]),
                    float(entry["total_duration_ms"]),
                ),
                reverse=True,
            )[: self.top_n]
        ]
        error_queries = [
            serialize_report_query_stat(item)
            for item in sorted(
                (entry for entry in query_stats if int(entry["error_count"]) > 0),
                key=lambda entry: (
                    int(entry["error_count"]),
                    int(entry["count"]),
                    float(entry["total_duration_ms"]),
                ),
                reverse=True,
            )[: self.top_n]
        ]

        return {
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "filter": self.filter_query,
            "top_n": self.top_n,
            "totals": {
                "events": self._total_events,
                "errors": self._total_errors,
                "slow": self._total_slow,
                "n_plus_1": self._total_nplus1,
                "total_duration_ms": round(self._total_duration_ms, 3),
                "total_rows": self._total_rows,
                "total_response_bytes": self._total_response_bytes,
                "operations": operations,
            },
            "top_queries": {
                "slow": slow_queries,
                "n_plus_1": nplus1_queries,
                "errors": error_queries,
            },
            "top_events": {
                "slow": self._top_slow_events,
                "n_plus_1": self._top_nplus1_events,
                "errors": self._top_error_events,
            },
        }


def run_event_sinks(store: EventStore, stop_event: threading.Event, sinks: List[object]) -> None:
    """EN: Fan out newly captured events to configured sink objects.
    RU: Рассылать новые захваченные события во все настроенные sink-объекты.

    Args:
        store (EventStore): EN: Event source. RU: Источник событий.
        stop_event (threading.Event): EN: Cooperative stop flag.
            RU: Флаг кооперативной остановки.
        sinks (List[object]): EN: Sink instances with handle()/close().
            RU: Инстансы sink с методами handle()/close().
    """
    last_sequence = 0
    try:
        while not stop_event.is_set():
            store.wait_for_change(last_sequence, 0.5)
            events, _, sequence = store.snapshot()
            if sequence == last_sequence:
                continue
            new_events = [event for event in events if event.sequence > last_sequence]
            last_sequence = sequence
            for event in new_events:
                for sink in sinks:
                    sink.handle(event)
    finally:
        for sink in sinks:
            with contextlib.suppress(Exception):
                sink.close()


def run_headless(store: EventStore, stop_event: threading.Event, sinks: List[object]) -> None:
    """EN: Run non-interactive processing loop.
    RU: Запустить неинтерактивный цикл обработки.

    Args:
        store (EventStore): EN: Event source. RU: Источник событий.
        stop_event (threading.Event): EN: Stop flag. RU: Флаг остановки.
        sinks (List[object]): EN: Active sinks. RU: Активные sink-объекты.
    """
    run_event_sinks(store, stop_event, sinks)


def init_colors() -> None:
    if not curses.has_colors():
        return
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_RED, -1)
    curses.init_pair(2, curses.COLOR_YELLOW, -1)
    curses.init_pair(3, curses.COLOR_CYAN, -1)


def style_for_event(event: QueryEvent) -> int:
    if event.error:
        return curses.color_pair(1)
    if event.n_plus_1:
        return curses.color_pair(2) | curses.A_BOLD
    if event.slow:
        return curses.color_pair(2)
    if event.tx_id:
        return curses.color_pair(3)
    return curses.A_NORMAL


def style_for_timeline_row(row: TimelineRow) -> int:
    if row.error:
        return curses.color_pair(1)
    if row.n_plus_1:
        return curses.color_pair(2) | curses.A_BOLD
    if row.slow:
        return curses.color_pair(2)
    if row.kind == "tx":
        return curses.color_pair(3)
    return curses.A_NORMAL


def style_for_display_row(row: DisplayRow, events: List[QueryEvent], tx_summaries: Dict[str, TxSummary]) -> int:
    if row.kind == "tx":
        summary = tx_summaries.get(row.tx_id)
        if summary is None:
            return curses.color_pair(3)
        if summary.error_count:
            return curses.color_pair(1)
        if summary.n_plus_1_count:
            return curses.color_pair(2) | curses.A_BOLD
        if summary.slow_count:
            return curses.color_pair(2)
        return curses.color_pair(3)
    if row.event_index < 0:
        return curses.A_NORMAL
    return style_for_event(events[row.event_index])


def build_detail_lines(
    row: Optional[DisplayRow],
    events: List[QueryEvent],
    tx_summaries: Dict[str, TxSummary],
    width: int,
) -> List[str]:
    if row is None:
        return ["No event selected."]
    if row.kind == "tx":
        return build_tx_detail_lines(tx_summaries.get(row.tx_id), events, row.tx_event_indices, width)
    if row.event_index < 0 or row.event_index >= len(events):
        return ["No event selected."]
    event = events[row.event_index]
    inspector_lines = build_event_inspector_lines(event, events)
    lines: List[str] = []
    for line in inspector_lines[:12]:
        lines.extend(wrap_text(line, width - 2, indent="" if ":" in line[:20] else ""))
    return lines[:12]


def build_tx_detail_lines(
    summary: Optional[TxSummary],
    events: List[QueryEvent],
    tx_event_indices: List[int],
    width: int,
) -> List[str]:
    if summary is None:
        return ["Transaction summary is unavailable."]
    lines = [
        (
            f"tx={summary.tx_id} conn={summary.connection_id} events={summary.event_count} "
            f"rows={summary.rows_affected}"
        ),
        (
            f"started={summary.started_at.astimezone().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} "
            f"finished={summary.finished_at.astimezone().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} "
            f"duration={summary.duration_ms:.2f} ms"
        ),
        f"errors={summary.error_count} slow={summary.slow_count} n+1={summary.n_plus_1_count}",
        "queries:",
    ]
    for position, index in enumerate(tx_event_indices, start=1):
        if index < 0 or index >= len(events):
            continue
        event = events[index]
        lines.extend(
            wrap_text(
                f"{position}. [{event_status(event)}] {compact_query(event.query or event.operation, 240)}",
                width - 2,
                indent="  ",
            )
        )
    return lines


def build_event_inspector_lines(
    event: QueryEvent,
    all_events: List[QueryEvent],
    response_page: int = 0,
    response_page_size: int = INSPECTOR_RESPONSE_PAGE_SIZE,
) -> List[str]:
    lines = [
        f"id: {event.event_id}",
        f"sequence: {event.sequence}",
        f"connection: {event.connection_id}",
        f"transaction: {event.tx_id or '-'}",
        f"operation: {event.operation}",
        f"started_at: {event.started_at.astimezone().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}",
        f"duration_ms: {event.duration_ms:.2f}",
        f"rows_affected: {event.rows_affected}",
        f"status: {event.status_tag or 'OK'}",
        f"flags: {event_status(event)}",
        f"normalized: {event.normalized_query or '-'}",
        (
            f"n_plus_1_scope: {event.n_plus_1_scope or '-'} | "
            f"hits: {event.n_plus_1_hits} | distinct_args: {event.n_plus_1_distinct_args}"
        ),
        "",
        "query:",
    ]
    lines.extend((event.query or "-").splitlines() or ["-"])
    lines.extend(["", "bound_query:", bind_query_preview(event.query, event.args) if event.query else "-"])
    lines.append("")
    lines.append("args:")
    if event.args:
        for index, arg in enumerate(event.args, start=1):
            lines.append(f"${index} = {arg}")
    else:
        lines.append("(none)")
    lines.append("")
    if event.error:
        lines.extend(["error:", event.error, ""])
    lines.append("response:")
    lines.append(f"size: rows={event.response_total_rows} bytes={event.response_total_bytes}")
    lines.append("columns: " + (" | ".join(event.response_columns) if event.response_columns else "(unknown or none)"))
    page_rows, bounded_page, page_count, start_index = response_preview_page_slice(
        event,
        response_page,
        response_page_size,
    )
    if event.response_rows:
        end_index = start_index + len(page_rows)
        lines.append(
            f"preview_page: {bounded_page + 1}/{page_count} "
            f"(rows {start_index + 1}-{end_index} of {len(event.response_rows)} preview rows)"
        )
        for offset, row in enumerate(page_rows, start=1):
            row_number = start_index + offset
            lines.append(f"row {row_number}: {' | '.join(row)}")
    else:
        lines.append("rows: (no preview rows)")
    if event.response_total_rows:
        suffix = " [truncated]" if event.response_truncated else ""
        lines.append(f"preview: {len(event.response_rows)} of {event.response_total_rows}{suffix}")
    elif event.response_truncated:
        lines.append("preview: truncated")
    if event.tx_id:
        tx_events = [item for item in all_events if item.tx_id == event.tx_id]
        lines.extend(["", "transaction_context:"])
        for item in tx_events:
            lines.append(
                f"{item.sequence:>4} {item.operation:<10} {item.duration_ms:>8.2f}ms {event_status(item):<10} "
                f"{compact_query(item.query or item.operation, 140)}"
            )
    return lines


def build_tx_inspector_lines(summary: Optional[TxSummary], events: List[QueryEvent], tx_event_indices: List[int]) -> List[str]:
    if summary is None:
        return ["Transaction summary is unavailable."]
    lines = [
        f"transaction_id: {summary.tx_id}",
        f"connection: {summary.connection_id}",
        f"started_at: {summary.started_at.astimezone().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}",
        f"finished_at: {summary.finished_at.astimezone().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}",
        f"duration_ms: {summary.duration_ms:.2f}",
        f"events: {summary.event_count}",
        f"rows_affected: {summary.rows_affected}",
        f"errors: {summary.error_count} | slow: {summary.slow_count} | n_plus_1: {summary.n_plus_1_count}",
        f"preview: {summary.query_preview}",
        "",
        "event_index:",
    ]
    for position, index in enumerate(tx_event_indices, start=1):
        if index < 0 or index >= len(events):
            continue
        event = events[index]
        lines.append(
            f"{position:>2}. seq={event.sequence} op={event.operation:<10} "
            f"dur={event.duration_ms:>8.2f}ms rows={event.rows_affected:<5} "
            f"status={event_status(event):<10} {compact_query(event.query or event.operation, 120)}"
        )
    for position, index in enumerate(tx_event_indices, start=1):
        event = events[index]
        lines.extend(["", "=" * 72, f"event {position} / {len(tx_event_indices)}"])
        lines.extend(build_event_inspector_lines(event, events))
    return lines


def event_status(event: QueryEvent) -> str:
    if event.error:
        return "ERROR"
    if event.n_plus_1 and event.slow:
        return f"N+1+S({event.n_plus_1_hits})"
    if event.n_plus_1:
        return f"N+1({event.n_plus_1_hits})"
    if event.slow:
        return "SLOW"
    return "OK"


def format_display_row(
    row: DisplayRow,
    events: List[QueryEvent],
    tx_summaries: Dict[str, TxSummary],
    grouped: bool,
) -> str:
    if row.kind == "tx":
        summary = tx_summaries.get(row.tx_id)
        if summary is None:
            return f"{'':>4}  {'-':<10} {'TX':<10} {'0.00':>8} {'0':>7} {'OK':<8} unavailable transaction"
        marker = "+" if row.collapsed else "-"
        status = "ERROR" if summary.error_count else "N+1" if summary.n_plus_1_count else "SLOW" if summary.slow_count else "TX"
        label = f"{marker} tx {summary.tx_id[:8]} ({summary.event_count} stmt) {summary.query_preview}"
        return (
            f"{summary.first_sequence:>4}  "
            f"{format_time(summary.started_at):<10} "
            f"{'TX':<10} "
            f"{summary.duration_ms:>8.2f} "
            f"{summary.rows_affected:>7} "
            f"{status:<8} "
            f"{compact_query(label, 120)}"
        )
    if row.event_index < 0:
        return ""
    event = events[row.event_index]
    prefix = "  " if grouped and event.tx_id else ""
    return (
        f"{event.sequence:>4}  "
        f"{format_time(event.started_at):<10} "
        f"{(prefix + event.operation)[:10]:<10} "
        f"{event.duration_ms:>8.2f} "
        f"{event.rows_affected:>7} "
        f"{event_status(event):<8} "
        f"{compact_query(event.query, 120)}"
    )


def draw_line(stdscr, y: int, x: int, text: str, width: int, attr: int) -> None:
    clipped = sanitize_for_terminal(text)[: max(0, width - x - 1)]
    with contextlib.suppress(curses.error):
        stdscr.addnstr(y, x, clipped, width - x - 1, attr)


def wrap_text(text: str, width: int, indent: str = "") -> List[str]:
    if width <= 1:
        return [indent + text]
    lines: List[str] = []
    for paragraph in text.splitlines() or [""]:
        words = paragraph.split()
        current = indent
        if not words:
            lines.append(indent.rstrip())
            continue
        for word in words:
            next_piece = word if current == indent else f" {word}"
            if len(current) + len(next_piece) > width and current != indent:
                lines.append(current.rstrip())
                current = indent + word
            else:
                current += next_piece
        lines.append(current.rstrip())
    return lines


def compact_query(query: str, limit: int) -> str:
    one_line = " ".join(sanitize_for_terminal(query).split())
    if len(one_line) <= limit:
        return one_line
    return one_line[: limit - 3] + "..."


def sanitize_for_terminal(text: str) -> str:
    return RE_CONTROL_CHARS.sub(" ", text)


def truncate_text(text: str, limit: int) -> str:
    if limit <= 0 or len(text) <= limit:
        return text
    marker = "... [truncated]"
    if limit <= len(marker):
        return text[:limit]
    return text[: limit - len(marker)] + marker


def format_time(value: dt.datetime) -> str:
    return value.astimezone().strftime("%H:%M:%S")


def infer_simple_operation(query: str) -> str:
    upper = query.strip().upper()
    if upper.startswith(SELECT_LIKE_PREFIXES):
        return "Query"
    if upper.startswith("BEGIN"):
        return "BEGIN"
    if upper.startswith("COMMIT"):
        return "COMMIT"
    if upper.startswith("ROLLBACK"):
        return "ROLLBACK"
    return "Exec"


def strip_sql_leading_comments(query: str) -> str:
    text = query.lstrip()
    while text:
        if text.startswith("--"):
            newline = text.find("\n")
            if newline == -1:
                return ""
            text = text[newline + 1 :].lstrip()
            continue
        if text.startswith("/*"):
            end = text.find("*/")
            if end == -1:
                return ""
            text = text[end + 2 :].lstrip()
            continue
        break
    return text


def is_explain_analyze_read_only(query: str) -> bool:
    clean = strip_sql_leading_comments(query).strip().upper()
    return clean.startswith(SELECT_LIKE_PREFIXES)


def parse_row_description(payload: bytes) -> List[str]:
    field_count = read_uint16(payload, 0)
    offset = 2
    columns: List[str] = []
    for _ in range(field_count):
        name, offset = read_cstring(payload, offset)
        columns.append(name)
        offset += 18
    return columns


def parse_data_row(payload: bytes) -> List[Optional[bytes]]:
    field_count = read_uint16(payload, 0)
    offset = 2
    fields: List[Optional[bytes]] = []
    for _ in range(field_count):
        field_length = read_int32(payload, offset)
        offset += 4
        if field_length == -1:
            fields.append(None)
            continue
        fields.append(payload[offset : offset + field_length])
        offset += field_length
    return fields


def decode_result_value(value: Optional[bytes]) -> str:
    if value is None:
        return "NULL"
    with contextlib.suppress(UnicodeDecodeError):
        return value.decode("utf-8")
    return "0x" + value.hex()


def parameter_uses_binary_format(format_codes: List[int], index: int) -> bool:
    if not format_codes:
        return False
    if len(format_codes) == 1:
        return format_codes[0] == 1
    return index < len(format_codes) and format_codes[index] == 1


def decode_parameter(raw: bytes, oid: int, is_binary: bool) -> str:
    if not is_binary:
        return raw.decode("utf-8", errors="replace")
    if oid in (OID_TIMESTAMP, OID_TIMESTAMPTZ) and len(raw) == 8:
        microseconds = struct.unpack("!q", raw)[0]
        return decode_postgres_timestamp(microseconds)
    if oid == OID_BOOL and len(raw) == 1:
        return "true" if raw[0] != 0 else "false"
    if oid == OID_INT2 and len(raw) == 2:
        return str(struct.unpack("!h", raw)[0])
    if oid in (OID_INT4, OID_OID) and len(raw) == 4:
        return str(struct.unpack("!i", raw)[0])
    if oid == OID_INT8 and len(raw) == 8:
        return str(struct.unpack("!q", raw)[0])
    if oid == OID_UUID and len(raw) == 16:
        return str(uuid.UUID(bytes=raw))
    if oid == OID_BYTEA:
        return "\\x" + raw.hex()
    if len(raw) == 16:
        with contextlib.suppress(ValueError):
            return str(uuid.UUID(bytes=raw))
    return "0x" + raw.hex()


def decode_postgres_timestamp(microseconds: int) -> str:
    seconds, remainder = divmod(microseconds, 1_000_000)
    unix_seconds = POSTGRES_EPOCH_UNIX + seconds
    timestamp = dt.datetime.fromtimestamp(unix_seconds, tz=dt.timezone.utc)
    timestamp += dt.timedelta(microseconds=remainder)
    return timestamp.isoformat()


def parse_rows_affected(command_tag: str) -> int:
    if not command_tag:
        return 0
    parts = command_tag.split()
    if not parts:
        return 0
    try:
        return int(parts[-1])
    except ValueError:
        return 0


def parse_error_response(payload: bytes) -> str:
    offset = 0
    message = "PostgreSQL error"
    while offset < len(payload):
        field_type = payload[offset : offset + 1]
        offset += 1
        if field_type == b"\x00":
            break
        value, offset = read_cstring(payload, offset)
        if field_type == b"M":
            message = value
    return message


def decode_cstring_payload(payload: bytes) -> str:
    if payload.endswith(b"\x00"):
        payload = payload[:-1]
    return payload.decode("utf-8", errors="replace")


def read_cstring(buffer: bytes, offset: int) -> Tuple[str, int]:
    end = buffer.index(0, offset)
    return buffer[offset:end].decode("utf-8", errors="replace"), end + 1


def read_uint16(buffer: bytes, offset: int) -> int:
    return struct.unpack_from("!H", buffer, offset)[0]


def read_int32(buffer: bytes, offset: int) -> int:
    return struct.unpack_from("!i", buffer, offset)[0]


def parse_host_port(value: str) -> Tuple[str, int]:
    if not value:
        raise argparse.ArgumentTypeError("address is empty")
    host: str
    port_text: str
    if value.startswith("["):
        closing = value.find("]")
        if closing == -1 or len(value) <= closing + 2 or value[closing + 1] != ":":
            raise argparse.ArgumentTypeError(f"invalid address: {value}")
        host = value[1:closing]
        port_text = value[closing + 2 :]
    else:
        host, _, port_text = value.rpartition(":")
        if not host:
            host = "0.0.0.0"
        if not port_text:
            raise argparse.ArgumentTypeError(f"invalid address: {value}")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid port in address: {value}") from exc
    return host, port


def is_loopback_host(host: str) -> bool:
    if not host:
        return False
    lowered = host.lower()
    if lowered == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def parse_client_allowlist(value: str) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    entries = [item.strip() for item in value.split(",") if item.strip()]
    networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
    for entry in entries:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid client allowlist entry: {entry}") from exc
        networks.append(network)
    return networks


def is_client_allowed(
    client_host: str,
    networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]],
) -> bool:
    if not networks:
        return True
    try:
        client_ip = ipaddress.ip_address(client_host.split("%", 1)[0])
    except ValueError:
        return False
    return any(client_ip in network for network in networks)


def normalize_sql(sql: str) -> str:
    if not sql:
        return ""

    result: List[str] = []
    index = 0
    prev_space = False
    while index < len(sql):
        char = sql[index]

        if char == "'":
            index = _normalize_string_literal(result, sql, index)
            prev_space = False
            continue

        if char == "$" and index + 1 < len(sql) and sql[index + 1].isdigit():
            start = index
            index += 1
            while index < len(sql) and sql[index].isdigit():
                index += 1
            result.append(sql[start:index])
            prev_space = False
            continue

        if char.isdigit() and (index == 0 or _is_num_boundary(sql[index - 1])):
            next_index = index + 1
            while next_index < len(sql) and (sql[next_index].isdigit() or sql[next_index] == "."):
                next_index += 1
            if next_index >= len(sql) or _is_num_boundary(sql[next_index]):
                result.append("?")
                index = next_index
                prev_space = False
                continue

        if char.isspace():
            if not prev_space and result:
                result.append(" ")
                prev_space = True
            index += 1
            continue

        result.append(char)
        index += 1
        prev_space = False

    return "".join(result).rstrip()


def _normalize_string_literal(result: List[str], sql: str, start: int) -> int:
    index = start + 1
    while index < len(sql):
        if sql[index] == "'" and index + 1 < len(sql) and sql[index + 1] == "'":
            index += 2
            continue
        if sql[index] == "'":
            index += 1
            break
        index += 1
    result.append("'?'")
    return index


def _is_num_boundary(char: str) -> bool:
    return char.isspace() or char in ",()=<>+-*/;"


def is_nplus1_candidate(operation: str, query: str) -> bool:
    upper = query.strip().upper()
    if operation not in ("Query", "Exec", "Execute"):
        return False
    if not upper.startswith(("SELECT", "WITH")):
        return False
    return " FROM " in f" {upper} "


def compile_filter(filter_query: str) -> Optional[FilterNode]:
    clean = filter_query.strip()
    if not clean:
        return None
    cached = FILTER_AST_CACHE.get(clean)
    if cached is not None:
        return cached
    tokens = tokenize_filter(clean)
    if not tokens:
        return None
    parser = FilterParser(tokens)
    ast = parser.parse()
    if clean not in FILTER_AST_CACHE and len(FILTER_AST_CACHE) >= DEFAULT_FILTER_AST_CACHE_SIZE:
        oldest_key = next(iter(FILTER_AST_CACHE))
        FILTER_AST_CACHE.pop(oldest_key, None)
    FILTER_AST_CACHE[clean] = ast
    return ast


def tokenize_filter(filter_query: str) -> List[str]:
    lexer = shlex.shlex(filter_query, posix=True, punctuation_chars="()")
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


class FilterParser:
    """EN: Recursive-descent parser for structured filter expressions.
    RU: Рекурсивный парсер выражений structured filter.
    """

    def __init__(self, tokens: List[str]) -> None:
        self.tokens = tokens
        self.index = 0

    def parse(self) -> FilterNode:
        node = self._parse_or()
        if self._peek() is not None:
            trailing = " ".join(self.tokens[self.index :])
            extra = FilterNode(kind="predicate", predicate=FilterPredicate(field_name="text", value=trailing.lower()))
            node = combine_filter_nodes("and", node, extra)
        return node

    def _parse_or(self) -> FilterNode:
        node = self._parse_and()
        while self._peek_lower() == "or":
            self._consume()
            node = combine_filter_nodes("or", node, self._parse_and())
        return node

    def _parse_and(self) -> FilterNode:
        node = self._parse_unary()
        while True:
            next_token = self._peek_lower()
            if next_token is None or next_token in (")", "or"):
                return node
            if next_token == "and":
                self._consume()
            node = combine_filter_nodes("and", node, self._parse_unary())

    def _parse_unary(self) -> FilterNode:
        token = self._peek_lower()
        if token == "not":
            self._consume()
            return FilterNode(kind="not", children=[self._parse_unary()])
        if self._peek() == "(":
            self._consume()
            node = self._parse_or()
            if self._peek() == ")":
                self._consume()
            return node
        raw = self._consume() or ""
        return FilterNode(kind="predicate", predicate=parse_predicate(raw))

    def _peek(self) -> Optional[str]:
        if self.index >= len(self.tokens):
            return None
        return self.tokens[self.index]

    def _peek_lower(self) -> Optional[str]:
        token = self._peek()
        if token is None:
            return None
        return token.lower()

    def _consume(self) -> Optional[str]:
        token = self._peek()
        if token is not None:
            self.index += 1
        return token


def combine_filter_nodes(kind: str, left: FilterNode, right: FilterNode) -> FilterNode:
    children: List[FilterNode] = []
    for node in (left, right):
        if node.kind == kind:
            children.extend(node.children)
        else:
            children.append(node)
    return FilterNode(kind=kind, children=children)


def parse_predicate(token: str) -> FilterPredicate:
    lower = token.lower()
    match = RE_DURATION.match(token)
    if match:
        op, number, unit = match.groups()
        return FilterPredicate(
            field_name="duration",
            operator=op,
            number=parse_duration_token(number, unit),
        )

    if lower in ("error", "slow", "n+1", "nplus1", "tx", "notx"):
        field_name = "nplus1" if lower in ("n+1", "nplus1") else lower
        if field_name == "tx":
            field_name = "has_tx"
        return FilterPredicate(field_name=field_name)

    comparison = RE_FIELD_COMPARISON.match(token)
    if comparison:
        raw_field, operator, raw_value = comparison.groups()
        field_name = normalize_filter_field(raw_field)
        if field_name == "duration":
            duration_match = re.match(r"^(\d+(?:\.\d+)?)(us|µs|ms|s|m)$", raw_value, re.IGNORECASE)
            if duration_match:
                number, unit = duration_match.groups()
                return FilterPredicate(
                    field_name="duration",
                    operator=operator,
                    number=parse_duration_token(number, unit),
                )
        if field_name == "rows" and RE_NUMERIC_LITERAL.match(raw_value):
            return FilterPredicate(field_name="rows", operator=operator, number=float(raw_value))
        return FilterPredicate(field_name=field_name, operator=operator, value=raw_value.lower())

    return FilterPredicate(field_name="text", value=lower)


def normalize_filter_field(name: str) -> str:
    lower = name.lower()
    aliases = {
        "d": "duration",
        "dur": "duration",
        "duration": "duration",
        "op": "op",
        "query": "query",
        "sql": "query",
        "norm": "normalized",
        "normalized": "normalized",
        "status": "status",
        "conn": "connection",
        "connection": "connection",
        "tx": "tx",
        "transaction": "tx",
        "arg": "args",
        "args": "args",
        "err": "error_text",
        "error": "error_text",
        "rows": "rows",
        "row": "rows",
        "scope": "scope",
        "col": "columns",
        "column": "columns",
        "table": "table",
    }
    return aliases.get(lower, lower)


def parse_duration_token(number: str, unit: str) -> float:
    value = float(number)
    normalized = unit.lower()
    if normalized in ("us", "µs"):
        return value / 1_000_000.0
    if normalized == "ms":
        return value / 1000.0
    if normalized == "s":
        return value
    if normalized == "m":
        return value * 60.0
    return value / 1000.0


def matches_event(event: QueryEvent, search_query: str, filter_ast: Optional[FilterNode]) -> bool:
    if filter_ast is not None and not evaluate_filter(filter_ast, event):
        return False
    if search_query:
        haystack = " ".join(
            [
                event.query.lower(),
                " ".join(arg.lower() for arg in event.args),
                event.error.lower(),
                event.normalized_query.lower(),
                " ".join(name.lower() for name in event.response_columns),
            ]
        )
        if search_query.lower() not in haystack:
            return False
    return True


def evaluate_filter(node: FilterNode, event: QueryEvent) -> bool:
    if node.kind == "predicate":
        return evaluate_predicate(node.predicate, event)
    if node.kind == "not":
        return not evaluate_filter(node.children[0], event)
    if node.kind == "or":
        return any(evaluate_filter(child, event) for child in node.children)
    return all(evaluate_filter(child, event) for child in node.children)


def evaluate_predicate(predicate: Optional[FilterPredicate], event: QueryEvent) -> bool:
    if predicate is None:
        return True
    if predicate.field_name == "text":
        return predicate.value in event_text_haystack(event)
    if predicate.field_name == "duration":
        return match_numeric(event.duration_ms / 1000.0, predicate.operator, predicate.number)
    if predicate.field_name == "rows":
        return match_numeric(float(event.rows_affected), predicate.operator, predicate.number)
    if predicate.field_name == "error":
        return bool(event.error)
    if predicate.field_name == "slow":
        return event.slow
    if predicate.field_name == "nplus1":
        return event.n_plus_1
    if predicate.field_name == "has_tx":
        return bool(event.tx_id)
    if predicate.field_name == "notx":
        return not event.tx_id
    if predicate.field_name == "op":
        return match_text_field(match_op(event, predicate.value), predicate.operator)
    if predicate.field_name == "query":
        return match_contains(event.query, predicate.operator, predicate.value)
    if predicate.field_name == "normalized":
        return match_contains(event.normalized_query, predicate.operator, predicate.value)
    if predicate.field_name == "args":
        return any(match_contains(arg, predicate.operator, predicate.value) for arg in event.args)
    if predicate.field_name == "error_text":
        return match_contains(event.error, predicate.operator, predicate.value)
    if predicate.field_name == "status":
        return match_contains(event_status(event), predicate.operator, predicate.value)
    if predicate.field_name == "connection":
        return match_contains(event.connection_id, predicate.operator, predicate.value)
    if predicate.field_name == "scope":
        return match_contains(event.n_plus_1_scope or event.connection_id, predicate.operator, predicate.value)
    if predicate.field_name == "tx":
        return match_contains(event.tx_id, predicate.operator, predicate.value)
    if predicate.field_name == "columns":
        return any(match_contains(name, predicate.operator, predicate.value) for name in event.response_columns)
    if predicate.field_name == "table":
        return match_table(event, predicate.operator, predicate.value)
    return match_contains(event_text_haystack(event), predicate.operator, predicate.value)


def event_text_haystack(event: QueryEvent) -> str:
    parts = [
        event.query,
        " ".join(event.args),
        event.error,
        event.normalized_query,
        event.connection_id,
        event.tx_id,
        event.status_tag,
        " ".join(event.response_columns),
    ]
    return " ".join(part.lower() for part in parts if part)


def match_text_field(result: bool, operator: str) -> bool:
    if operator == "!=":
        return not result
    return result


def match_contains(text: str, operator: str, value: str) -> bool:
    haystack = text.lower()
    matched = value in haystack
    if operator == "!=":
        return not matched
    return matched


def match_numeric(actual: float, operator: str, expected: float) -> bool:
    if operator in ("", ":"):
        return actual == expected
    if operator == ">":
        return actual > expected
    if operator == "<":
        return actual < expected
    if operator == ">=":
        return actual >= expected
    if operator == "<=":
        return actual <= expected
    if operator == "!=":
        return actual != expected
    return actual == expected


def match_table(event: QueryEvent, operator: str, value: str) -> bool:
    normalized = f" {event.normalized_query.lower()} "
    matched = f" from {value} " in normalized or f" join {value} " in normalized or f" update {value} " in normalized
    if operator == "!=":
        return not matched
    return matched


def match_op(event: QueryEvent, pattern: str) -> bool:
    if pattern in ("query", "exec", "execute", "begin", "commit", "rollback"):
        return event.operation.lower() == pattern
    normalized_query = event.query.strip().lower()
    if pattern in ("select", "insert", "update", "delete"):
        return normalized_query.startswith(pattern)
    return False


def percentile_ms(sorted_values: List[float], percentile: float) -> float:
    if not sorted_values:
        return 0.0
    index = int((len(sorted_values) - 1) * percentile)
    return sorted_values[index]


def next_analytics_sort_mode(current: str) -> str:
    modes = ["total", "count", "avg", "p95", "max", "rows", "errors", "nplus1"]
    try:
        index = modes.index(current)
    except ValueError:
        return modes[0]
    return modes[(index + 1) % len(modes)]


def sort_analytics_rows(rows: List[AnalyticsRow], mode: str) -> None:
    if mode == "count":
        rows.sort(key=lambda row: (-row.count, row.query))
    elif mode == "avg":
        rows.sort(key=lambda row: (-row.avg_duration_ms, row.query))
    elif mode == "p95":
        rows.sort(key=lambda row: (-row.p95_duration_ms, row.query))
    elif mode == "max":
        rows.sort(key=lambda row: (-row.max_duration_ms, row.query))
    elif mode == "rows":
        rows.sort(key=lambda row: (-row.total_rows, row.query))
    elif mode == "errors":
        rows.sort(key=lambda row: (-row.error_count, -row.total_duration_ms, row.query))
    elif mode == "nplus1":
        rows.sort(key=lambda row: (-row.n_plus_1_count, -row.count, row.query))
    else:
        rows.sort(key=lambda row: (-row.total_duration_ms, row.query))


def render_timeline_axis(span_seconds: float, chart_width: int) -> str:
    if chart_width <= 0:
        return ""
    tick_count = max(2, min(chart_width // 12, 6))
    canvas = [" "] * chart_width
    for index in range(tick_count + 1):
        fraction = index / float(tick_count)
        label = format_ms(fraction * span_seconds * 1000.0)
        offset = min(chart_width - 1, int(fraction * max(chart_width - 1, 1)))
        for label_index, char in enumerate(label):
            target = offset + label_index
            if target < chart_width:
                canvas[target] = char
    return "".join(canvas)


def format_ms(value: float) -> str:
    if value < 1.0:
        return f"{value * 1000.0:.0f}us"
    if value < 1000.0:
        return f"{value:.1f}ms"
    return f"{value / 1000.0:.2f}s"


def apply_hscroll(text: str, offset: int) -> str:
    if offset <= 0:
        return text
    return text[offset:]


def key_matches(key: Union[int, str], *aliases: str) -> bool:
    if not isinstance(key, str):
        return False
    normalized = key.lower()
    return normalized in {alias.lower() for alias in aliases}


def key_is_enter(key: Union[int, str]) -> bool:
    return key in (curses.KEY_ENTER, 10, 13, "\n", "\r")


def key_is_backspace(key: Union[int, str]) -> bool:
    return key in (curses.KEY_BACKSPACE, 127, 8, "\b", "\x7f")


def key_is_escape(key: Union[int, str]) -> bool:
    return key in (27, "\x1b")


def bind_query_preview(query: str, args: List[str]) -> str:
    def replacer(match) -> str:
        position = int(match.group(1)) - 1
        if 0 <= position < len(args):
            value = args[position]
            if value == "NULL":
                return "NULL"
            escaped = value.replace("'", "''")
            return f"'{escaped}'"
        return match.group(0)

    return RE_PLACEHOLDER.sub(replacer, query)


def copy_to_clipboard(text: str) -> bool:
    candidates = [
        ["pbcopy"],
        ["wl-copy"],
        ["xclip", "-selection", "clipboard"],
        ["xsel", "--clipboard", "--input"],
    ]
    for command in candidates:
        executable = shutil.which(command[0])
        if executable is None:
            continue
        try:
            completed = subprocess.run(
                [executable] + command[1:],
                input=text.encode("utf-8"),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if completed.returncode == 0:
                return True
        except OSError:
            continue
    return False


def open_external_editor(stdscr, initial_query: str, analyze: bool) -> str:
    editor = os.environ.get("EDITOR") or shutil.which("vi") or shutil.which("nano")
    if not editor:
        return ""

    prefix = "EXPLAIN ANALYZE" if analyze else "EXPLAIN"
    with tempfile.NamedTemporaryFile("w+", suffix=".sql", delete=False) as handle:
        path = handle.name
        handle.write(
            f"-- Edit this query, save and quit to run {prefix}\n"
            "-- To cancel, remove all SQL or quit without saving.\n\n"
        )
        handle.write(initial_query)

    curses.def_prog_mode()
    curses.endwin()
    try:
        subprocess.run([editor, path], check=False)
        with open(path, "r", encoding="utf-8") as handle:
            content = handle.read()
    finally:
        with contextlib.suppress(OSError):
            os.unlink(path)
        curses.reset_prog_mode()
        stdscr.refresh()

    lines = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("--"):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def render_sql_literal(value: str) -> str:
    if value == "NULL":
        return "NULL"
    escaped = value.replace("\\", "\\\\").replace("'", "''")
    return f"'{escaped}'"


def build_explain_sql(query: str, args: List[str], analyze: bool) -> List[str]:
    """EN: Build SQL statements for EXPLAIN with optional PREPARE/EXECUTE wrapper.
    RU: Собрать SQL-операторы для EXPLAIN с optional PREPARE/EXECUTE.

    Args:
        query (str): EN: Original query text. RU: Исходный текст запроса.
        args (List[str]): EN: Captured bind arguments. RU: Захваченные bind-аргументы.
        analyze (bool): EN: Use EXPLAIN ANALYZE when True.
            RU: Использовать EXPLAIN ANALYZE при True.

    Returns:
        List[str]: EN: SQL statements to execute sequentially.
            RU: SQL-операторы для последовательного выполнения.
    """
    prefix = "EXPLAIN ANALYZE " if analyze else "EXPLAIN "
    placeholders = sorted({int(match) for match in RE_PLACEHOLDER.findall(query)})
    if not placeholders:
        return [prefix + query]

    statement_name = f"sqltracer_explain_{uuid.uuid4().hex[:8]}"
    execute_args = []
    for position in placeholders:
        value = args[position - 1] if 0 <= position - 1 < len(args) else "NULL"
        execute_args.append(render_sql_literal(value))
    return [
        f"PREPARE {statement_name} AS {query}",
        f"{prefix}EXECUTE {statement_name} ({', '.join(execute_args)})",
        f"DEALLOCATE {statement_name}",
    ]


def explain_unavailable_reason(dsn: str) -> Optional[str]:
    """EN: Return human-readable reason why EXPLAIN is unavailable, or None.
    RU: Вернуть понятную причину недоступности EXPLAIN, либо None.

    Args:
        dsn (str): EN: Connection string used for EXPLAIN. RU: DSN для EXPLAIN.

    Returns:
        Optional[str]: EN: Reason text when unavailable.
            RU: Текст причины, если EXPLAIN недоступен.
    """
    if not dsn:
        return "EXPLAIN requires --dsn or DATABASE_URL. Restart sqltracer with a PostgreSQL DSN for direct explain access."
    try:
        import psycopg  # type: ignore  # noqa: F401
    except ImportError:
        return "EXPLAIN requires the psycopg package in the runtime environment."
    return None


def execute_explain(dsn: str, query: str, args: List[str], analyze: bool) -> str:
    """EN: Execute EXPLAIN plan request against upstream DB.
    RU: Выполнить запрос плана EXPLAIN к upstream БД.

    Args:
        dsn (str): EN: PostgreSQL DSN for direct DB connection.
            RU: PostgreSQL DSN для прямого подключения к БД.
        query (str): EN: Query to explain. RU: Запрос для explain.
        args (List[str]): EN: Captured bind args from protocol.
            RU: Захваченные bind-аргументы из протокола.
        analyze (bool): EN: Run EXPLAIN ANALYZE when True.
            RU: Выполнять EXPLAIN ANALYZE при True.

    Returns:
        str: EN: Multiline textual plan. RU: Многострочный текст плана.

    Raises:
        RuntimeError: EN: Missing DSN or missing psycopg dependency.
            RU: Нет DSN или отсутствует зависимость psycopg.
    """
    if not dsn:
        raise RuntimeError("EXPLAIN is not configured; set --dsn or DATABASE_URL")
    try:
        import psycopg  # type: ignore
    except ImportError as exc:
        raise RuntimeError("psycopg is required for EXPLAIN support") from exc

    with psycopg.connect(dsn) as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            statements = build_explain_sql(query, args, analyze)
            rows: List[Tuple[object, ...]] = []
            try:
                # EN: Always run inside explicit transaction and rollback.
                # RU: Всегда запускаем в явной транзакции с последующим rollback.
                cur.execute("BEGIN")
                for statement in statements:
                    cur.execute(statement)
                    if statement.startswith("EXPLAIN"):
                        rows = cur.fetchall()
            finally:
                with contextlib.suppress(Exception):
                    cur.execute("ROLLBACK")
            if not rows:
                return "(empty plan)"
            return "\n".join(str(row[0]) if row else "" for row in rows)


def write_export_file(events: List[QueryEvent], search_query: str, filter_query: str, fmt: str) -> str:
    """EN: Export visible events into timestamped JSON/Markdown file.
    RU: Экспортировать видимые события в timestamped JSON/Markdown файл.

    Args:
        events (List[QueryEvent]): EN: Events to export. RU: События для экспорта.
        search_query (str): EN: Active text search. RU: Активный текстовый поиск.
        filter_query (str): EN: Active structured filter. RU: Активный structured filter.
        fmt (str): EN: Export format ("json" or "markdown").
            RU: Формат экспорта ("json" или "markdown").

    Returns:
        str: EN: Absolute path of created export file.
            RU: Абсолютный путь созданного файла экспорта.
    """
    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    extension = "md" if fmt == "markdown" else "json"
    path = os.path.abspath(f"sqltracer-export-{timestamp}.{extension}")
    if fmt == "markdown":
        content = render_markdown_export(events, search_query, filter_query)
    else:
        content = json.dumps(build_export_payload(events, search_query, filter_query), indent=2, ensure_ascii=False) + "\n"
    with open_private_text_file(path, "w") as handle:
        handle.write(content)
    return path


def write_response_export_file(event: QueryEvent) -> str:
    """EN: Export selected event response payload to standalone JSON file.
    RU: Экспортировать payload ответа выбранного события в отдельный JSON.

    Args:
        event (QueryEvent): EN: Event whose response should be exported.
            RU: Событие, чей response нужно экспортировать.

    Returns:
        str: EN: Absolute path to generated file.
            RU: Абсолютный путь к созданному файлу.
    """
    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.abspath(f"sqltracer-response-{timestamp}-seq{event.sequence}.json")
    payload = build_response_export_payload(event)
    with open_private_text_file(path, "w") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return path


def build_export_payload(events: List[QueryEvent], search_query: str, filter_query: str) -> Dict[str, object]:
    """EN: Build structured export payload with query/analytics/transaction blocks.
    RU: Собрать структурированный payload экспорта с блоками query/analytics/transaction.

    Args:
        events (List[QueryEvent]): EN: Exported events. RU: Экспортируемые события.
        search_query (str): EN: Active text search string. RU: Строка текстового поиска.
        filter_query (str): EN: Active structured filter string.
            RU: Строка structured filter.

    Returns:
        Dict[str, object]: EN: JSON-serializable export payload.
            RU: JSON-сериализуемый payload экспорта.
    """
    payload: Dict[str, object] = {
        "captured": len(events),
        "search": search_query,
        "filter": filter_query,
        "queries": [],
        "analytics": [],
        "transactions": [],
    }

    queries: List[Dict[str, object]] = []
    for event in events:
        queries.append(
            {
                "time": event.started_at.isoformat(),
                "op": event.operation,
                "query": event.query,
                "args": event.args,
                "duration_ms": event.duration_ms,
                "rows_affected": event.rows_affected,
                "error": event.error,
                "tx_id": event.tx_id,
                "n_plus_1": event.n_plus_1,
                "n_plus_1_scope": event.n_plus_1_scope,
                "n_plus_1_hits": event.n_plus_1_hits,
                "n_plus_1_distinct_args": event.n_plus_1_distinct_args,
                "slow": event.slow,
                "normalized_query": event.normalized_query,
                "response_rows": event.response_total_rows,
                "response_bytes": event.response_total_bytes,
                "response_truncated": event.response_truncated,
            }
        )
    payload["queries"] = queries

    grouped: Dict[str, List[QueryEvent]] = {}
    for event in events:
        if event.normalized_query:
            grouped.setdefault(event.normalized_query, []).append(event)

    analytics_payload: List[Dict[str, object]] = []
    for normalized_query, group in grouped.items():
        durations = sorted(item.duration_ms for item in group)
        total = sum(durations)
        analytics_payload.append(
            {
                "query": normalized_query,
                "count": len(group),
                "total_ms": total,
                "avg_ms": total / len(group),
                "p95_ms": percentile_ms(durations, 0.95),
                "max_ms": durations[-1],
                "rows_total": sum(item.rows_affected for item in group),
                "errors": sum(1 for item in group if item.error),
                "slow": sum(1 for item in group if item.slow),
                "n_plus_1": sum(1 for item in group if item.n_plus_1),
            }
        )
    payload["analytics"] = analytics_payload

    tx_grouped: Dict[str, List[QueryEvent]] = {}
    for event in events:
        if event.tx_id:
            tx_grouped.setdefault(event.tx_id, []).append(event)
    tx_payload: List[Dict[str, object]] = []
    for tx_id, group in tx_grouped.items():
        started_at = min(item.started_at for item in group)
        finished_at = max(item.started_at + dt.timedelta(milliseconds=item.duration_ms) for item in group)
        tx_payload.append(
            {
                "tx_id": tx_id,
                "connection_id": group[0].connection_id,
                "event_count": len(group),
                "rows_affected": sum(item.rows_affected for item in group),
                "error_count": sum(1 for item in group if item.error),
                "slow_count": sum(1 for item in group if item.slow),
                "n_plus_1_count": sum(1 for item in group if item.n_plus_1),
                "started_at": started_at.isoformat(),
                "finished_at": finished_at.isoformat(),
                "duration_ms": max((finished_at - started_at).total_seconds() * 1000.0, 0.0),
            }
        )
    payload["transactions"] = tx_payload
    return payload


def render_markdown_export(events: List[QueryEvent], search_query: str, filter_query: str) -> str:
    lines = [
        "# sqltracer export",
        "",
        f"- Captured: {len(events)}",
        f"- Search: {search_query or '(none)'}",
        f"- Filter: {filter_query or '(none)'}",
        "",
        "## Queries",
        "",
        "| # | Time | Op | Duration | Resp | Query | Args | Error |",
        "|---|------|----|----------|------|-------|------|-------|",
    ]
    for index, event in enumerate(events, start=1):
        lines.append(
            "| {index} | {time} | {op} | {duration} | {response} | {query} | {args} | {error} |".format(
                index=index,
                time=event.started_at.astimezone().strftime("%H:%M:%S.%f")[:-3],
                op=escape_markdown_pipe(event.operation),
                duration=escape_markdown_pipe(format_ms(event.duration_ms)),
                response=escape_markdown_pipe(f"{event.response_total_rows} rows / {event.response_total_bytes} B"),
                query=escape_markdown_pipe(compact_query(event.query, 200)),
                args=escape_markdown_pipe(", ".join(event.args) if event.args else ""),
                error=escape_markdown_pipe(event.error),
            )
        )
    return "\n".join(lines) + "\n"


def render_summary_report_markdown(payload: Dict[str, object]) -> str:
    totals = payload.get("totals", {})
    top_queries = payload.get("top_queries", {})
    top_events = payload.get("top_events", {})
    lines = [
        "# sqltracer summary report",
        "",
        f"- generated_at: {payload.get('generated_at', '')}",
        f"- filter: {payload.get('filter', '') or '(none)'}",
        f"- top_n: {payload.get('top_n', 0)}",
        "",
        "## Totals",
        "",
        f"- events: {totals.get('events', 0)}",
        f"- errors: {totals.get('errors', 0)}",
        f"- slow: {totals.get('slow', 0)}",
        f"- n_plus_1: {totals.get('n_plus_1', 0)}",
        f"- total_duration_ms: {totals.get('total_duration_ms', 0)}",
        f"- total_rows: {totals.get('total_rows', 0)}",
        f"- total_response_bytes: {totals.get('total_response_bytes', 0)}",
        "",
        "## Top Slow Queries",
        "",
        "| # | Count | Slow | Max ms | Total ms | Query |",
        "|---|------:|-----:|-------:|---------:|-------|",
    ]
    for index, row in enumerate(top_queries.get("slow", []), start=1):
        row_map = row if isinstance(row, dict) else {}
        lines.append(
            "| {index} | {count} | {slow} | {max_ms} | {total_ms} | {query} |".format(
                index=index,
                count=row_map.get("count", 0),
                slow=row_map.get("slow_count", 0),
                max_ms=row_map.get("max_duration_ms", 0),
                total_ms=row_map.get("total_duration_ms", 0),
                query=escape_markdown_pipe(compact_query(str(row_map.get("query", "")), 180)),
            )
        )
    lines.extend(
        [
            "",
            "## Top N+1 Queries",
            "",
            "| # | Count | N+1 | Max ms | Query |",
            "|---|------:|----:|-------:|-------|",
        ]
    )
    for index, row in enumerate(top_queries.get("n_plus_1", []), start=1):
        row_map = row if isinstance(row, dict) else {}
        lines.append(
            "| {index} | {count} | {nplus1} | {max_ms} | {query} |".format(
                index=index,
                count=row_map.get("count", 0),
                nplus1=row_map.get("n_plus_1_count", 0),
                max_ms=row_map.get("max_duration_ms", 0),
                query=escape_markdown_pipe(compact_query(str(row_map.get("query", "")), 180)),
            )
        )
    lines.extend(
        [
            "",
            "## Top Error Queries",
            "",
            "| # | Count | Errors | Max ms | Query |",
            "|---|------:|-------:|-------:|-------|",
        ]
    )
    for index, row in enumerate(top_queries.get("errors", []), start=1):
        row_map = row if isinstance(row, dict) else {}
        lines.append(
            "| {index} | {count} | {errors} | {max_ms} | {query} |".format(
                index=index,
                count=row_map.get("count", 0),
                errors=row_map.get("error_count", 0),
                max_ms=row_map.get("max_duration_ms", 0),
                query=escape_markdown_pipe(compact_query(str(row_map.get("query", "")), 180)),
            )
        )

    lines.extend(
        [
            "",
            "## Top Slow Events",
            "",
            "| # | Seq | ms | Status | Query |",
            "|---|----:|---:|--------|-------|",
        ]
    )
    for index, row in enumerate(top_events.get("slow", []), start=1):
        row_map = row if isinstance(row, dict) else {}
        lines.append(
            "| {index} | {seq} | {ms} | {status} | {query} |".format(
                index=index,
                seq=row_map.get("sequence", 0),
                ms=row_map.get("duration_ms", 0),
                status=escape_markdown_pipe(str(row_map.get("status", ""))),
                query=escape_markdown_pipe(compact_query(str(row_map.get("query", "")), 180)),
            )
        )

    return "\n".join(lines) + "\n"


def escape_markdown_pipe(text: str) -> str:
    return text.replace("|", "\\|")


def default_settings() -> ConfigSettings:
    """EN: Return baseline runtime settings.
    RU: Вернуть базовые настройки выполнения.

    Returns:
        ConfigSettings: EN: Default settings object.
            RU: Объект настроек по умолчанию.
    """
    return ConfigSettings(
        listen="127.0.0.1:5433",
        upstream="127.0.0.1:5432",
        max_events=1000,
        max_connections=DEFAULT_MAX_CONNECTIONS,
        slow_ms=100.0,
        refresh_ms=200,
        socket_timeout_seconds=DEFAULT_SOCKET_TIMEOUT_SECONDS,
        max_startup_packet_bytes=DEFAULT_MAX_STARTUP_PACKET_BYTES,
        max_protocol_packet_bytes=DEFAULT_MAX_PROTOCOL_PACKET_BYTES,
        max_pending_events_per_connection=DEFAULT_MAX_PENDING_EVENTS_PER_CONNECTION,
        no_tui=False,
        log_level="WARNING",
        log_file="",
        allow_remote_listen=False,
        client_allowlist="",
        dsn=os.environ.get("DATABASE_URL", ""),
        allow_unsafe_explain_analyze=False,
        filter_query="",
        response_body="none",
        save_file="",
        save_format="jsonl",
        save_profile="default",
        save_response="none",
        report_file="",
        report_format="json",
        report_top=10,
        jsonl_flush_every=DEFAULT_JSONL_FLUSH_EVERY,
        nplus1_threshold=DEFAULT_NPLUS1_THRESHOLD,
        nplus1_window=DEFAULT_NPLUS1_WINDOW_SECONDS,
        nplus1_cooldown=DEFAULT_NPLUS1_COOLDOWN_SECONDS,
        nplus1_max_tracked_keys=DEFAULT_NPLUS1_MAX_TRACKED_KEYS,
    )


def duration_config_to_seconds(value: object) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    match = re.match(r"^(\d+(?:\.\d+)?)(us|µs|ms|s|m)$", text, re.IGNORECASE)
    if not match:
        raise ValueError(f"invalid duration: {value}")
    number, unit = match.groups()
    return parse_duration_token(number, unit)


def duration_config_to_ms(value: object) -> float:
    return duration_config_to_seconds(value) * 1000.0


def settings_from_config(config: Dict[str, object], path: str) -> ConfigSettings:
    """EN: Build settings from config mapping with type conversions.
    RU: Построить настройки из config-словаря с преобразованием типов.

    Args:
        config (Dict[str, object]): EN: Parsed config map.
            RU: Распарсенный config-словарь.
        path (str): EN: Config source label/path for notices.
            RU: Путь/метка источника конфига для notice.

    Returns:
        ConfigSettings: EN: Settings resolved from config only.
            RU: Настройки, полученные только из конфига.

    Raises:
        ValueError: EN: Invalid duration tokens in config.
            RU: Некорректные duration-значения в конфиге.
    """
    settings = default_settings()
    settings.config_path = path
    if not config:
        return settings
    if "listen" in config:
        settings.listen = str(config["listen"])
    if "upstream" in config:
        settings.upstream = str(config["upstream"])
    if "max_events" in config:
        settings.max_events = int(config["max_events"])
    if "max_connections" in config:
        settings.max_connections = int(config["max_connections"])
    if "slow_ms" in config:
        settings.slow_ms = float(config["slow_ms"])
    if "slow_threshold" in config:
        settings.slow_ms = duration_config_to_ms(config["slow_threshold"])
    if "refresh_ms" in config:
        settings.refresh_ms = int(config["refresh_ms"])
    if "socket_timeout_seconds" in config:
        settings.socket_timeout_seconds = float(config["socket_timeout_seconds"])
    if "max_startup_packet_bytes" in config:
        settings.max_startup_packet_bytes = int(config["max_startup_packet_bytes"])
    if "max_protocol_packet_bytes" in config:
        settings.max_protocol_packet_bytes = int(config["max_protocol_packet_bytes"])
    if "max_pending_events_per_connection" in config:
        settings.max_pending_events_per_connection = int(config["max_pending_events_per_connection"])
    if "no_tui" in config:
        settings.no_tui = bool(config["no_tui"])
    if "allow_remote_listen" in config:
        settings.allow_remote_listen = bool(config["allow_remote_listen"])
    if "client_allowlist" in config:
        settings.client_allowlist = str(config["client_allowlist"])
    if "log_level" in config:
        settings.log_level = str(config["log_level"]).upper()
    if "log_file" in config:
        settings.log_file = str(config["log_file"])
    dsn_env = str(config.get("dsn_env", "")).strip()
    if "dsn" in config:
        settings.dsn = str(config["dsn"])
    elif dsn_env:
        settings.dsn = os.environ.get(dsn_env, settings.dsn)
    if "allow_unsafe_explain_analyze" in config:
        settings.allow_unsafe_explain_analyze = bool(config["allow_unsafe_explain_analyze"])
    if "filter" in config:
        settings.filter_query = str(config["filter"])
    if "response_body" in config:
        settings.response_body = str(config["response_body"]).lower()
    if "save_file" in config:
        settings.save_file = str(config["save_file"])
    if "save_format" in config:
        settings.save_format = str(config["save_format"]).lower()
    if "save_profile" in config:
        settings.save_profile = str(config["save_profile"]).lower()
    if "save_response" in config:
        settings.save_response = str(config["save_response"]).lower()
    if "report_file" in config:
        settings.report_file = str(config["report_file"])
    if "report_format" in config:
        settings.report_format = str(config["report_format"]).lower()
    if "report_top" in config:
        settings.report_top = int(config["report_top"])
    if "jsonl_flush_every" in config:
        settings.jsonl_flush_every = int(config["jsonl_flush_every"])
    nplus1 = config.get("nplus1", {})
    if isinstance(nplus1, dict):
        if "threshold" in nplus1:
            settings.nplus1_threshold = int(nplus1["threshold"])
        if "window" in nplus1:
            settings.nplus1_window = duration_config_to_seconds(nplus1["window"])
        if "cooldown" in nplus1:
            settings.nplus1_cooldown = duration_config_to_seconds(nplus1["cooldown"])
        if "max_tracked_keys" in nplus1:
            settings.nplus1_max_tracked_keys = int(nplus1["max_tracked_keys"])
    if "nplus1_max_tracked_keys" in config:
        settings.nplus1_max_tracked_keys = int(config["nplus1_max_tracked_keys"])
    return settings


def apply_cli_overrides(settings: ConfigSettings, args: argparse.Namespace) -> ConfigSettings:
    """EN: Override config settings with explicit CLI arguments.
    RU: Переопределить настройки из конфига явными CLI-аргументами.

    Args:
        settings (ConfigSettings): EN: Base settings from config.
            RU: Базовые настройки из конфига.
        args (argparse.Namespace): EN: Parsed CLI args.
            RU: Распарсенные CLI-аргументы.

    Returns:
        ConfigSettings: EN: Effective merged settings.
            RU: Итоговые объединенные настройки.
    """
    for field_name in (
        "listen",
        "upstream",
        "max_events",
        "max_connections",
        "slow_ms",
        "refresh_ms",
        "socket_timeout_seconds",
        "max_startup_packet_bytes",
        "max_protocol_packet_bytes",
        "max_pending_events_per_connection",
        "no_tui",
        "allow_remote_listen",
        "client_allowlist",
        "log_level",
        "log_file",
        "dsn",
        "allow_unsafe_explain_analyze",
        "filter_query",
        "response_body",
        "save_file",
        "save_format",
        "save_profile",
        "save_response",
        "report_file",
        "report_format",
        "report_top",
        "jsonl_flush_every",
        "nplus1_threshold",
        "nplus1_window",
        "nplus1_cooldown",
        "nplus1_max_tracked_keys",
    ):
        value = getattr(args, field_name)
        if value is not None:
            setattr(settings, field_name, value)
    if args.vault_url and args.vault_path:
        settings.config_path = f"vault:{args.vault_path}"
    elif args.encrypted_config:
        settings.config_path = os.path.abspath(args.encrypted_config)
    elif args.config:
        settings.config_path = args.config
    return settings


def configure_logging(log_level: str, no_tui: bool, log_file: str) -> None:
    """EN: Configure root logging handlers based on runtime mode.
    RU: Настроить root-логирование в зависимости от режима запуска.

    Args:
        log_level (str): EN: Logging level name. RU: Имя уровня логирования.
        no_tui (bool): EN: Headless mode flag. RU: Флаг headless-режима.
        log_file (str): EN: Optional log file path.
            RU: Необязательный путь к файлу логов.
    """
    handlers: List[logging.Handler]
    if log_file:
        handlers = [logging.FileHandler(log_file)]
    elif no_tui:
        handlers = [logging.StreamHandler()]
    else:
        handlers = [logging.NullHandler()]

    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )


def build_parser() -> argparse.ArgumentParser:
    """EN: Build command-line parser for sqltracer runtime.
    RU: Создать парсер аргументов командной строки для sqltracer.

    Returns:
        argparse.ArgumentParser: EN: Configured parser.
            RU: Настроенный парсер аргументов.
    """
    parser = argparse.ArgumentParser(
        description="Single-file PostgreSQL SQL proxy with a curses TUI.",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="path to config file; auto-loads .sqltracer.yaml when present",
    )
    parser.add_argument(
        "--encrypted-config",
        default=None,
        help="path to an encrypted config file created by config-encryptor.py",
    )
    parser.add_argument(
        "--vault-url",
        default=None,
        help="HashiCorp Vault base URL, for example https://vault.example.org:8200",
    )
    parser.add_argument(
        "--vault-path",
        default=None,
        help="HashiCorp Vault secret path; userpass auth is used to read it",
    )
    parser.add_argument(
        "--vault-username",
        default=None,
        help="Vault username for userpass auth; falls back to VAULT_USERNAME or prompt",
    )
    parser.add_argument(
        "--vault-password",
        default=None,
        help="Vault password for userpass auth; falls back to VAULT_PASSWORD or prompt",
    )
    parser.add_argument(
        "--allow-insecure-vault-http",
        action="store_const",
        const=True,
        default=False,
        help="allow Vault URL over http:// (insecure; use only for local test environments)",
    )
    parser.add_argument(
        "--allow-cli-secrets",
        action="store_const",
        const=True,
        default=False,
        help="allow secrets in CLI arguments (unsafe; can leak via process list/history)",
    )
    parser.add_argument(
        "--listen",
        default=None,
        help="local proxy listen address, default: 127.0.0.1:5433",
    )
    parser.add_argument(
        "--upstream",
        default=None,
        help="upstream PostgreSQL address, default: 127.0.0.1:5432",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=None,
        help="maximum number of events kept in memory, default: 1000",
    )
    parser.add_argument(
        "--max-connections",
        type=int,
        default=None,
        help=f"maximum number of concurrent proxied connections, default: {DEFAULT_MAX_CONNECTIONS}",
    )
    parser.add_argument(
        "--slow-ms",
        type=float,
        default=None,
        help="slow query threshold in milliseconds, default: 100",
    )
    parser.add_argument(
        "--refresh-ms",
        type=int,
        default=None,
        help="TUI refresh interval in milliseconds, default: 200",
    )
    parser.add_argument(
        "--socket-timeout-seconds",
        type=float,
        default=None,
        help=f"socket I/O timeout in seconds, default: {DEFAULT_SOCKET_TIMEOUT_SECONDS}",
    )
    parser.add_argument(
        "--max-startup-packet-bytes",
        type=int,
        default=None,
        help=f"max startup packet size in bytes, default: {DEFAULT_MAX_STARTUP_PACKET_BYTES}",
    )
    parser.add_argument(
        "--max-protocol-packet-bytes",
        type=int,
        default=None,
        help=f"max protocol packet size in bytes, default: {DEFAULT_MAX_PROTOCOL_PACKET_BYTES}",
    )
    parser.add_argument(
        "--max-pending-events-per-connection",
        type=int,
        default=None,
        help=f"max in-flight events kept per connection before disconnect, default: {DEFAULT_MAX_PENDING_EVENTS_PER_CONNECTION}",
    )
    parser.add_argument(
        "--allow-remote-listen",
        action="store_const",
        const=True,
        default=None,
        help="allow listen address outside loopback (dangerous unless protected by network controls)",
    )
    parser.add_argument(
        "--client-allowlist",
        default=None,
        help="comma-separated client IPs/CIDRs allowed to connect (example: 127.0.0.1,10.0.0.0/8)",
    )
    parser.add_argument(
        "--no-tui",
        action="store_const",
        const=True,
        default=None,
        help="disable curses TUI and print captured events to stdout",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="logging level for proxy diagnostics, default: WARNING",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="write diagnostic logs to a file; recommended for TUI mode",
    )
    parser.add_argument(
        "--dsn",
        default=None,
        help="PostgreSQL DSN used for EXPLAIN / EXPLAIN ANALYZE; defaults to DATABASE_URL",
    )
    parser.add_argument(
        "--allow-unsafe-explain-analyze",
        action="store_const",
        const=True,
        default=None,
        help="allow EXPLAIN ANALYZE for non-read-only statements",
    )
    parser.add_argument(
        "--filter",
        dest="filter_query",
        default=None,
        help="startup filter query; in --no-tui mode only matching events are printed/saved",
    )
    parser.add_argument(
        "--response-body",
        default=None,
        choices=["none", "preview"],
        help="in --no-tui mode, print no response body or a bounded preview; default: none",
    )
    parser.add_argument(
        "--save-file",
        default=None,
        help="write captured events to a file in TUI and --no-tui modes",
    )
    parser.add_argument(
        "--save-format",
        default=None,
        choices=["jsonl", "json"],
        help="save file format, default: jsonl",
    )
    parser.add_argument(
        "--save-profile",
        default=None,
        choices=["minimal", "default", "full"],
        help="event detail level for --save-file, default: default",
    )
    parser.add_argument(
        "--save-response",
        default=None,
        choices=["none", "preview"],
        help="response body inclusion for --save-file, default: none",
    )
    parser.add_argument(
        "--report-file",
        default=None,
        help="write aggregated summary report (slow/N+1/error) to a file",
    )
    parser.add_argument(
        "--report-format",
        default=None,
        choices=["json", "markdown"],
        help="report format for --report-file, default: json",
    )
    parser.add_argument(
        "--report-top",
        type=int,
        default=None,
        help="top N items per section in summary report, default: 10",
    )
    parser.add_argument(
        "--jsonl-flush-every",
        type=int,
        default=None,
        help=f"flush jsonl sink after N events, default: {DEFAULT_JSONL_FLUSH_EVERY}",
    )
    parser.add_argument(
        "--nplus1-threshold",
        type=int,
        default=None,
        help="N+1 detection threshold, default: 5; set 0 to disable",
    )
    parser.add_argument(
        "--nplus1-window",
        type=float,
        default=None,
        help="N+1 detection sliding window in seconds, default: 1.0",
    )
    parser.add_argument(
        "--nplus1-cooldown",
        type=float,
        default=None,
        help="N+1 alert cooldown in seconds per query template, default: 10.0",
    )
    parser.add_argument(
        "--nplus1-max-tracked-keys",
        type=int,
        default=None,
        help=f"max tracked N+1 query keys in memory, default: {DEFAULT_NPLUS1_MAX_TRACKED_KEYS}",
    )
    return parser


def main() -> int:
    """EN: Program entrypoint: load config, start proxy, run TUI/headless loop.
    RU: Точка входа: загрузка конфига, старт прокси и цикл TUI/headless.

    Returns:
        int: EN: Process exit code (0 on success).
            RU: Код завершения процесса (0 при успехе).
    """
    parser = build_parser()
    argv = sys.argv[1:]
    args = parser.parse_args(argv)
    if args.vault_password and not args.allow_cli_secrets:
        parser.error(
            "--vault-password in CLI is disabled by default; use VAULT_PASSWORD env var/prompt, "
            "or pass --allow-cli-secrets explicitly"
        )
    try:
        config_data, config_source = config_sources.load_config_source(args, argv)
    except RuntimeError as exc:
        parser.error(str(exc))
    settings = apply_cli_overrides(settings_from_config(config_data, config_source), args)
    client_allowlist_networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
    try:
        if settings.filter_query:
            compile_filter(settings.filter_query)
        if settings.max_connections <= 0:
            raise ValueError(f"invalid max_connections: {settings.max_connections}")
        if settings.socket_timeout_seconds <= 0:
            raise ValueError(f"invalid socket_timeout_seconds: {settings.socket_timeout_seconds}")
        if settings.max_startup_packet_bytes < 1024:
            raise ValueError(f"invalid max_startup_packet_bytes: {settings.max_startup_packet_bytes}")
        if settings.max_protocol_packet_bytes < 1024:
            raise ValueError(f"invalid max_protocol_packet_bytes: {settings.max_protocol_packet_bytes}")
        if settings.max_startup_packet_bytes > settings.max_protocol_packet_bytes:
            raise ValueError(
                "max_startup_packet_bytes cannot exceed max_protocol_packet_bytes"
            )
        if settings.max_pending_events_per_connection <= 0:
            raise ValueError(
                f"invalid max_pending_events_per_connection: {settings.max_pending_events_per_connection}"
            )
        if settings.nplus1_max_tracked_keys <= 0:
            raise ValueError(f"invalid nplus1_max_tracked_keys: {settings.nplus1_max_tracked_keys}")
        if settings.response_body not in ("none", "preview"):
            raise ValueError(f"invalid response_body: {settings.response_body}")
        if settings.save_format not in ("jsonl", "json"):
            raise ValueError(f"invalid save_format: {settings.save_format}")
        if settings.save_profile not in ("minimal", "default", "full"):
            raise ValueError(f"invalid save_profile: {settings.save_profile}")
        if settings.save_response not in ("none", "preview"):
            raise ValueError(f"invalid save_response: {settings.save_response}")
        if settings.report_format not in ("json", "markdown"):
            raise ValueError(f"invalid report_format: {settings.report_format}")
        if settings.report_top <= 0:
            raise ValueError(f"invalid report_top: {settings.report_top}")
        if settings.jsonl_flush_every <= 0:
            raise ValueError(f"invalid jsonl_flush_every: {settings.jsonl_flush_every}")
        listen_host, _ = parse_host_port(settings.listen)
        if not is_loopback_host(listen_host) and not settings.allow_remote_listen:
            raise ValueError(
                f"refusing non-loopback listen address {settings.listen}; use --allow-remote-listen to override"
            )
        client_allowlist_networks = parse_client_allowlist(settings.client_allowlist)
    except ValueError as exc:
        parser.error(str(exc))

    configure_logging(log_level=settings.log_level, no_tui=settings.no_tui, log_file=settings.log_file)
    if args.vault_password and args.allow_cli_secrets:
        LOGGER.warning("--vault-password was passed via CLI with --allow-cli-secrets enabled")

    store = EventStore(
        max_events=settings.max_events,
        slow_ms=settings.slow_ms,
        nplus1_threshold=settings.nplus1_threshold,
        nplus1_window_seconds=settings.nplus1_window,
        nplus1_cooldown_seconds=settings.nplus1_cooldown,
        nplus1_max_tracked_keys=settings.nplus1_max_tracked_keys,
    )
    if settings.config_path:
        store.add_notice(f"Loaded config {settings.config_path}")
    if settings.client_allowlist:
        store.add_notice(f"Client allowlist enabled: {settings.client_allowlist}")
    sinks: List[object] = []
    sink_thread: Optional[threading.Thread] = None
    if settings.no_tui:
        sinks.append(StdoutEventSink(filter_query=settings.filter_query, response_mode=settings.response_body))
    if settings.save_file:
        sinks.append(
            FileEventSink(
                path=settings.save_file,
                fmt=settings.save_format,
                profile=settings.save_profile,
                response_mode=settings.save_response,
                filter_query=settings.filter_query,
                flush_every=settings.jsonl_flush_every,
            )
        )
        store.add_notice(
            f"Saving events to {os.path.abspath(settings.save_file)} "
            f"({settings.save_format}, {settings.save_profile}, response={settings.save_response})"
        )
    if settings.report_file:
        sinks.append(
            SummaryReportSink(
                path=settings.report_file,
                fmt=settings.report_format,
                top_n=settings.report_top,
                filter_query=settings.filter_query,
            )
        )
        store.add_notice(
            f"Summary report will be written to {os.path.abspath(settings.report_file)} "
            f"({settings.report_format}, top={settings.report_top})"
        )
    proxy = PostgresProxy(
        listen_address=settings.listen,
        upstream_address=settings.upstream,
        store=store,
        max_connections=settings.max_connections,
        socket_timeout_seconds=settings.socket_timeout_seconds,
        max_startup_packet_bytes=settings.max_startup_packet_bytes,
        max_protocol_packet_bytes=settings.max_protocol_packet_bytes,
        max_pending_events_per_connection=settings.max_pending_events_per_connection,
        client_allowlist_networks=client_allowlist_networks,
    )
    try:
        proxy.start()
    except Exception as exc:
        message = f"failed to start proxy on {settings.listen}: {exc}"
        LOGGER.error(message)
        print(message, flush=True)
        return 1
    stop_event = threading.Event()

    try:
        if settings.no_tui:
            run_headless(store, stop_event, sinks)
        else:
            if sinks:
                sink_thread = threading.Thread(
                    target=run_event_sinks,
                    args=(store, stop_event, sinks),
                    name="sqltracer-sinks",
                    daemon=True,
                )
                sink_thread.start()
            app = CursesApp(
                store=store,
                proxy=proxy,
                refresh_ms=settings.refresh_ms,
                listen=settings.listen,
                upstream=settings.upstream,
                explain_dsn=settings.dsn,
                allow_unsafe_explain_analyze=settings.allow_unsafe_explain_analyze,
                initial_filter=settings.filter_query,
            )
            app.run()
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        if sink_thread is not None:
            sink_thread.join(timeout=1.0)
        proxy.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
