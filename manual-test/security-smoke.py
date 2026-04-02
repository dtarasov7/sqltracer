#!/usr/bin/env python3
"""Minimal security smoke checks for sqltracer P0 controls."""

from __future__ import annotations

import datetime as dt
import os
import socket
import stat
import sys
import tempfile

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import sqltracer


def check_private_save_permissions() -> None:
    fd, path = tempfile.mkstemp(prefix="sqltracer-security-", suffix=".jsonl")
    os.close(fd)
    os.unlink(path)
    event = sqltracer.QueryEvent(
        event_id="e-1",
        sequence=1,
        connection_id="conn-1",
        operation="Query",
        query="SELECT 1",
        args=[],
        started_at=dt.datetime.now(dt.timezone.utc),
        duration_ms=1.0,
        rows_affected=1,
        error="",
        tx_id="",
        status_tag="OK",
        slow=False,
        n_plus_1=False,
        n_plus_1_scope="",
        n_plus_1_hits=0,
        n_plus_1_distinct_args=0,
        normalized_query="SELECT ?",
        response_columns=[],
        response_rows=[],
        response_total_rows=0,
        response_total_bytes=0,
        response_truncated=False,
    )
    sink = sqltracer.FileEventSink(
        path=path,
        fmt="jsonl",
        profile="default",
        response_mode="none",
        filter_query="",
        flush_every=1,
    )
    sink.handle(event)
    sink.close()
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode != 0o600:
        raise RuntimeError(f"expected mode 0o600, got {oct(mode)} for {path}")
    os.unlink(path)


def check_pending_limit_enforced() -> None:
    client_sock, peer_sock = socket.socketpair()
    store = sqltracer.EventStore(
        max_events=10,
        slow_ms=1.0,
        nplus1_threshold=0,
        nplus1_window_seconds=1.0,
        nplus1_cooldown_seconds=1.0,
        nplus1_max_tracked_keys=10,
    )
    connection = sqltracer.PostgresProxyConnection(
        client_sock=client_sock,
        client_addr=("127.0.0.1", 54321),
        upstream_host="127.0.0.1",
        upstream_port=5432,
        store=store,
        on_close=lambda _connection: None,
        socket_timeout_seconds=1.0,
        max_startup_packet_bytes=4096,
        max_protocol_packet_bytes=4096,
        max_pending_events_per_connection=1,
    )
    try:
        connection._queue_pending_event("Query", "SELECT 1", [], "")
        try:
            connection._queue_pending_event("Query", "SELECT 2", [], "")
        except RuntimeError as exc:
            if "pending query limit exceeded" not in str(exc):
                raise RuntimeError(f"unexpected error text: {exc}") from exc
        else:
            raise RuntimeError("pending query limit check did not trigger")
    finally:
        connection.close()
        peer_sock.close()


def main() -> int:
    check_private_save_permissions()
    check_pending_limit_enforced()
    print("security smoke checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
