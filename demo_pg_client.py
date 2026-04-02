#!/usr/bin/env python3
import os
import time

import psycopg


DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://appuser:apppass@127.0.0.1:5433/appdb?sslmode=disable",
)
WAIT_TIMEOUT = int(os.environ.get("CLIENT_WAIT_TIMEOUT", "30"))


def wait_for_proxy(dsn: str, timeout_seconds: int) -> None:
    deadline = time.time() + timeout_seconds
    last_error = None
    while time.time() < deadline:
        try:
            with psycopg.connect(dsn, connect_timeout=2) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    cur.fetchone()
            return
        except psycopg.Error as exc:
            last_error = exc
            time.sleep(1)
    raise RuntimeError(f"proxy/database is not ready after {timeout_seconds}s: {last_error}")


def main() -> None:
    print(f"Connecting through proxy: {DATABASE_URL}")
    wait_for_proxy(DATABASE_URL, WAIT_TIMEOUT)

    with psycopg.connect(DATABASE_URL, autocommit=True) as conn:
        with conn.cursor() as cur:
            print("Step 1: truncate demo tables")
            cur.execute("TRUNCATE TABLE order_items, orders, users RESTART IDENTITY CASCADE")

            print("Step 2: insert users with bind parameters")
            users = [
                ("Alice", "alice@example.com"),
                ("Bob", "bob@example.com"),
                ("Charlie", "charlie@example.com"),
            ]
            for name, email in users:
                cur.execute(
                    "INSERT INTO users (name, email) VALUES (%s, %s)",
                    (name, email),
                )

            print("Step 3: select aggregate")
            cur.execute("SELECT COUNT(*) FROM users")
            user_count = cur.fetchone()[0]
            print(f"Users in table: {user_count}")

            print("Step 4: committed transaction with insert and update")
            cur.execute("BEGIN")
            cur.execute(
                "INSERT INTO orders (user_id, total_amount) VALUES (%s, %s) RETURNING id",
                (1, 120.50),
            )
            order_id = cur.fetchone()[0]
            cur.execute(
                "INSERT INTO order_items (order_id, product_name, quantity, unit_price) VALUES (%s, %s, %s, %s)",
                (order_id, "Keyboard", 1, 120.50),
            )
            cur.execute(
                "UPDATE users SET name = %s WHERE id = %s",
                ("Alice Cooper", 1),
            )
            cur.execute("COMMIT")

            print("Step 5: rollback transaction")
            cur.execute("BEGIN")
            cur.execute(
                "INSERT INTO orders (user_id, total_amount) VALUES (%s, %s)",
                (2, 999.99),
            )
            cur.execute("ROLLBACK")

            print("Step 6: parameterized selects to emulate repeated traffic")
            for user_id in (1, 2, 3, 1, 2):
                cur.execute("SELECT id, name, email FROM users WHERE id = %s", (user_id,))
                row = cur.fetchone()
                print(f"Fetched user {row[0]} -> {row[1]}")

            print("Step 7: slow query")
            cur.execute("SELECT pg_sleep(%s)", (0.08,))
            cur.fetchone()

            print("Step 8: expected SQL error")
            try:
                cur.execute("SELECT missing_column FROM users")
                cur.fetchall()
            except psycopg.Error as exc:
                print(f"Caught expected error: {exc.sqlstate} {exc}")

            print("Step 9: long query body with multiple CTEs")
            cur.execute(
                """
                WITH base_users AS (
                    SELECT u.id, u.name, u.email
                    FROM users AS u
                ),
                order_stats AS (
                    SELECT
                        o.user_id,
                        COUNT(*) AS order_count,
                        COALESCE(SUM(o.total_amount), 0) AS total_amount,
                        MAX(o.created_at) AS last_order_at
                    FROM orders AS o
                    GROUP BY o.user_id
                ),
                item_stats AS (
                    SELECT
                        o.user_id,
                        COUNT(oi.id) AS item_count,
                        STRING_AGG(oi.product_name, ', ' ORDER BY oi.product_name) AS product_names
                    FROM orders AS o
                    LEFT JOIN order_items AS oi ON oi.order_id = o.id
                    GROUP BY o.user_id
                ),
                enriched AS (
                    SELECT
                        bu.id,
                        bu.name,
                        bu.email,
                        COALESCE(os.order_count, 0) AS order_count,
                        COALESCE(os.total_amount, 0) AS total_amount,
                        COALESCE(is2.item_count, 0) AS item_count,
                        COALESCE(is2.product_names, '(none)') AS product_names,
                        COALESCE(os.last_order_at::text, 'never') AS last_order_at
                    FROM base_users AS bu
                    LEFT JOIN order_stats AS os ON os.user_id = bu.id
                    LEFT JOIN item_stats AS is2 ON is2.user_id = bu.id
                )
                SELECT
                    e.id,
                    e.name,
                    e.email,
                    e.order_count,
                    e.item_count,
                    e.total_amount,
                    e.product_names,
                    e.last_order_at,
                    CASE
                        WHEN e.order_count = 0 THEN 'no-orders'
                        WHEN e.total_amount >= 100 THEN 'vip'
                        ELSE 'regular'
                    END AS customer_tier
                FROM enriched AS e
                ORDER BY e.id
                """
            )
            for row in cur.fetchall():
                print(f"Long query row: {row[0]} -> {row[1]} / {row[-1]}")

            print("Step 10: large result set in a single response")
            cur.execute(
                """
                SELECT
                    gs AS item_id,
                    repeat(md5(gs::text), 4) AS payload,
                    gs % 7 AS bucket
                FROM generate_series(1, 180) AS gs
                ORDER BY gs
                """
            )
            large_rows = cur.fetchall()
            print(f"Large result rows fetched: {len(large_rows)}")

            print("Step 11: large result set fetched in chunks through a cursor")
            cur.execute("BEGIN")
            cur.execute(
                """
                DECLARE sqltracer_demo_cursor NO SCROLL CURSOR FOR
                SELECT
                    gs AS item_id,
                    repeat(lpad(gs::text, 4, '0'), 25) AS payload,
                    md5((gs * 17)::text) AS checksum
                FROM generate_series(1, 120) AS gs
                ORDER BY gs
                """
            )
            total_cursor_rows = 0
            for chunk_size in (15, 20, 25, 30, 30):
                cur.execute(f"FETCH FORWARD {chunk_size} FROM sqltracer_demo_cursor")
                chunk = cur.fetchall()
                total_cursor_rows += len(chunk)
                print(f"Fetched cursor chunk: requested={chunk_size} got={len(chunk)}")
                if not chunk:
                    break
            cur.execute("CLOSE sqltracer_demo_cursor")
            cur.execute("COMMIT")
            print(f"Cursor rows fetched in total: {total_cursor_rows}")

            print("Step 12: final join query")
            cur.execute(
                """
                SELECT u.name, o.total_amount, oi.product_name
                FROM users AS u
                JOIN orders AS o ON o.user_id = u.id
                JOIN order_items AS oi ON oi.order_id = o.id
                ORDER BY o.id, oi.id
                """
            )
            for row in cur.fetchall():
                print(f"Order row: {row}")

    print("Demo workload finished successfully.")


if __name__ == "__main__":
    main()
