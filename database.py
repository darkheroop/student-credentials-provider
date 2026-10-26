"""
Database module for Student Credentials Provider.

Supports both persistent Neon PostgreSQL (production) and SQLite (development/fallback).
Provides thread-safe connections, automatic schema initialization, data migration from SQLite,
health status tracking, and failover eligibility queries.
"""

import json
import logging
import os
import secrets
import sqlite3
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from werkzeug.security import generate_password_hash, check_password_hash

from config import Config
from services.crypto import CredentialCrypto

logger = logging.getLogger(__name__)


def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def parse_pg_url(url: str) -> dict[str, Any]:
    """Parse PostgreSQL / Neon connection URL into connection parameters."""
    parsed = urlparse(url)
    user = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    host = parsed.hostname or "localhost"
    port = parsed.port or 5432
    database = unquote(parsed.path.lstrip("/") or "")

    qs = parse_qs(parsed.query)
    sslmode = qs.get("sslmode", ["require"])[0]

    ssl_context = None
    if sslmode in ("require", "verify-ca", "verify-full", "prefer") or "neon.tech" in host:
        ssl_context = True
    elif sslmode == "disable":
        ssl_context = False

    return {
        "user": user,
        "password": password,
        "host": host,
        "port": port,
        "database": database,
        "ssl_context": ssl_context,
    }


class RowDict(dict):
    """Row wrapper compatible with both dict key access, dict(row) conversion, and integer index access."""

    def __init__(self, mapping: dict[str, Any], tuple_row: tuple | None = None):
        super().__init__(mapping)
        self._tuple = tuple_row or tuple(mapping.values())

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            return self._tuple[key]
        return super().__getitem__(key)

    def get(self, key: Any, default: Any = None) -> Any:
        return super().get(key, default)


class PostgresCursor:
    """Cursor wrapper for PostgreSQL (pg8000) that normalizes rows to RowDict mappings and provides lastrowid."""

    def __init__(self, raw_cursor: Any, lastrowid: int | None = None):
        self.raw_cursor = raw_cursor
        self.lastrowid = lastrowid

    def fetchone(self) -> RowDict | None:
        row = self.raw_cursor.fetchone()
        if row is None:
            return None
        if self.raw_cursor.description:
            cols = [d[0] for d in self.raw_cursor.description]
            return RowDict(dict(zip(cols, row)), row)
        return row

    def fetchall(self) -> list[RowDict]:
        rows = self.raw_cursor.fetchall()
        if not rows or not self.raw_cursor.description:
            return []
        cols = [d[0] for d in self.raw_cursor.description]
        return [RowDict(dict(zip(cols, r)), r) for r in rows]

    @property
    def rowcount(self) -> int:
        return self.raw_cursor.rowcount


class PostgresConnection:
    """Wrapper around pg8000 Connection to provide a consistent DBAPI interface matching SQLite."""

    def __init__(self, raw_conn: Any):
        self.raw_conn = raw_conn

    def execute(self, sql: str, params: tuple | list = ()):
        cursor = self.raw_conn.cursor()
        pg_sql = sql.replace("?", "%s")
        auto_returning = False
        if pg_sql.strip().upper().startswith("INSERT INTO ") and "RETURNING" not in pg_sql.upper():
            pg_sql = pg_sql.rstrip(";") + " RETURNING id"
            auto_returning = True

        cursor.execute(pg_sql, params)
        lastrowid = None
        if auto_returning or "RETURNING ID" in pg_sql.upper():
            try:
                row = cursor.fetchone()
                if row:
                    lastrowid = row[0]
            except Exception:
                pass

        return PostgresCursor(cursor, lastrowid=lastrowid)

    def commit(self):
        self.raw_conn.commit()

    def rollback(self):
        try:
            self.raw_conn.rollback()
        except Exception:
            pass

    def close(self):
        try:
            self.raw_conn.close()
        except Exception:
            pass


class Database:
    """Database manager supporting persistent Neon PostgreSQL and local SQLite."""

    def __init__(
        self,
        db_path: str | None = None,
        database_url: str | None = None,
        config: Config | None = None,
        force_production_check: bool = False,
    ):
        self.config = config or Config()
        self.database_url = database_url or self.config.DATABASE_URL
        self.is_postgres = bool(
            self.database_url
            and (
                self.database_url.startswith("postgres://")
                or self.database_url.startswith("postgresql://")
            )
        )

        raw_path = db_path or self.config.DATABASE_PATH

        # Guard against in-memory databases in production
        if raw_path == ":memory:":
            is_prod = os.getenv("FLASK_ENV") == "production"
            is_test = bool(os.getenv("TESTING")) or ("pytest" in sys.modules)
            if is_prod and (not is_test or force_production_check):
                raise ValueError("In-memory SQLite database is strictly prohibited in production mode.")
            self.db_path = ":memory:"
        elif not os.path.isabs(raw_path):
            self.db_path = os.path.abspath(os.path.join(self.config.BASE_DIR, raw_path))
        else:
            self.db_path = os.path.abspath(raw_path)

        # Enforce requirement: If in production (Vercel or FLASK_ENV=production outside test) and DATABASE_URL is missing, fail clearly
        is_prod_env = bool(os.getenv("VERCEL")) or (
            (os.getenv("FLASK_ENV") == "production" or os.getenv("ENVIRONMENT") == "production")
            and not (bool(os.getenv("TESTING")) or ("pytest" in sys.modules))
        )
        if (is_prod_env or (force_production_check and raw_path != ":memory:")) and not self.is_postgres:
            raise RuntimeError(
                "CRITICAL CONFIGURATION ERROR: Neon PostgreSQL DATABASE_URL is missing in production environment. "
                "Persistent Neon PostgreSQL storage is required in production to prevent ephemeral data loss."
            )

        if not self.is_postgres:
            self._ensure_parent_dir()

        self.init_db()
        if self.is_postgres:
            self._migrate_sqlite_to_postgres_if_empty()

    def _ensure_parent_dir(self):
        """Ensure parent directory of database file exists."""
        if self.db_path and self.db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)

    @contextmanager
    def get_connection(self):
        """
        Yield a database connection (Neon PostgreSQL or SQLite) with commit/rollback management.
        Ensures connections are properly committed and closed.
        """
        if self.is_postgres:
            import pg8000.dbapi
            pg_params = parse_pg_url(self.database_url)
            raw_conn = pg8000.dbapi.connect(
                user=pg_params["user"],
                password=pg_params["password"],
                host=pg_params["host"],
                port=pg_params["port"],
                database=pg_params["database"],
                ssl_context=pg_params["ssl_context"],
                timeout=15.0,
            )
            wrapped_conn = PostgresConnection(raw_conn)
            try:
                yield wrapped_conn
            except Exception:
                wrapped_conn.rollback()
                raise
            finally:
                wrapped_conn.close()
        else:
            conn = sqlite3.connect(self.db_path, timeout=15.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA foreign_keys = ON;")
            try:
                yield conn
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def init_db(self):
        """Create database tables and indexes if they do not exist."""
        now_iso = _utc_now_iso()
        if self.is_postgres:
            with self.get_connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS api_configurations (
                        id SERIAL PRIMARY KEY,
                        owner_id INTEGER DEFAULT NULL REFERENCES admin_users(id) ON DELETE SET NULL,
                        provider_name TEXT NOT NULL,
                        display_name TEXT NOT NULL,
                        endpoint TEXT NOT NULL,
                        encrypted_credential TEXT NOT NULL,
                        auth_config TEXT DEFAULT '{}',
                        provider_config TEXT DEFAULT '{}',
                        priority INTEGER NOT NULL DEFAULT 10,
                        enabled INTEGER NOT NULL DEFAULT 1,
                        health_status TEXT NOT NULL DEFAULT 'active',
                        paused_until TEXT DEFAULT NULL,
                        last_success_at TEXT DEFAULT NULL,
                        last_failure_at TEXT DEFAULT NULL,
                        last_error_category TEXT DEFAULT NULL,
                        last_failure_reason TEXT DEFAULT '',
                        consecutive_failures INTEGER NOT NULL DEFAULT 0,
                        total_requests INTEGER NOT NULL DEFAULT 0,
                        total_successes INTEGER NOT NULL DEFAULT 0,
                        notes TEXT DEFAULT '',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS api_event_history (
                        id SERIAL PRIMARY KEY,
                        api_config_id INTEGER NOT NULL REFERENCES api_configurations(id) ON DELETE CASCADE,
                        event_category TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        sanitized_message TEXT NOT NULL,
                        http_status INTEGER DEFAULT NULL,
                        duration DOUBLE PRECISION DEFAULT 0.0
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS admin_users (
                        id SERIAL PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'subadmin',
                        is_active INTEGER NOT NULL DEFAULT 1,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS client_api_keys (
                        id SERIAL PRIMARY KEY,
                        name TEXT NOT NULL,
                        api_key TEXT UNIQUE NOT NULL,
                        is_active INTEGER NOT NULL DEFAULT 1,
                        rate_limit_per_minute INTEGER NOT NULL DEFAULT 60,
                        requests_count INTEGER NOT NULL DEFAULT 0,
                        last_used_at TEXT DEFAULT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS api_rotation_state (
                        id INTEGER PRIMARY KEY,
                        last_config_id INTEGER DEFAULT NULL,
                        last_priority INTEGER DEFAULT NULL,
                        rotation_counter BIGINT NOT NULL DEFAULT 0,
                        updated_at TEXT NOT NULL
                    )
                """)
                # Safe migrations for existing PostgreSQL tables
                try:
                    conn.execute("ALTER TABLE api_configurations ADD COLUMN IF NOT EXISTS owner_id INTEGER DEFAULT NULL REFERENCES admin_users(id) ON DELETE SET NULL")
                    conn.execute("ALTER TABLE api_configurations ADD COLUMN IF NOT EXISTS consecutive_failures INTEGER NOT NULL DEFAULT 0")
                    conn.execute("ALTER TABLE api_configurations ADD COLUMN IF NOT EXISTS last_failure_reason TEXT DEFAULT ''")
                    conn.execute("ALTER TABLE api_configurations ADD COLUMN IF NOT EXISTS total_requests INTEGER NOT NULL DEFAULT 0")
                    conn.execute("ALTER TABLE api_configurations ADD COLUMN IF NOT EXISTS total_successes INTEGER NOT NULL DEFAULT 0")
                except Exception as e:
                    logger.debug("PostgreSQL column addition: %s", e)

                # Seed rotation state row if absent
                conn.execute(
                    """
                    INSERT INTO api_rotation_state (id, last_config_id, last_priority, rotation_counter, updated_at)
                    VALUES (1, NULL, NULL, 0, ?)
                    ON CONFLICT (id) DO NOTHING
                    """,
                    (now_iso,),
                )

                conn.execute("CREATE INDEX IF NOT EXISTS idx_api_config_eligibility ON api_configurations(enabled, health_status, priority)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_api_config_owner ON api_configurations(owner_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_api_event_history_config ON api_event_history(api_config_id, timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_admin_users_username ON admin_users(username)")
                conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_users_username_lower ON admin_users(LOWER(username))")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_client_api_keys_key ON client_api_keys(api_key)")
                conn.commit()
        else:
            with self.get_connection() as conn:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS api_configurations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        owner_id INTEGER DEFAULT NULL,
                        provider_name TEXT NOT NULL,
                        display_name TEXT NOT NULL,
                        endpoint TEXT NOT NULL,
                        encrypted_credential TEXT NOT NULL,
                        auth_config TEXT DEFAULT '{}',
                        provider_config TEXT DEFAULT '{}',
                        priority INTEGER NOT NULL DEFAULT 10,
                        enabled INTEGER NOT NULL DEFAULT 1,
                        health_status TEXT NOT NULL DEFAULT 'active',
                        paused_until TEXT DEFAULT NULL,
                        last_success_at TEXT DEFAULT NULL,
                        last_failure_at TEXT DEFAULT NULL,
                        last_error_category TEXT DEFAULT NULL,
                        last_failure_reason TEXT DEFAULT '',
                        consecutive_failures INTEGER NOT NULL DEFAULT 0,
                        total_requests INTEGER NOT NULL DEFAULT 0,
                        total_successes INTEGER NOT NULL DEFAULT 0,
                        notes TEXT DEFAULT '',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        FOREIGN KEY (owner_id) REFERENCES admin_users(id) ON DELETE SET NULL
                    );

                    CREATE TABLE IF NOT EXISTS api_event_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        api_config_id INTEGER NOT NULL,
                        event_category TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        sanitized_message TEXT NOT NULL,
                        http_status INTEGER DEFAULT NULL,
                        duration REAL DEFAULT 0.0,
                        FOREIGN KEY (api_config_id) REFERENCES api_configurations(id) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS admin_users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'subadmin',
                        is_active INTEGER NOT NULL DEFAULT 1,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS client_api_keys (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        api_key TEXT UNIQUE NOT NULL,
                        is_active INTEGER NOT NULL DEFAULT 1,
                        rate_limit_per_minute INTEGER NOT NULL DEFAULT 60,
                        requests_count INTEGER NOT NULL DEFAULT 0,
                        last_used_at TEXT DEFAULT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS api_rotation_state (
                        id INTEGER PRIMARY KEY,
                        last_config_id INTEGER DEFAULT NULL,
                        last_priority INTEGER DEFAULT NULL,
                        rotation_counter INTEGER NOT NULL DEFAULT 0,
                        updated_at TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_api_config_eligibility
                    ON api_configurations(enabled, health_status, priority);

                    CREATE INDEX IF NOT EXISTS idx_api_event_history_config
                    ON api_event_history(api_config_id, timestamp);

                    CREATE INDEX IF NOT EXISTS idx_admin_users_username
                    ON admin_users(username);

                    CREATE INDEX IF NOT EXISTS idx_client_api_keys_key
                    ON client_api_keys(api_key);
                """)
                # Safe migrations for existing SQLite tables
                cols = [r[1] for r in conn.execute("PRAGMA table_info(api_configurations)").fetchall()]
                if "owner_id" not in cols:
                    conn.execute("ALTER TABLE api_configurations ADD COLUMN owner_id INTEGER DEFAULT NULL")
                if "consecutive_failures" not in cols:
                    conn.execute("ALTER TABLE api_configurations ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0")
                if "last_failure_reason" not in cols:
                    conn.execute("ALTER TABLE api_configurations ADD COLUMN last_failure_reason TEXT DEFAULT ''")
                if "total_requests" not in cols:
                    conn.execute("ALTER TABLE api_configurations ADD COLUMN total_requests INTEGER NOT NULL DEFAULT 0")
                if "total_successes" not in cols:
                    conn.execute("ALTER TABLE api_configurations ADD COLUMN total_successes INTEGER NOT NULL DEFAULT 0")

                conn.execute("CREATE INDEX IF NOT EXISTS idx_api_config_owner ON api_configurations(owner_id)")
                
                # Seed rotation state row if absent
                conn.execute(
                    """
                    INSERT OR IGNORE INTO api_rotation_state (id, last_config_id, last_priority, rotation_counter, updated_at)
                    VALUES (1, NULL, NULL, 0, ?)
                    """,
                    (now_iso,),
                )
                conn.commit()

    def _migrate_sqlite_to_postgres_if_empty(self):
        """
        If connected to a fresh Neon PostgreSQL database and existing SQLite records exist,
        safely and repeatably migrate all data into PostgreSQL without data loss.
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.execute("SELECT COUNT(*) AS cnt FROM admin_users")
                row = cursor.fetchone()
                user_count = row["cnt"] if (row and "cnt" in row) else (row[0] if row else 0)
                if user_count > 0:
                    # PostgreSQL already has data; do not touch
                    return
        except Exception as e:
            logger.warning("Could not check PostgreSQL admin_users count: %s", e)
            return

        # Check if local SQLite database exists with data
        sqlite_file = self.db_path if (self.db_path and self.db_path != ":memory:") else os.path.join(self.config.BASE_DIR, "scp.db")
        if not os.path.isfile(sqlite_file):
            logger.info("Fresh Neon PostgreSQL database initialized. No local SQLite database found to migrate.")
            return

        try:
            # Create a safety backup copy of the SQLite file before reading
            backup_sqlite_path = f"{sqlite_file}.pre_postgres_backup_{int(datetime.now().timestamp())}"
            try:
                import shutil
                shutil.copy2(sqlite_file, backup_sqlite_path)
                logger.info("Created pre-migration SQLite backup at %s", backup_sqlite_path)
            except Exception:
                pass

            src_conn = sqlite3.connect(sqlite_file)
            src_conn.row_factory = sqlite3.Row

            migrated_users = 0
            migrated_configs = 0
            migrated_keys = 0
            migrated_events = 0

            with self.get_connection() as dst_conn:
                # 1. Migrate admin_users
                src_cursor = src_conn.execute("SELECT * FROM admin_users ORDER BY id ASC")
                for u in src_cursor.fetchall():
                    dst_conn.execute(
                        """
                        INSERT INTO admin_users (id, username, password_hash, role, is_active, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT (id) DO NOTHING
                        """,
                        (u["id"], u["username"], u["password_hash"], u["role"], u["is_active"], u["created_at"], u["updated_at"])
                    )
                    migrated_users += 1

                # 2. Migrate api_configurations
                src_cursor = src_conn.execute("SELECT * FROM api_configurations ORDER BY id ASC")
                for c in src_cursor.fetchall():
                    c_dict = dict(c)
                    dst_conn.execute(
                        """
                        INSERT INTO api_configurations (
                            id, owner_id, provider_name, display_name, endpoint, encrypted_credential,
                            auth_config, provider_config, priority, enabled,
                            health_status, paused_until, last_success_at, last_failure_at,
                            last_error_category, last_failure_reason, consecutive_failures,
                            total_requests, total_successes, notes, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT (id) DO NOTHING
                        """,
                        (
                            c_dict.get("id"),
                            c_dict.get("owner_id"),
                            c_dict.get("provider_name"),
                            c_dict.get("display_name"),
                            c_dict.get("endpoint"),
                            c_dict.get("encrypted_credential"),
                            c_dict.get("auth_config", "{}"),
                            c_dict.get("provider_config", "{}"),
                            c_dict.get("priority", 10),
                            c_dict.get("enabled", 1),
                            c_dict.get("health_status", "active"),
                            c_dict.get("paused_until"),
                            c_dict.get("last_success_at"),
                            c_dict.get("last_failure_at"),
                            c_dict.get("last_error_category"),
                            c_dict.get("last_failure_reason", ""),
                            c_dict.get("consecutive_failures", 0),
                            c_dict.get("total_requests", 0),
                            c_dict.get("total_successes", 0),
                            c_dict.get("notes", ""),
                            c_dict.get("created_at"),
                            c_dict.get("updated_at"),
                        )
                    )
                    migrated_configs += 1

                # 3. Migrate client_api_keys
                src_cursor = src_conn.execute("SELECT * FROM client_api_keys ORDER BY id ASC")
                for k in src_cursor.fetchall():
                    dst_conn.execute(
                        """
                        INSERT INTO client_api_keys (
                            id, name, api_key, is_active, rate_limit_per_minute,
                            requests_count, last_used_at, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT (id) DO NOTHING
                        """,
                        (
                            k["id"], k["name"], k["api_key"], k["is_active"], k["rate_limit_per_minute"],
                            k["requests_count"], k["last_used_at"], k["created_at"], k["updated_at"]
                        )
                    )
                    migrated_keys += 1

                # 4. Migrate api_event_history
                src_cursor = src_conn.execute("SELECT * FROM api_event_history ORDER BY id ASC")
                for e in src_cursor.fetchall():
                    dst_conn.execute(
                        """
                        INSERT INTO api_event_history (
                            id, api_config_id, event_category, timestamp,
                            sanitized_message, http_status, duration
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT (id) DO NOTHING
                        """,
                        (e["id"], e["api_config_id"], e["event_category"], e["timestamp"], e["sanitized_message"], e["http_status"], e["duration"])
                    )
                    migrated_events += 1

                # Advance PostgreSQL sequences so subsequent inserts generate non-colliding IDs
                for seq_table in ("admin_users", "api_configurations", "client_api_keys", "api_event_history"):
                    try:
                        dst_conn.execute(
                            f"SELECT setval('{seq_table}_id_seq', COALESCE((SELECT MAX(id) FROM {seq_table}), 1))"
                        )
                    except Exception:
                        pass

                dst_conn.commit()
                logger.info(
                    "SQLite to PostgreSQL migration completed: %d users, %d configs, %d keys, %d events migrated.",
                    migrated_users, migrated_configs, migrated_keys, migrated_events
                )
            src_conn.close()
        except Exception as err:
            logger.error("Error during SQLite to PostgreSQL migration: %s", err)

    # ── Configuration Queries ───────────────────────────────────────────

    def get_all_configs(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        """Retrieve all API configurations, ordered by priority and creation."""
        with self.get_connection() as conn:
            if enabled_only:
                cursor = conn.execute(
                    "SELECT * FROM api_configurations WHERE enabled = 1 ORDER BY priority ASC, id ASC"
                )
            else:
                cursor = conn.execute(
                    "SELECT * FROM api_configurations ORDER BY priority ASC, id ASC"
                )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_config_by_id(self, config_id: int) -> dict[str, Any] | None:
        """Retrieve a specific API configuration by ID."""
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM api_configurations WHERE id = ?", (config_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_eligible_configs(self) -> list[dict[str, Any]]:
        """
        Retrieve all enabled, healthy, non-paused API configurations,
        ordered by priority (ascending).
        
        Automatically clears expired paused_until windows back to 'active'
        for configurations that are not manually disabled or in configuration error.
        """
        now_iso = _utc_now_iso()
        with self.get_connection() as conn:
            # Unpause configurations whose cooldown window has expired
            conn.execute(
                """
                UPDATE api_configurations
                SET health_status = 'active',
                    paused_until = NULL,
                    updated_at = ?
                WHERE enabled = 1
                  AND paused_until IS NOT NULL
                  AND paused_until <= ?
                  AND health_status NOT IN ('config_error', 'auth_failed')
                """,
                (now_iso, now_iso),
            )
            conn.commit()

            cursor = conn.execute(
                """
                SELECT * FROM api_configurations
                WHERE enabled = 1
                  AND health_status = 'active'
                  AND (paused_until IS NULL OR paused_until <= ?)
                ORDER BY priority ASC, id ASC
                """,
                (now_iso,),
            )
            return [dict(r) for r in cursor.fetchall()]

    def get_next_priority(self) -> int:
        """Return the next available sequential priority (max priority + 1, or 1 if empty)."""
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT COALESCE(MAX(priority), 0) + 1 AS next_pri FROM api_configurations")
            row = cursor.fetchone()
            if row:
                return row["next_pri"] if "next_pri" in row else row[0]
            return 1

    def sync_rotation_state_priority(self) -> None:
        """Synchronize api_rotation_state last_priority with last_config_id current priority."""
        try:
            rot = self.get_rotation_state()
            last_id = rot.get("last_config_id")
            if last_id:
                cfg = self.get_config_by_id(last_id)
                if cfg and cfg.get("priority") != rot.get("last_priority"):
                    now_iso = _utc_now_iso()
                    with self.get_connection() as conn:
                        conn.execute(
                            "UPDATE api_rotation_state SET last_priority = ?, updated_at = ? WHERE id = 1",
                            (cfg["priority"], now_iso),
                        )
                        conn.commit()
        except Exception as e:
            logger.debug("Failed to sync rotation priority: %s", e)

    def change_priority(self, config_id: int, new_priority: int) -> list[dict[str, Any]]:
        """
        Move an API configuration to a requested priority position and automatically
        shift other configurations to maintain a consecutive sequence starting at 1.
        Atomically persisted in PostgreSQL/SQLite transaction with row locking.
        """
        from services.priority import validate_priority_input, calculate_reordered_sequence
        validated_pri = validate_priority_input(new_priority)
        now_iso = _utc_now_iso()

        with self.get_connection() as conn:
            query = (
                "SELECT id, priority FROM api_configurations ORDER BY priority ASC, id ASC FOR UPDATE"
                if self.is_postgres
                else "SELECT id, priority FROM api_configurations ORDER BY priority ASC, id ASC"
            )
            cursor = conn.execute(query)
            current_configs = [dict(r) for r in cursor.fetchall()]

            if not current_configs:
                return []

            new_ordered_ids = calculate_reordered_sequence(current_configs, config_id, validated_pri)

            # Phase 1: temporary negative priorities to prevent transient constraint violations
            for idx, cid in enumerate(new_ordered_ids, start=1):
                conn.execute(
                    "UPDATE api_configurations SET priority = ?, updated_at = ? WHERE id = ?",
                    (-idx, now_iso, cid),
                )
            # Phase 2: positive consecutive priorities 1..N
            for idx, cid in enumerate(new_ordered_ids, start=1):
                conn.execute(
                    "UPDATE api_configurations SET priority = ?, updated_at = ? WHERE id = ?",
                    (idx, now_iso, cid),
                )
            conn.commit()

        self.sync_rotation_state_priority()
        return self.get_all_configs()

    def normalize_priorities(self) -> list[dict[str, Any]]:
        """
        Normalize priorities of all api_configurations to sequential 1, 2, 3...
        preserving existing relative priority order and ID tie-breaking.
        """
        now_iso = _utc_now_iso()
        with self.get_connection() as conn:
            query = (
                "SELECT id FROM api_configurations ORDER BY priority ASC, id ASC FOR UPDATE"
                if self.is_postgres
                else "SELECT id FROM api_configurations ORDER BY priority ASC, id ASC"
            )
            cursor = conn.execute(query)
            rows = cursor.fetchall()
            # Phase 1: temporary negative priorities
            for idx, r in enumerate(rows, start=1):
                cfg_id = r["id"] if (isinstance(r, dict) or hasattr(r, "__getitem__")) else r[0]
                conn.execute(
                    "UPDATE api_configurations SET priority = ?, updated_at = ? WHERE id = ?",
                    (-idx, now_iso, cfg_id),
                )
            # Phase 2: positive consecutive priorities
            for idx, r in enumerate(rows, start=1):
                cfg_id = r["id"] if (isinstance(r, dict) or hasattr(r, "__getitem__")) else r[0]
                conn.execute(
                    "UPDATE api_configurations SET priority = ?, updated_at = ? WHERE id = ?",
                    (idx, now_iso, cfg_id),
                )
            conn.commit()
        self.sync_rotation_state_priority()
        return self.get_all_configs()

    def reorder_priorities(self, config_ids: list[int]) -> bool:
        """
        Reorder configurations giving consecutive priorities 1..N
        based on the ordered list of config_ids.
        """
        if not config_ids:
            return False
        now_iso = _utc_now_iso()
        with self.get_connection() as conn:
            # Phase 1: temporary negative priorities
            for priority_num, cfg_id in enumerate(config_ids, start=1):
                conn.execute(
                    "UPDATE api_configurations SET priority = ?, updated_at = ? WHERE id = ?",
                    (-priority_num, now_iso, int(cfg_id)),
                )
            # Phase 2: final positive consecutive priorities
            for priority_num, cfg_id in enumerate(config_ids, start=1):
                conn.execute(
                    "UPDATE api_configurations SET priority = ?, updated_at = ? WHERE id = ?",
                    (priority_num, now_iso, int(cfg_id)),
                )
            conn.commit()
        self.sync_rotation_state_priority()
        return True

    def move_priority(self, config_id: int, direction: str) -> bool:
        """
        Move a configuration 'up' (higher priority, smaller number)
        or 'down' (lower priority, larger number) by shifting its position
        using the priority reordering service.
        """
        configs = self.get_all_configs()
        if not configs:
            return False

        idx = next((i for i, c in enumerate(configs) if c["id"] == config_id), None)
        if idx is None:
            return False

        cur_priority = configs[idx]["priority"]
        if direction == "up":
            if cur_priority <= 1:
                return False  # Already at top
            target_pri = cur_priority - 1
        elif direction == "down":
            if cur_priority >= len(configs):
                return False  # Already at bottom
            target_pri = cur_priority + 1
        else:
            return False

        self.change_priority(config_id, target_pri)
        return True

    def get_rotation_state(self) -> dict[str, Any]:
        """Fetch the persistent rotation state from PostgreSQL/SQLite."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT last_config_id, last_priority, rotation_counter, updated_at FROM api_rotation_state WHERE id = 1"
            )
            row = cursor.fetchone()
            if row:
                return {
                    "last_config_id": row["last_config_id"] if "last_config_id" in row else row[0],
                    "last_priority": row["last_priority"] if "last_priority" in row else row[1],
                    "rotation_counter": int(row["rotation_counter"] if "rotation_counter" in row else row[2]),
                    "updated_at": row["updated_at"] if "updated_at" in row else row[3],
                }
            return {"last_config_id": None, "last_priority": None, "rotation_counter": 0, "updated_at": ""}

    def update_rotation_state(self, last_config_id: int | None, last_priority: int | None = None) -> None:
        """Atomically update the last used config and increment rotation counter."""
        now_iso = _utc_now_iso()
        with self.get_connection() as conn:
            conn.execute(
                """
                UPDATE api_rotation_state
                SET last_config_id = ?,
                    last_priority = ?,
                    rotation_counter = rotation_counter + 1,
                    updated_at = ?
                WHERE id = 1
                """,
                (last_config_id, last_priority, now_iso),
            )
            conn.commit()

    def insert_config(
        self,
        provider_name: str,
        display_name: str,
        endpoint: str,
        encrypted_credential: str,
        priority: int | None = None,
        enabled: int = 1,
        auth_config: dict | None = None,
        provider_config: dict | None = None,
        notes: str = "",
        owner_id: int | None = None,
    ) -> int:
        """Insert a new API configuration record and return its ID."""
        now_iso = _utc_now_iso()
        auth_json = json.dumps(auth_config or {})
        provider_json = json.dumps(provider_config or {})

        with self.get_connection() as conn:
            if priority is None or int(priority) <= 0:
                # Atomically assign next priority: MAX(priority) + 1
                cursor = conn.execute(
                    """
                    INSERT INTO api_configurations (
                        owner_id, provider_name, display_name, endpoint, encrypted_credential,
                        auth_config, provider_config, priority, enabled,
                        health_status, notes, created_at, updated_at,
                        consecutive_failures, last_failure_reason,
                        total_requests, total_successes
                    ) VALUES (
                        ?, ?, ?, ?, ?,
                        ?, ?, (SELECT COALESCE(MAX(priority), 0) + 1 FROM api_configurations), ?,
                        'active', ?, ?, ?,
                        0, '',
                        0, 0
                    )
                    """,
                    (
                        owner_id,
                        provider_name.strip().lower(),
                        display_name.strip(),
                        endpoint.strip(),
                        encrypted_credential,
                        auth_json,
                        provider_json,
                        1 if enabled else 0,
                        (notes or "").strip(),
                        now_iso,
                        now_iso,
                    ),
                )
            else:
                cursor = conn.execute(
                    """
                    INSERT INTO api_configurations (
                        owner_id, provider_name, display_name, endpoint, encrypted_credential,
                        auth_config, provider_config, priority, enabled,
                        health_status, notes, created_at, updated_at,
                        consecutive_failures, last_failure_reason,
                        total_requests, total_successes
                    ) VALUES (
                        ?, ?, ?, ?, ?,
                        ?, ?, ?, ?,
                        'active', ?, ?, ?,
                        0, '',
                        0, 0
                    )
                    """,
                    (
                        owner_id,
                        provider_name.strip().lower(),
                        display_name.strip(),
                        endpoint.strip(),
                        encrypted_credential,
                        auth_json,
                        provider_json,
                        int(priority),
                        1 if enabled else 0,
                        (notes or "").strip(),
                        now_iso,
                        now_iso,
                    ),
                )
            conn.commit()
            new_id = cursor.lastrowid

        if priority is not None and int(priority) > 0:
            try:
                self.change_priority(new_id, int(priority))
            except Exception as e:
                logger.warning("Priority shift after insert failed: %s", e)

        return new_id

    def update_config(
        self,
        config_id: int,
        display_name: str | None = None,
        endpoint: str | None = None,
        encrypted_credential: str | None = None,
        priority: int | None = None,
        enabled: int | None = None,
        notes: str | None = None,
        auth_config: dict | None = None,
        provider_config: dict | None = None,
        owner_id: int | None = None,
    ) -> bool:
        """Update an existing configuration without overwriting unset fields."""
        existing = self.get_config_by_id(config_id)
        if not existing:
            return False

        old_priority = existing["priority"]
        now_iso = _utc_now_iso()
        new_name = display_name.strip() if display_name is not None else existing["display_name"]
        new_endpoint = endpoint.strip() if endpoint is not None else existing["endpoint"]
        new_cred = encrypted_credential if encrypted_credential is not None else existing["encrypted_credential"]
        new_priority = int(priority) if priority is not None else existing["priority"]
        new_enabled = (1 if enabled else 0) if enabled is not None else existing["enabled"]
        new_notes = notes.strip() if notes is not None else existing["notes"]
        new_auth = json.dumps(auth_config) if auth_config is not None else existing["auth_config"]
        new_prov = json.dumps(provider_config) if provider_config is not None else existing["provider_config"]
        new_owner_id = owner_id if owner_id is not None else existing.get("owner_id")

        with self.get_connection() as conn:
            conn.execute(
                """
                UPDATE api_configurations
                SET display_name = ?,
                    endpoint = ?,
                    encrypted_credential = ?,
                    priority = ?,
                    enabled = ?,
                    notes = ?,
                    auth_config = ?,
                    provider_config = ?,
                    owner_id = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    new_name,
                    new_endpoint,
                    new_cred,
                    new_priority,
                    new_enabled,
                    new_notes,
                    new_auth,
                    new_prov,
                    new_owner_id,
                    now_iso,
                    config_id,
                ),
            )
            conn.commit()

        if priority is not None and int(priority) != old_priority:
            self.change_priority(config_id, int(priority))

        return True

    def delete_config(self, config_id: int) -> bool:
        """Delete an API configuration, normalize priorities of remaining configs, and update rotation safely."""
        with self.get_connection() as conn:
            cursor = conn.execute("DELETE FROM api_configurations WHERE id = ?", (config_id,))
            # If deleted config was the rotation cursor, clear last_config_id but preserve last_priority
            conn.execute(
                "UPDATE api_rotation_state SET last_config_id = NULL, updated_at = ? WHERE id = 1 AND last_config_id = ?",
                (_utc_now_iso(), config_id),
            )
            conn.commit()
            deleted = cursor.rowcount > 0
        if deleted:
            try:
                self.normalize_priorities()
            except Exception as e:
                logger.warning("Priority normalization after delete failed: %s", e)
        return deleted

    def set_enabled(self, config_id: int, enabled: bool) -> bool:
        """Toggle an API configuration's enabled state."""
        now_iso = _utc_now_iso()
        with self.get_connection() as conn:
            cursor = conn.execute(
                "UPDATE api_configurations SET enabled = ?, updated_at = ? WHERE id = ?",
                (1 if enabled else 0, now_iso, config_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def set_health_status(
        self,
        config_id: int,
        health_status: str,
        paused_until: str | None = None,
        error_category: str | None = None,
        failure_reason: str | None = None,
        increment_failure: bool = True,
    ) -> bool:
        """Update the health/availability status of an API configuration."""
        now_iso = _utc_now_iso()
        with self.get_connection() as conn:
            if increment_failure:
                cursor = conn.execute(
                    """
                    UPDATE api_configurations
                    SET health_status = ?,
                        paused_until = ?,
                        last_failure_at = ?,
                        last_error_category = ?,
                        last_failure_reason = ?,
                        consecutive_failures = consecutive_failures + 1,
                        total_requests = total_requests + 1,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (health_status, paused_until, now_iso, error_category, failure_reason or "", now_iso, config_id),
                )
            else:
                cursor = conn.execute(
                    """
                    UPDATE api_configurations
                    SET health_status = ?,
                        paused_until = ?,
                        last_failure_at = ?,
                        last_error_category = ?,
                        last_failure_reason = ?,
                        total_requests = total_requests + 1,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (health_status, paused_until, now_iso, error_category, failure_reason or "", now_iso, config_id),
                )
            conn.commit()
            return cursor.rowcount > 0

    def record_success(self, config_id: int, duration: float = 0.0) -> bool:
        """Update last_success_at and reset error fields upon successful call."""
        now_iso = _utc_now_iso()
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE api_configurations
                SET health_status = 'active',
                    paused_until = NULL,
                    last_success_at = ?,
                    last_error_category = NULL,
                    last_failure_reason = '',
                    consecutive_failures = 0,
                    total_requests = total_requests + 1,
                    total_successes = total_successes + 1,
                    updated_at = ?
                WHERE id = ?
                """,
                (now_iso, now_iso, config_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def reactivate(self, config_id: int) -> bool:
        """Manually reactivate a paused or quota-exhausted configuration."""
        now_iso = _utc_now_iso()
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE api_configurations
                SET health_status = 'active',
                    paused_until = NULL,
                    last_error_category = NULL,
                    last_failure_reason = '',
                    consecutive_failures = 0,
                    updated_at = ?
                WHERE id = ?
                """,
                (now_iso, config_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    # ── Event History ───────────────────────────────────────────────────

    def record_event(
        self,
        config_id: int,
        event_category: str,
        sanitized_message: str,
        http_status: int | None = None,
        duration: float = 0.0,
    ) -> int:
        """Record a sanitized event entry in history."""
        now_iso = _utc_now_iso()
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO api_event_history (
                    api_config_id, event_category, timestamp,
                    sanitized_message, http_status, duration
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (config_id, event_category, now_iso, sanitized_message, http_status, float(duration)),
            )
            # Bound history size: keep at most 200 events per config
            if self.is_postgres:
                conn.execute(
                    """
                    DELETE FROM api_event_history
                    WHERE id IN (
                        SELECT id FROM api_event_history
                        WHERE api_config_id = ?
                        ORDER BY timestamp DESC
                        OFFSET 200
                    )
                    """,
                    (config_id,),
                )
            else:
                conn.execute(
                    """
                    DELETE FROM api_event_history
                    WHERE id IN (
                        SELECT id FROM api_event_history
                        WHERE api_config_id = ?
                        ORDER BY timestamp DESC
                        LIMIT -1 OFFSET 200
                    )
                    """,
                    (config_id,),
                )
            conn.commit()
            return cursor.lastrowid

    def get_events_for_config(self, config_id: int, limit: int = 50) -> list[dict[str, Any]]:
        """Retrieve recent sanitized events for a specific API configuration."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM api_event_history
                WHERE api_config_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (config_id, limit),
            )
            return [dict(r) for r in cursor.fetchall()]

    # ── Startup Seeding ─────────────────────────────────────────────────

    def seed_default_if_empty(self, crypto: CredentialCrypto) -> bool:
        """
        Seed the initial MD5Decrypt provider from environment variables if the
        configuration table is currently empty.
        """
        all_configs = self.get_all_configs()
        if all_configs:
            return False

        key = self.config.MD5DECRYPT_API_KEY
        if not key or key == "replace_with_your_api_key":
            return False

        encrypted = crypto.encrypt(key)
        self.insert_config(
            provider_name="md5decrypt",
            display_name="MD5Decrypt Default",
            endpoint=self.config.MD5DECRYPT_API_URL or "https://api.md5decrypt.net/",
            encrypted_credential=encrypted,
            priority=1,
            enabled=1,
            notes="Initial default provider seeded from environment variable.",
        )
        return True

    # ── Admin User Management ──────────────────────────────────────────

    def seed_main_admin_if_empty(self, username: str, password: str) -> bool:
        """
        Ensure the default main administrator account exists.
        If no user with role 'main_admin' exists, creates or updates the record.
        """
        if not username or not password:
            return False

        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM admin_users WHERE role = 'main_admin' LIMIT 1"
            )
            existing_main = cursor.fetchone()
            if existing_main:
                return False

            now_iso = _utc_now_iso()
            hashed = generate_password_hash(password)

            # Check if username exists already
            cursor = conn.execute(
                "SELECT * FROM admin_users WHERE LOWER(username) = LOWER(?)", (username.strip(),)
            )
            user_exists = cursor.fetchone()

            if user_exists:
                conn.execute(
                    """
                    UPDATE admin_users
                    SET password_hash = ?, role = 'main_admin', is_active = 1, updated_at = ?
                    WHERE id = ?
                    """,
                    (hashed, now_iso, user_exists["id"]),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO admin_users (username, password_hash, role, is_active, created_at, updated_at)
                    VALUES (?, ?, 'main_admin', 1, ?, ?)
                    """,
                    (username.strip(), hashed, now_iso, now_iso),
                )
            conn.commit()
            return True

    def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        """Retrieve user record by username (case-insensitive)."""
        if not username:
            return None
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM admin_users WHERE LOWER(username) = LOWER(?)", (username.strip(),)
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_user_by_id(self, user_id: int) -> dict[str, Any] | None:
        """Retrieve user record by primary key ID."""
        if not user_id:
            return None
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM admin_users WHERE id = ?", (user_id,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_all_subadmins(self) -> list[dict[str, Any]]:
        """Retrieve all subadmin users without exposing password hashes."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, username, role, is_active, created_at, updated_at
                FROM admin_users
                WHERE role = 'subadmin'
                ORDER BY id ASC
                """
            )
            return [dict(r) for r in cursor.fetchall()]

    def is_username_taken(self, username: str, exclude_user_id: int | None = None) -> bool:
        """Check if a username is already registered to another user."""
        if not username:
            return False
        with self.get_connection() as conn:
            if exclude_user_id is not None:
                cursor = conn.execute(
                    "SELECT 1 FROM admin_users WHERE LOWER(username) = LOWER(?) AND id != ?",
                    (username.strip(), exclude_user_id),
                )
            else:
                cursor = conn.execute(
                    "SELECT 1 FROM admin_users WHERE LOWER(username) = LOWER(?)",
                    (username.strip(),),
                )
            return cursor.fetchone() is not None

    def create_user(
        self,
        username: str,
        password_hash: str,
        role: str = "subadmin",
        is_active: int = 1,
    ) -> int:
        """Create a new admin or subadmin user."""
        now_iso = _utc_now_iso()
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO admin_users (username, password_hash, role, is_active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (username.strip(), password_hash, role, 1 if is_active else 0, now_iso, now_iso),
            )
            conn.commit()
            return cursor.lastrowid

    def update_user_credentials(
        self,
        user_id: int,
        new_username: str | None = None,
        new_password_hash: str | None = None,
    ) -> bool:
        """Update username and/or password hash for an admin or subadmin."""
        now_iso = _utc_now_iso()
        fields = []
        params = []
        if new_username is not None and str(new_username).strip():
            fields.append("username = ?")
            params.append(str(new_username).strip())
        if new_password_hash is not None and str(new_password_hash).strip():
            fields.append("password_hash = ?")
            params.append(str(new_password_hash).strip())

        if not fields:
            return False

        fields.append("updated_at = ?")
        params.append(now_iso)
        params.append(user_id)

        query = f"UPDATE admin_users SET {', '.join(fields)} WHERE id = ?"
        with self.get_connection() as conn:
            cursor = conn.execute(query, tuple(params))
            conn.commit()
            return cursor.rowcount > 0

    def set_user_active_status(self, user_id: int, is_active: bool) -> bool:
        """
        Enable or disable a subadmin account.
        Disabling main_admin is strictly prohibited.
        """
        now_iso = _utc_now_iso()
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT role FROM admin_users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            if not user or user["role"] == "main_admin":
                return False

            cursor = conn.execute(
                "UPDATE admin_users SET is_active = ?, updated_at = ? WHERE id = ?",
                (1 if is_active else 0, now_iso, user_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def delete_subadmin(self, user_id: int) -> bool:
        """
        Delete a subadmin account.
        Deleting main_admin is strictly prohibited.
        """
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT role FROM admin_users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            if not user or user["role"] == "main_admin":
                return False

            cursor = conn.execute("DELETE FROM admin_users WHERE id = ?", (user_id,))
            conn.commit()
            return cursor.rowcount > 0

    # ── Client API Key Management (External Projects) ──────────────────

    def get_all_client_api_keys(self) -> list[dict[str, Any]]:
        """Retrieve all issued client API keys for external applications."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, name, api_key, is_active, rate_limit_per_minute,
                       requests_count, last_used_at, created_at, updated_at
                FROM client_api_keys
                ORDER BY id DESC
                """
            )
            return [dict(r) for r in cursor.fetchall()]

    def get_client_api_key(self, api_key: str) -> dict[str, Any] | None:
        """Lookup a client API key by its exact secret value."""
        if not api_key:
            return None
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM client_api_keys WHERE api_key = ?",
                (api_key.strip(),),
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def create_client_api_key(
        self,
        name: str,
        rate_limit_per_minute: int = 60,
    ) -> dict[str, Any]:
        """Generate and store a new unique client API key for an external project."""
        now_iso = _utc_now_iso()
        api_key = f"scp_live_{secrets.token_hex(20)}"
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO client_api_keys (
                    name, api_key, is_active, rate_limit_per_minute,
                    requests_count, last_used_at, created_at, updated_at
                ) VALUES (?, ?, 1, ?, 0, NULL, ?, ?)
                """,
                (name.strip(), api_key, rate_limit_per_minute, now_iso, now_iso),
            )
            key_id = cursor.lastrowid
            conn.commit()

        return {
            "id": key_id,
            "name": name.strip(),
            "api_key": api_key,
            "is_active": 1,
            "rate_limit_per_minute": rate_limit_per_minute,
            "requests_count": 0,
            "last_used_at": None,
            "created_at": now_iso,
            "updated_at": now_iso,
        }

    def set_client_api_key_status(self, key_id: int, is_active: bool) -> bool:
        """Enable or revoke an external client API key."""
        now_iso = _utc_now_iso()
        with self.get_connection() as conn:
            cursor = conn.execute(
                "UPDATE client_api_keys SET is_active = ?, updated_at = ? WHERE id = ?",
                (1 if is_active else 0, now_iso, key_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def delete_client_api_key(self, key_id: int) -> bool:
        """Permanently delete a client API key."""
        with self.get_connection() as conn:
            cursor = conn.execute("DELETE FROM client_api_keys WHERE id = ?", (key_id,))
            conn.commit()
            return cursor.rowcount > 0

    def record_api_key_usage(self, api_key: str) -> bool:
        """Increment usage counter and update last_used_at timestamp."""
        now_iso = _utc_now_iso()
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE client_api_keys
                SET requests_count = requests_count + 1,
                    last_used_at = ?,
                    updated_at = ?
                WHERE api_key = ?
                """,
                (now_iso, now_iso, api_key.strip()),
            )
            conn.commit()
            return cursor.rowcount > 0

    # ── Persistence & Serverless State Synchronization ─────────────────

    def seed_subadmins_from_config(self, subadmin_config: str | None) -> list[str]:
        """
        Seed subadmin accounts defined in configuration or environment variable.
        Format: 'username:password,username2:password2' or JSON list of objects.
        Guarantees subadmins persist across Vercel serverless container restarts.
        """
        if not subadmin_config or not str(subadmin_config).strip():
            return []

        raw = str(subadmin_config).strip()
        seeded = []

        # 1. Try JSON format
        if raw.startswith("[") and raw.endswith("]"):
            try:
                items = json.loads(raw)
                for item in items:
                    uname = str(item.get("username") or "").strip()
                    pwd = str(item.get("password") or "").strip()
                    if uname and pwd:
                        if self._seed_single_subadmin(uname, pwd):
                            seeded.append(uname)
                return seeded
            except Exception:
                pass

        # 2. Try comma-separated 'username:password,user2:pass2'
        pairs = [p.strip() for p in raw.split(",") if p.strip()]
        for pair in pairs:
            if ":" in pair:
                parts = pair.split(":", 1)
                uname = parts[0].strip()
                pwd = parts[1].strip()
                if uname and pwd:
                    if self._seed_single_subadmin(uname, pwd):
                        seeded.append(uname)

        return seeded

    def _seed_single_subadmin(self, username: str, password: str) -> bool:
        """Create or ensure an active subadmin user exists."""
        user = self.get_user_by_username(username)
        if not user:
            hashed = generate_password_hash(password)
            self.create_user(username=username, password_hash=hashed, role="subadmin", is_active=1)
            return True
        elif not user["is_active"]:
            self.set_user_active_status(user["id"], True)
            return True
        return True

    def export_backup(self) -> dict[str, Any]:
        """
        Export all subadmins, API configurations, and client API keys into
        a portable JSON backup structure.
        """
        now_iso = _utc_now_iso()
        subadmins = []
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, username, password_hash, role, is_active, created_at, updated_at
                FROM admin_users
                WHERE role = 'subadmin'
                ORDER BY id ASC
                """
            )
            subadmins = [dict(r) for r in cursor.fetchall()]

        configs = self.get_all_configs()
        client_keys = self.get_all_client_api_keys()

        return {
            "version": "1.0",
            "exported_at": now_iso,
            "subadmins": subadmins,
            "api_configurations": configs,
            "client_api_keys": client_keys,
        }

    def import_backup(self, backup_data: dict[str, Any]) -> tuple[bool, str]:
        """
        Restore subadmins, API configurations, and client API keys from backup data.
        """
        if not isinstance(backup_data, dict):
            return False, "Invalid backup data format."

        restored_subadmins = 0
        restored_configs = 0
        restored_keys = 0
        now_iso = _utc_now_iso()

        # 1. Restore subadmins
        for sub in backup_data.get("subadmins", []):
            username = str(sub.get("username") or "").strip()
            pwd_hash = str(sub.get("password_hash") or "").strip()
            if username and pwd_hash and username.lower() != self.config.ADMIN_USERNAME.lower():
                existing = self.get_user_by_username(username)
                if not existing:
                    with self.get_connection() as conn:
                        conn.execute(
                            """
                            INSERT INTO admin_users (username, password_hash, role, is_active, created_at, updated_at)
                            VALUES (?, ?, 'subadmin', ?, ?, ?)
                            """,
                            (
                                username,
                                pwd_hash,
                                1 if sub.get("is_active", 1) else 0,
                                sub.get("created_at") or now_iso,
                                now_iso,
                            ),
                        )
                        conn.commit()
                        restored_subadmins += 1
                else:
                    self.update_user_credentials(existing["id"], new_password_hash=pwd_hash)
                    self.set_user_active_status(existing["id"], bool(sub.get("is_active", 1)))
                    restored_subadmins += 1

        # 2. Restore client API keys
        for key_obj in backup_data.get("client_api_keys", []):
            api_key = str(key_obj.get("api_key") or "").strip()
            name = str(key_obj.get("name") or "").strip()
            if api_key and name:
                existing_key = self.get_client_api_key(api_key)
                if not existing_key:
                    with self.get_connection() as conn:
                        conn.execute(
                            """
                            INSERT INTO client_api_keys (
                                name, api_key, is_active, rate_limit_per_minute,
                                requests_count, last_used_at, created_at, updated_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                name,
                                api_key,
                                1 if key_obj.get("is_active", 1) else 0,
                                int(key_obj.get("rate_limit_per_minute", 60)),
                                int(key_obj.get("requests_count", 0)),
                                key_obj.get("last_used_at"),
                                key_obj.get("created_at") or now_iso,
                                now_iso,
                            ),
                        )
                        conn.commit()
                        restored_keys += 1

        # 3. Restore API configurations
        for cfg in backup_data.get("api_configurations", []):
            display_name = cfg.get("display_name")
            endpoint = cfg.get("endpoint")
            enc_cred = cfg.get("encrypted_credential")
            if display_name and endpoint and enc_cred:
                existing_cfg = any(c["display_name"] == display_name for c in self.get_all_configs())
                if not existing_cfg:
                    self.insert_config(
                        provider_name=cfg.get("provider_name", "md5decrypt"),
                        display_name=display_name,
                        endpoint=endpoint,
                        encrypted_credential=enc_cred,
                        priority=cfg.get("priority", 10),
                        enabled=cfg.get("enabled", 1),
                        notes=cfg.get("notes", ""),
                        owner_id=cfg.get("owner_id"),
                    )
                    restored_configs += 1

        # Persist a snapshot if possible
        self.save_state_snapshot()

        return True, f"Restored {restored_subadmins} subadmin(s), {restored_keys} client key(s), and {restored_configs} API provider(s)."

    def seed_from_state_file(self, state_file_path: str | None = None) -> bool:
        """
        Seed database from a JSON state file if present (e.g. data/seed_state.json).
        Guarantees that subadmins pre-saved in the repo survive all cold boots.
        """
        path = state_file_path or os.path.join(self.config.BASE_DIR, "data", "seed_state.json")
        if not os.path.isfile(path):
            return False

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            ok, _ = self.import_backup(data)
            return ok
        except Exception:
            return False

    def save_state_snapshot(self) -> bool:
        """
        Attempt to write a current snapshot to runtime cache (/tmp/seed_state.json).
        Does not dirty repository source code.
        """
        if "pytest" in sys.modules or os.environ.get("PYTEST_CURRENT_TEST"):
            return False

        if self.is_postgres:
            # Neon PostgreSQL is the authoritative persistent database.
            # Avoid using ephemeral filesystem paths (/tmp) in production.
            return True

        data = self.export_backup()
        # Only write to temporary runtime directory, never dirty source repository
        tmp_path = os.path.join("/tmp", "seed_state.json")
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            return True
        except Exception:
            return False
