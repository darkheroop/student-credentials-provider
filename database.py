"""
Database module for Student Credentials Provider.

Provides SQLite persistence for dynamic API configurations and event history,
supporting thread-safe connections, automatic schema initialization,
health status tracking, and failover eligibility queries.
"""

import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Any

from werkzeug.security import generate_password_hash, check_password_hash

from config import Config
from services.crypto import CredentialCrypto


def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


class Database:
    """SQLite database manager for API configurations and event history."""

    def __init__(self, db_path: str | None = None, config: Config | None = None):
        self.config = config or Config()
        self.db_path = db_path or self.config.DATABASE_PATH
        self._ensure_parent_dir()
        self.init_db()

    def _ensure_parent_dir(self):
        """Ensure parent directory of database file exists."""
        if self.db_path and self.db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)

    def get_connection(self) -> sqlite3.Connection:
        """Create and return a new SQLite connection with row factory."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def init_db(self):
        """Create database tables and indexes if they do not exist."""
        with self.get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS api_configurations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                    notes TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
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

                CREATE INDEX IF NOT EXISTS idx_api_config_eligibility
                ON api_configurations(enabled, health_status, priority);

                CREATE INDEX IF NOT EXISTS idx_api_event_history_config
                ON api_event_history(api_config_id, timestamp);

                CREATE INDEX IF NOT EXISTS idx_admin_users_username
                ON admin_users(username);

                CREATE INDEX IF NOT EXISTS idx_client_api_keys_key
                ON client_api_keys(api_key);
            """)
            conn.commit()

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
        
        Automatically clears expired paused_until windows back to 'active'.
        """
        now_iso = _utc_now_iso()
        with self.get_connection() as conn:
            # First: automatically unpause configurations whose pause window has passed
            conn.execute(
                """
                UPDATE api_configurations
                SET health_status = 'active', paused_until = NULL, updated_at = ?
                WHERE enabled = 1
                  AND paused_until IS NOT NULL
                  AND paused_until <= ?
                """,
                (now_iso, now_iso),
            )
            conn.commit()

            cursor = conn.execute(
                """
                SELECT * FROM api_configurations
                WHERE enabled = 1
                  AND health_status = 'active'
                ORDER BY priority ASC, id ASC
                """
            )
            return [dict(r) for r in cursor.fetchall()]

    def insert_config(
        self,
        provider_name: str,
        display_name: str,
        endpoint: str,
        encrypted_credential: str,
        priority: int = 10,
        enabled: int = 1,
        auth_config: dict | None = None,
        provider_config: dict | None = None,
        notes: str = "",
    ) -> int:
        """Insert a new API configuration record and return its ID."""
        now_iso = _utc_now_iso()
        auth_json = json.dumps(auth_config or {})
        provider_json = json.dumps(provider_config or {})

        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO api_configurations (
                    provider_name, display_name, endpoint, encrypted_credential,
                    auth_config, provider_config, priority, enabled,
                    health_status, notes, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
                """,
                (
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
            return cursor.lastrowid

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
    ) -> bool:
        """Update an existing configuration without overwriting unset fields."""
        existing = self.get_config_by_id(config_id)
        if not existing:
            return False

        now_iso = _utc_now_iso()
        new_name = display_name.strip() if display_name is not None else existing["display_name"]
        new_endpoint = endpoint.strip() if endpoint is not None else existing["endpoint"]
        new_cred = encrypted_credential if encrypted_credential is not None else existing["encrypted_credential"]
        new_priority = int(priority) if priority is not None else existing["priority"]
        new_enabled = (1 if enabled else 0) if enabled is not None else existing["enabled"]
        new_notes = notes.strip() if notes is not None else existing["notes"]
        new_auth = json.dumps(auth_config) if auth_config is not None else existing["auth_config"]
        new_prov = json.dumps(provider_config) if provider_config is not None else existing["provider_config"]

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
                    now_iso,
                    config_id,
                ),
            )
            conn.commit()
            return True

    def delete_config(self, config_id: int) -> bool:
        """Delete an API configuration and its event history."""
        with self.get_connection() as conn:
            cursor = conn.execute("DELETE FROM api_configurations WHERE id = ?", (config_id,))
            conn.commit()
            return cursor.rowcount > 0

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
    ) -> bool:
        """Update the health/availability status of an API configuration."""
        now_iso = _utc_now_iso()
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE api_configurations
                SET health_status = ?,
                    paused_until = ?,
                    last_failure_at = ?,
                    last_error_category = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (health_status, paused_until, now_iso, error_category, now_iso, config_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def record_success(self, config_id: int, duration: float = 0.0) -> bool:
        """Update last_success_at and reset error category upon successful call."""
        now_iso = _utc_now_iso()
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE api_configurations
                SET health_status = 'active',
                    paused_until = NULL,
                    last_success_at = ?,
                    last_error_category = NULL,
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
            priority=10,
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
                "SELECT * FROM admin_users WHERE username = ?", (username.strip(),)
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
                "SELECT * FROM admin_users WHERE username = ?", (username.strip(),)
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
                    "SELECT 1 FROM admin_users WHERE username = ? AND id != ?",
                    (username.strip(), exclude_user_id),
                )
            else:
                cursor = conn.execute(
                    "SELECT 1 FROM admin_users WHERE username = ?",
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
        Attempt to write a current snapshot to data/seed_state.json or /tmp/seed_state.json.
        Does not overwrite repo seed file during pytest runs.
        """
        if os.environ.get("PYTEST_CURRENT_TEST"):
            return False

        data = self.export_backup()
        target_path = os.path.join(self.config.BASE_DIR, "data", "seed_state.json")
        try:
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            with open(target_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            return True
        except Exception:
            # If filesystem is read-only (like /var/task on Vercel)
            pass

        # Try /tmp as secondary snapshot location
        tmp_path = os.path.join("/tmp", "seed_state.json")
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            return True
        except Exception:
            return False
