"""
Unit and integration tests for Serverless Persistence, SUBADMIN_USERS seeding, and Backup/Restore.
"""

import pytest
from app import app, db


@pytest.fixture
def test_client():
    """Create Flask test client with clean testing configuration."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def main_admin_session(test_client):
    """Log in as default main admin and return (client, csrf_token)."""
    db.seed_main_admin_if_empty("inexpert_trifler", "om sai 0987654321")
    res = test_client.post(
        "/admin/login",
        json={"username": "inexpert_trifler", "password": "om sai 0987654321"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    return test_client, data["csrf_token"]


class TestSubadminSeedingAndPersistence:
    """Test seeding subadmins from config and environment variables across container restarts."""

    def test_seed_subadmins_from_comma_separated_string(self):
        config_str = "seeded_sub1:secret_pass_1,seeded_sub2:secret_pass_2"
        seeded = db.seed_subadmins_from_config(config_str)
        assert "seeded_sub1" in seeded
        assert "seeded_sub2" in seeded

        # Verify users exist in database
        u1 = db.get_user_by_username("seeded_sub1")
        assert u1 is not None
        assert u1["role"] == "subadmin"
        assert u1["is_active"] == 1

        u2 = db.get_user_by_username("seeded_sub2")
        assert u2 is not None
        assert u2["role"] == "subadmin"

    def test_seed_subadmins_from_json_string(self):
        json_str = '[{"username": "json_subadmin", "password": "json_password_123"}]'
        seeded = db.seed_subadmins_from_config(json_str)
        assert "json_subadmin" in seeded

        u = db.get_user_by_username("json_subadmin")
        assert u is not None
        assert u["role"] == "subadmin"

    def test_export_and_import_backup(self, main_admin_session, test_client):
        client, csrf = main_admin_session

        # 1. Create a subadmin
        client.post(
            "/admin/api/subadmins",
            headers={"X-CSRF-Token": csrf},
            json={"username": "backup_user_alpha", "password": "backup_password_1"},
        )

        # 2. Export backup via API
        export_res = client.get("/admin/api/backup/export")
        assert export_res.status_code == 200
        backup_data = export_res.get_json()["backup"]
        assert "subadmins" in backup_data
        usernames = [s["username"] for s in backup_data["subadmins"]]
        assert "backup_user_alpha" in usernames

        # 3. Simulate a fresh container wipe: delete the subadmin from DB
        user = db.get_user_by_username("backup_user_alpha")
        db.delete_subadmin(user["id"])
        assert db.get_user_by_username("backup_user_alpha") is None

        # 4. Import backup to restore
        import_res = client.post(
            "/admin/api/backup/import",
            headers={"X-CSRF-Token": csrf},
            json={"backup": backup_data},
        )
        assert import_res.status_code == 200
        assert import_res.get_json()["success"] is True

        # 5. Verify subadmin was restored and can log in
        login_res = test_client.post(
            "/admin/login",
            json={"username": "backup_user_alpha", "password": "backup_password_1"},
        )
        assert login_res.status_code == 200
        assert login_res.get_json()["success"] is True

    def test_subadmin_cannot_access_backup_endpoints(self, main_admin_session, test_client):
        client, csrf = main_admin_session
        # Create subadmin
        client.post(
            "/admin/api/subadmins",
            headers={"X-CSRF-Token": csrf},
            json={"username": "regular_sub", "password": "regular_password_123"},
        )

        # Log in as subadmin
        sub_login = test_client.post(
            "/admin/login",
            json={"username": "regular_sub", "password": "regular_password_123"},
        )
        sub_csrf = sub_login.get_json()["csrf_token"]

        # Subadmin denied access to export backup -> 403 Forbidden
        export_res = test_client.get("/admin/api/backup/export")
        assert export_res.status_code == 403

        # Subadmin denied access to import backup -> 403 Forbidden
        import_res = test_client.post(
            "/admin/api/backup/import",
            headers={"X-CSRF-Token": sub_csrf},
            json={"backup": {}},
        )
        assert import_res.status_code == 403

    def test_get_persistence_info_main_admin(self, main_admin_session):
        client, _ = main_admin_session
        res = client.get("/admin/api/persistence-info")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert "is_vercel" in data
        assert "subadmins_count" in data
        assert "database_path" in data

    def test_subadmin_account_preserved_when_adding_and_deleting_api(self, main_admin_session, test_client):
        client, csrf = main_admin_session
        # 1. Main admin creates subadmin
        client.post(
            "/admin/api/subadmins",
            headers={"X-CSRF-Token": csrf},
            json={"username": "api_creator_sub", "password": "sub_pass_strong_123"},
        )
        user = db.get_user_by_username("api_creator_sub")
        assert user is not None
        user_id = user["id"]

        # 2. Subadmin logs in
        login_res = test_client.post(
            "/admin/login",
            json={"username": "api_creator_sub", "password": "sub_pass_strong_123"},
        )
        assert login_res.status_code == 200
        sub_csrf = login_res.get_json()["csrf_token"]

        # 3. Subadmin adds an API configuration
        add_res = test_client.post(
            "/admin/api/configs",
            headers={"X-CSRF-Token": sub_csrf},
            json={
                "display_name": "API Added By Subadmin",
                "provider_name": "md5decrypt",
                "endpoint": "https://api.md5decrypt.net/",
                "credential": "test_cred_token_999",
                "priority": 10,
            },
        )
        assert add_res.status_code == 201
        cfg_id = add_res.get_json()["id"]

        # 4. Verify subadmin account was NOT touched or deleted
        user_after_add = db.get_user_by_username("api_creator_sub")
        assert user_after_add is not None
        assert user_after_add["id"] == user_id
        assert user_after_add["is_active"] == 1
        assert user_after_add["role"] == "subadmin"

        # 5. Subadmin deletes the API configuration
        del_res = test_client.delete(
            f"/admin/api/configs/{cfg_id}",
            headers={"X-CSRF-Token": sub_csrf},
        )
        assert del_res.status_code == 200

        # 6. Verify subadmin account is STILL intact
        user_after_del = db.get_user_by_username("api_creator_sub")
        assert user_after_del is not None
        assert user_after_del["id"] == user_id
        assert user_after_del["is_active"] == 1

    def test_database_path_normalized_to_absolute(self):
        import os
        from database import Database
        from config import Config
        cfg = Config()
        d = Database(db_path="relative_test.db", config=cfg)
        assert os.path.isabs(d.db_path)
        assert d.db_path.endswith("relative_test.db")
        if os.path.exists(d.db_path):
            os.remove(d.db_path)

    def test_in_memory_prohibited_in_production(self, monkeypatch):
        import pytest
        from database import Database
        from config import Config
        cfg = Config()
        monkeypatch.setenv("FLASK_ENV", "production")
        monkeypatch.delenv("TESTING", raising=False)
        # Verify prohibited check
        with pytest.raises(ValueError, match="strictly prohibited"):
            Database(db_path=":memory:", config=cfg, force_production_check=True)

    def test_parse_pg_url(self):
        from database import parse_pg_url
        neon_url = "postgresql://user_test:pass_secret@ep-cool-frost-123456-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require"
        params = parse_pg_url(neon_url)
        assert params["user"] == "user_test"
        assert params["password"] == "pass_secret"
        assert params["host"] == "ep-cool-frost-123456-pooler.us-east-2.aws.neon.tech"
        assert params["database"] == "neondb"
        assert params["ssl_context"] is True

    def test_missing_database_url_on_vercel_raises_error(self, monkeypatch):
        import pytest
        from database import Database
        from config import Config
        cfg = Config()
        monkeypatch.setenv("VERCEL", "1")
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.delenv("DATABASE_POSTGRES_URL", raising=False)
        monkeypatch.delenv("POSTGRES_URL", raising=False)
        with pytest.raises(RuntimeError, match="CRITICAL CONFIGURATION ERROR: Neon PostgreSQL DATABASE_URL is missing"):
            Database(config=cfg)

    def test_postgres_connection_wrapper(self):
        from database import PostgresConnection, PostgresCursor, RowDict

        class MockCursor:
            def __init__(self):
                self.description = [("id",), ("username",), ("role",)]
                self.executed_sql = None
                self.executed_params = None
                self.rowcount = 1

            def execute(self, sql, params=()):
                self.executed_sql = sql
                self.executed_params = params

            def fetchone(self):
                return (42, "admin_mock", "main_admin")

            def fetchall(self):
                return [(42, "admin_mock", "main_admin")]

        class MockRawConn:
            def __init__(self):
                self.cur = MockCursor()
                self.committed = False
                self.rolled_back = False

            def cursor(self):
                return self.cur

            def commit(self):
                self.committed = True

            def rollback(self):
                self.rolled_back = True

            def close(self):
                pass

        raw = MockRawConn()
        pg_conn = PostgresConnection(raw)

        # Test execute translating '?' to '%s' and auto appending RETURNING id
        cur = pg_conn.execute("INSERT INTO admin_users (username) VALUES (?)", ("test_sub",))
        assert "%s" in raw.cur.executed_sql
        assert "RETURNING id" in raw.cur.executed_sql
        assert cur.lastrowid == 42
        assert cur.rowcount == 1

        # Test fetchone returns RowDict
        row = cur.fetchone()
        assert isinstance(row, RowDict)
        assert row["username"] == "admin_mock"
        assert row[0] == 42
        assert dict(row) == {"id": 42, "username": "admin_mock", "role": "main_admin"}

        # Test fetchall returns list of RowDict
        rows = cur.fetchall()
        assert len(rows) == 1
        assert rows[0]["role"] == "main_admin"

        pg_conn.commit()
        assert raw.committed is True

    def test_database_transaction_rollback(self):
        # Verify transaction rollback on exception
        initial_configs_count = len(db.get_all_configs())
        try:
            with db.get_connection() as conn:
                conn.execute(
                    "INSERT INTO api_configurations (provider_name, display_name, endpoint, encrypted_credential, priority, enabled, created_at, updated_at) "
                    "VALUES ('fail', 'Will Rollback', 'http://example.com', 'cred', 10, 1, 'now', 'now')"
                )
                raise RuntimeError("Simulated failure in transaction")
        except RuntimeError:
            pass

        # Verify that uncommitted insert was rolled back
        assert len(db.get_all_configs()) == initial_configs_count
