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
