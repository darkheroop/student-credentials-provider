"""
Tests for administrative API management, authentication, CSRF, and SSRF defenses.
"""

import json
import pytest

from app import app, db, crypto


@pytest.fixture
def admin_client():
    """Create Flask test client with clean testing configuration."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def auth_session(admin_client):
    """Authenticate administrator session and return client with CSRF token."""
    res = admin_client.post(
        "/admin/login",
        json={"username": "admin", "password": "admin123"},
    )
    assert res.status_code == 200
    data = res.get_json()
    csrf_token = data["csrf_token"]
    return admin_client, csrf_token


class TestAdminSecurity:
    def test_unauthenticated_user_cannot_access_configs(self, admin_client):
        # JSON API request
        res = admin_client.get("/admin/api/configs")
        assert res.status_code == 401
        data = res.get_json()
        assert data["success"] is False

        # HTML page request
        res_page = admin_client.get("/admin/")
        assert res_page.status_code == 302
        assert "/admin/login" in res_page.headers["Location"]

    def test_invalid_login_rejected(self, admin_client):
        res = admin_client.post(
            "/admin/login",
            json={"username": "admin", "password": "wrong_password"},
        )
        assert res.status_code == 401

    def test_successful_login(self, admin_client):
        res = admin_client.post(
            "/admin/login",
            json={"username": "admin", "password": "admin123"},
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert "csrf_token" in data

    def test_csrf_protection_enforced(self, auth_session):
        client, _ = auth_session
        # Sending request WITHOUT CSRF token must fail with 403
        res = client.post(
            "/admin/api/configs",
            json={
                "display_name": "Test Without CSRF",
                "endpoint": "https://api.md5decrypt.net/",
                "credential": "key",
            },
        )
        assert res.status_code == 403

    def test_ssrf_blocked_metadata_endpoint(self, auth_session):
        client, csrf_token = auth_session
        res = client.post(
            "/admin/api/configs",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "display_name": "SSRF Attempt",
                "endpoint": "http://169.254.169.254/latest/meta-data/",
                "credential": "key",
            },
        )
        assert res.status_code == 400
        assert "restricted" in res.get_json()["error"].lower()


class TestAdminCrud:
    def test_add_and_list_api_config(self, auth_session):
        client, csrf_token = auth_session
        raw_key = "md5d_live_my_super_secret_key_12345"

        # 1. Add configuration
        add_res = client.post(
            "/admin/api/configs",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "display_name": "Admin Test API",
                "provider_name": "md5decrypt",
                "endpoint": "https://api.md5decrypt.net/",
                "credential": raw_key,
                "priority": 15,
                "notes": "Added in unit test",
            },
        )
        assert add_res.status_code == 201
        cfg_id = add_res.get_json()["id"]

        # 2. Check Database directly: verify key is ENCRYPTED at rest
        row = db.get_config_by_id(cfg_id)
        assert row is not None
        assert row["encrypted_credential"].startswith("enc:v1:")
        assert raw_key not in row["encrypted_credential"]

        # 3. Check List API response: verify key is MASKED, never exposed
        list_res = client.get("/admin/api/configs")
        assert list_res.status_code == 200
        configs = list_res.get_json()["configs"]
        matched = next((c for c in configs if c["id"] == cfg_id), None)
        assert matched is not None
        assert matched["masked_credential"] == "********2345"
        assert raw_key not in json.dumps(list_res.get_json())

    def test_update_config_preserving_credential(self, auth_session):
        client, csrf_token = auth_session
        original_key = "md5d_live_original_key_9999"

        # Add initial config
        add_res = client.post(
            "/admin/api/configs",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "display_name": "Before Update",
                "endpoint": "https://api.md5decrypt.net/",
                "credential": original_key,
                "priority": 10,
            },
        )
        cfg_id = add_res.get_json()["id"]

        # Update without providing 'credential'
        update_res = client.put(
            f"/admin/api/configs/{cfg_id}",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "display_name": "After Update Name",
                "priority": 5,
            },
        )
        assert update_res.status_code == 200

        # Verify key was preserved and name updated
        row = db.get_config_by_id(cfg_id)
        assert row["display_name"] == "After Update Name"
        assert row["priority"] == 5
        assert crypto.decrypt(row["encrypted_credential"]) == original_key

    def test_toggle_and_reactivate_config(self, auth_session):
        client, csrf_token = auth_session

        add_res = client.post(
            "/admin/api/configs",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "display_name": "Toggle API",
                "endpoint": "https://api.md5decrypt.net/",
                "credential": "key",
                "priority": 10,
            },
        )
        cfg_id = add_res.get_json()["id"]

        # Toggle to disabled
        toggle_res = client.post(
            f"/admin/api/configs/{cfg_id}/toggle",
            headers={"X-CSRF-Token": csrf_token},
        )
        assert toggle_res.status_code == 200
        assert toggle_res.get_json()["enabled"] is False

        # Mark as paused
        db.set_health_status(cfg_id, "quota_exhausted", paused_until="2099-01-01T00:00:00Z")
        assert db.get_config_by_id(cfg_id)["health_status"] == "quota_exhausted"

        # Reactivate
        reactivate_res = client.post(
            f"/admin/api/configs/{cfg_id}/reactivate",
            headers={"X-CSRF-Token": csrf_token},
        )
        assert reactivate_res.status_code == 200
        assert db.get_config_by_id(cfg_id)["health_status"] == "active"
        assert db.get_config_by_id(cfg_id)["paused_until"] is None

    def test_delete_config(self, auth_session):
        client, csrf_token = auth_session

        add_res = client.post(
            "/admin/api/configs",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "display_name": "Delete API",
                "endpoint": "https://api.md5decrypt.net/",
                "credential": "key",
            },
        )
        cfg_id = add_res.get_json()["id"]

        del_res = client.delete(
            f"/admin/api/configs/{cfg_id}",
            headers={"X-CSRF-Token": csrf_token},
        )
        assert del_res.status_code == 200
        assert db.get_config_by_id(cfg_id) is None
