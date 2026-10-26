"""
Unit and integration tests for External Client API Keys and /api/v1/lookup Endpoint.
"""

import pytest
from app import app, db


@pytest.fixture(autouse=True)
def clean_client_keys():
    """Ensure clean state for client keys before and after each test."""
    with db.get_connection() as conn:
        conn.execute("DELETE FROM client_api_keys")
        conn.commit()
    yield
    with db.get_connection() as conn:
        conn.execute("DELETE FROM client_api_keys")
        conn.commit()


@pytest.fixture
def test_client():
    """Create Flask test client with clean testing configuration."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def main_admin_session(test_client):
    """Log in as the default main admin and return (client, csrf_token)."""
    db.seed_main_admin_if_empty("inexpert_trifler", "om sai 0987654321")
    res = test_client.post(
        "/admin/login",
        json={"username": "inexpert_trifler", "password": "om sai 0987654321"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    return test_client, data["csrf_token"]


class TestClientApiKeyManagement:
    """Test generating, listing, toggling, and deleting external client API keys."""

    def test_main_admin_can_create_client_api_key(self, main_admin_session):
        client, csrf = main_admin_session
        res = client.post(
            "/admin/api/client-keys",
            headers={"X-CSRF-Token": csrf},
            json={"name": "University Mobile App", "rate_limit_per_minute": 100},
        )
        assert res.status_code == 201
        data = res.get_json()
        assert data["success"] is True
        assert "key" in data
        assert data["key"]["name"] == "University Mobile App"
        assert data["key"]["api_key"].startswith("scp_live_")
        assert data["key"]["rate_limit_per_minute"] == 100

    def test_subadmin_cannot_create_client_api_key(self, main_admin_session, test_client):
        client, csrf = main_admin_session
        # Create a subadmin
        client.post(
            "/admin/api/subadmins",
            headers={"X-CSRF-Token": csrf},
            json={"username": "sub_worker", "password": "sub_password_123"},
        )

        # Log in as subadmin
        sub_login = test_client.post(
            "/admin/login",
            json={"username": "sub_worker", "password": "sub_password_123"},
        )
        sub_csrf = sub_login.get_json()["csrf_token"]

        # Subadmin attempts to create API key -> 403 Forbidden
        res = test_client.post(
            "/admin/api/client-keys",
            headers={"X-CSRF-Token": sub_csrf},
            json={"name": "Illegal App Key"},
        )
        assert res.status_code == 403
        data = res.get_json()
        assert data["success"] is False
        assert "privileges required" in data["error"].lower()

    def test_main_admin_can_list_and_toggle_api_keys(self, main_admin_session):
        client, csrf = main_admin_session
        # Create key
        create_res = client.post(
            "/admin/api/client-keys",
            headers={"X-CSRF-Token": csrf},
            json={"name": "Testing Toggle App"},
        )
        key_id = create_res.get_json()["key"]["id"]

        # List keys
        list_res = client.get("/admin/api/client-keys")
        assert list_res.status_code == 200
        keys = list_res.get_json()["keys"]
        assert len(keys) == 1
        assert keys[0]["name"] == "Testing Toggle App"
        assert keys[0]["is_active"] == 1

        # Toggle (revoke) key
        toggle_res = client.post(
            f"/admin/api/client-keys/{key_id}/toggle",
            headers={"X-CSRF-Token": csrf},
        )
        assert toggle_res.status_code == 200
        assert toggle_res.get_json()["is_active"] is False

        # Toggle back to active
        toggle_res2 = client.post(
            f"/admin/api/client-keys/{key_id}/toggle",
            headers={"X-CSRF-Token": csrf},
        )
        assert toggle_res2.status_code == 200
        assert toggle_res2.get_json()["is_active"] is True

    def test_main_admin_can_delete_api_key(self, main_admin_session):
        client, csrf = main_admin_session
        create_res = client.post(
            "/admin/api/client-keys",
            headers={"X-CSRF-Token": csrf},
            json={"name": "To Delete App"},
        )
        key_id = create_res.get_json()["key"]["id"]

        del_res = client.delete(
            f"/admin/api/client-keys/{key_id}",
            headers={"X-CSRF-Token": csrf},
        )
        assert del_res.status_code == 200

        # List is empty
        list_res = client.get("/admin/api/client-keys")
        assert len(list_res.get_json()["keys"]) == 0


class TestExternalApiConsumption:
    """Test consuming /api/v1/lookup using generated client API keys."""

    def test_missing_api_key_returns_401(self, test_client):
        res = test_client.post(
            "/api/v1/lookup",
            json={"lookup_input": "098f6bcd4621d373cade4e832627b4f6", "algorithm_type": "md5"},
        )
        assert res.status_code == 401
        data = res.get_json()
        assert data["success"] is False
        assert "authentication required" in data["error"].lower()

    def test_invalid_api_key_returns_403(self, test_client):
        res = test_client.post(
            "/api/v1/lookup",
            headers={"X-API-Key": "scp_live_invalid_nonexistent_key_12345"},
            json={"lookup_input": "098f6bcd4621d373cade4e832627b4f6", "algorithm_type": "md5"},
        )
        assert res.status_code == 403
        data = res.get_json()
        assert data["success"] is False
        assert "invalid or revoked" in data["error"].lower()

    def test_revoked_api_key_returns_403(self, main_admin_session, test_client):
        client, csrf = main_admin_session
        create_res = client.post(
            "/admin/api/client-keys",
            headers={"X-CSRF-Token": csrf},
            json={"name": "Will Revoke App"},
        )
        key_obj = create_res.get_json()["key"]
        api_key = key_obj["api_key"]
        key_id = key_obj["id"]

        # Revoke the key
        client.post(
            f"/admin/api/client-keys/{key_id}/toggle",
            headers={"X-CSRF-Token": csrf},
        )

        # Call API with revoked key
        res = test_client.post(
            "/api/v1/lookup",
            headers={"X-API-Key": api_key},
            json={"lookup_input": "098f6bcd4621d373cade4e832627b4f6", "algorithm_type": "md5"},
        )
        assert res.status_code == 403
        assert "revoked" in res.get_json()["error"].lower()

    def test_valid_api_key_via_header_succeeds_and_increments_usage(
        self, main_admin_session, test_client
    ):
        client, csrf = main_admin_session
        create_res = client.post(
            "/admin/api/client-keys",
            headers={"X-CSRF-Token": csrf},
            json={"name": "Valid Client App"},
        )
        api_key = create_res.get_json()["key"]["api_key"]

        # Make lookup request using X-API-Key
        res = test_client.post(
            "/api/v1/lookup",
            headers={"X-API-Key": api_key},
            json={"lookup_input": "098f6bcd4621d373cade4e832627b4f6", "algorithm_type": "md5"},
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["status"] == "match_found"
        assert data["lookup_result"] == "test"

        # Verify usage count incremented in database
        key_record = db.get_client_api_key(api_key)
        assert key_record["requests_count"] == 1
        assert key_record["last_used_at"] is not None

    def test_valid_api_key_via_bearer_token_succeeds(
        self, main_admin_session, test_client
    ):
        client, csrf = main_admin_session
        create_res = client.post(
            "/admin/api/client-keys",
            headers={"X-CSRF-Token": csrf},
            json={"name": "Bearer Client App"},
        )
        api_key = create_res.get_json()["key"]["api_key"]

        # Make lookup request using Authorization: Bearer <key>
        res = test_client.post(
            "/api/v1/lookup",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"lookup_input": "098f6bcd4621d373cade4e832627b4f6", "algorithm_type": "md5"},
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["status"] == "match_found"

        # Verify usage count
        key_record = db.get_client_api_key(api_key)
        assert key_record["requests_count"] == 1
