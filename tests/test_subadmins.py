"""
Unit and integration tests for Subadmin Management and Post-Login Credential Updates.
"""

import pytest
from app import app, db


@pytest.fixture(autouse=True)
def clean_subadmins():
    """Ensure a clean subadmin table state before and after each test."""
    db.seed_main_admin_if_empty("inexpert_trifler", "om sai 0987654321")
    with db.get_connection() as conn:
        conn.execute("DELETE FROM admin_users WHERE role != 'main_admin'")
        conn.commit()
    yield
    with db.get_connection() as conn:
        conn.execute("DELETE FROM admin_users WHERE role != 'main_admin'")
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
    res = test_client.post(
        "/admin/login",
        json={"username": "inexpert_trifler", "password": "om sai 0987654321"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["user"]["role"] == "main_admin"
    return test_client, data["csrf_token"]


class TestSubadminManagement:
    """Test creating, listing, toggling, resetting password, and deleting subadmins."""

    def test_main_admin_can_create_subadmin(self, main_admin_session):
        client, csrf = main_admin_session
        res = client.post(
            "/admin/api/subadmins",
            headers={"X-CSRF-Token": csrf},
            json={"username": "test_subadmin_1", "password": "subadmin_secret_123"},
        )
        assert res.status_code == 201
        data = res.get_json()
        assert data["success"] is True
        assert "id" in data

    def test_duplicate_subadmin_username_rejected(self, main_admin_session):
        client, csrf = main_admin_session
        # Create first
        client.post(
            "/admin/api/subadmins",
            headers={"X-CSRF-Token": csrf},
            json={"username": "unique_subadmin", "password": "password123"},
        )
        # Attempt duplicate
        res = client.post(
            "/admin/api/subadmins",
            headers={"X-CSRF-Token": csrf},
            json={"username": "unique_subadmin", "password": "newpassword123"},
        )
        assert res.status_code == 400
        data = res.get_json()
        assert data["success"] is False
        assert "already taken" in data["error"]

    def test_main_admin_can_list_subadmins(self, main_admin_session):
        client, csrf = main_admin_session
        client.post(
            "/admin/api/subadmins",
            headers={"X-CSRF-Token": csrf},
            json={"username": "listed_subadmin", "password": "password123"},
        )
        res = client.get("/admin/api/subadmins")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        usernames = [s["username"] for s in data["subadmins"]]
        assert "listed_subadmin" in usernames

    def test_subadmin_can_log_in_and_access_apis(self, main_admin_session, test_client):
        client, csrf = main_admin_session
        # 1. Main admin creates subadmin
        client.post(
            "/admin/api/subadmins",
            headers={"X-CSRF-Token": csrf},
            json={"username": "worker_admin", "password": "work_password_999"},
        )

        # 2. Subadmin logs in
        login_res = test_client.post(
            "/admin/login",
            json={"username": "worker_admin", "password": "work_password_999"},
        )
        assert login_res.status_code == 200
        sub_data = login_res.get_json()
        assert sub_data["user"]["role"] == "subadmin"
        sub_csrf = sub_data["csrf_token"]

        # 3. Subadmin can view API configs
        configs_res = test_client.get("/admin/api/configs")
        assert configs_res.status_code == 200

        # 4. Subadmin CANNOT access subadmin management (forbidden 403)
        subadmins_res = test_client.get("/admin/api/subadmins")
        assert subadmins_res.status_code == 403
        data = subadmins_res.get_json()
        assert data["success"] is False

    def test_main_admin_can_disable_and_enable_subadmin(self, main_admin_session, test_client):
        client, csrf = main_admin_session
        # Create subadmin
        res = client.post(
            "/admin/api/subadmins",
            headers={"X-CSRF-Token": csrf},
            json={"username": "toggle_user", "password": "toggle_pass_123"},
        )
        sub_id = res.get_json()["id"]

        # Disable subadmin
        toggle_res = client.post(
            f"/admin/api/subadmins/{sub_id}/toggle",
            headers={"X-CSRF-Token": csrf},
        )
        assert toggle_res.status_code == 200
        assert toggle_res.get_json()["is_active"] is False

        # Attempt to log in with disabled subadmin
        login_res = test_client.post(
            "/admin/login",
            json={"username": "toggle_user", "password": "toggle_pass_123"},
        )
        assert login_res.status_code == 403
        assert "disabled" in login_res.get_json()["error"]

        # Re-enable subadmin
        client.post(
            f"/admin/api/subadmins/{sub_id}/toggle",
            headers={"X-CSRF-Token": csrf},
        )
        # Login now succeeds
        login_ok = test_client.post(
            "/admin/login",
            json={"username": "toggle_user", "password": "toggle_pass_123"},
        )
        assert login_ok.status_code == 200

    def test_main_admin_cannot_be_disabled_or_deleted(self, main_admin_session):
        client, csrf = main_admin_session
        main_user = db.get_user_by_username("inexpert_trifler")
        assert main_user is not None
        main_id = main_user["id"]

        # Attempt to disable main admin
        toggle_res = client.post(
            f"/admin/api/subadmins/{main_id}/toggle",
            headers={"X-CSRF-Token": csrf},
        )
        assert toggle_res.status_code == 403

        # Attempt to delete main admin
        delete_res = client.delete(
            f"/admin/api/subadmins/{main_id}",
            headers={"X-CSRF-Token": csrf},
        )
        assert delete_res.status_code == 403

    def test_main_admin_can_reset_subadmin_password(self, main_admin_session, test_client):
        client, csrf = main_admin_session
        # Create subadmin
        res = client.post(
            "/admin/api/subadmins",
            headers={"X-CSRF-Token": csrf},
            json={"username": "reset_user", "password": "initial_password_1"},
        )
        sub_id = res.get_json()["id"]

        # Reset password
        reset_res = client.post(
            f"/admin/api/subadmins/{sub_id}/reset-password",
            headers={"X-CSRF-Token": csrf},
            json={"new_password": "brand_new_secret_777"},
        )
        assert reset_res.status_code == 200

        # Old password fails
        bad_login = test_client.post(
            "/admin/login",
            json={"username": "reset_user", "password": "initial_password_1"},
        )
        assert bad_login.status_code == 401

        # New password succeeds
        good_login = test_client.post(
            "/admin/login",
            json={"username": "reset_user", "password": "brand_new_secret_777"},
        )
        assert good_login.status_code == 200

    def test_main_admin_can_delete_subadmin(self, main_admin_session, test_client):
        client, csrf = main_admin_session
        res = client.post(
            "/admin/api/subadmins",
            headers={"X-CSRF-Token": csrf},
            json={"username": "to_be_deleted", "password": "password_del_123"},
        )
        sub_id = res.get_json()["id"]

        del_res = client.delete(
            f"/admin/api/subadmins/{sub_id}",
            headers={"X-CSRF-Token": csrf},
        )
        assert del_res.status_code == 200

        # Logging in fails
        login_res = test_client.post(
            "/admin/login",
            json={"username": "to_be_deleted", "password": "password_del_123"},
        )
        assert login_res.status_code == 401


class TestAccountCredentialsUpdate:
    """Test updating username and password only after authentication."""

    def test_unauthenticated_cannot_update_credentials(self, test_client):
        res = test_client.post(
            "/admin/api/account/update",
            json={"current_password": "any", "new_username": "hacker"},
        )
        assert res.status_code == 401

    def test_update_requires_correct_current_password(self, main_admin_session):
        client, csrf = main_admin_session
        res = client.post(
            "/admin/api/account/update",
            headers={"X-CSRF-Token": csrf},
            json={
                "current_password": "wrong_current_password",
                "new_username": "new_name",
            },
        )
        assert res.status_code == 400
        assert "Incorrect current password" in res.get_json()["error"]

    def test_user_can_update_password_after_login(self, main_admin_session, test_client):
        client, csrf = main_admin_session
        # Create a user to test password update
        client.post(
            "/admin/api/subadmins",
            headers={"X-CSRF-Token": csrf},
            json={"username": "password_updater", "password": "first_password_1"},
        )

        # Login as the user
        login_res = test_client.post(
            "/admin/login",
            json={"username": "password_updater", "password": "first_password_1"},
        )
        user_csrf = login_res.get_json()["csrf_token"]

        # Update password
        update_res = test_client.post(
            "/admin/api/account/update",
            headers={"X-CSRF-Token": user_csrf},
            json={
                "current_password": "first_password_1",
                "new_password": "second_password_2",
            },
        )
        assert update_res.status_code == 200
        assert update_res.get_json()["success"] is True

        # Log in with updated password
        new_login = app.test_client().post(
            "/admin/login",
            json={"username": "password_updater", "password": "second_password_2"},
        )
        assert new_login.status_code == 200

    def test_user_can_update_username_after_login(self, main_admin_session, test_client):
        client, csrf = main_admin_session
        client.post(
            "/admin/api/subadmins",
            headers={"X-CSRF-Token": csrf},
            json={"username": "old_handle", "password": "my_secure_pass_123"},
        )

        # Login as the user
        login_res = test_client.post(
            "/admin/login",
            json={"username": "old_handle", "password": "my_secure_pass_123"},
        )
        user_csrf = login_res.get_json()["csrf_token"]

        # Update username
        update_res = test_client.post(
            "/admin/api/account/update",
            headers={"X-CSRF-Token": user_csrf},
            json={
                "current_password": "my_secure_pass_123",
                "new_username": "new_shiny_handle",
            },
        )
        assert update_res.status_code == 200
        data = update_res.get_json()
        assert data["username"] == "new_shiny_handle"

        # Old handle fails
        old_login = app.test_client().post(
            "/admin/login",
            json={"username": "old_handle", "password": "my_secure_pass_123"},
        )
        assert old_login.status_code == 401

        # New handle succeeds
        new_login = app.test_client().post(
            "/admin/login",
            json={"username": "new_shiny_handle", "password": "my_secure_pass_123"},
        )
        assert new_login.status_code == 200
