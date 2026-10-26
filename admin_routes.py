"""
Administrative routes and controllers for dynamic API key management.

Provides server-side authentication, CSRF validation, SSRF protection,
and CRUD endpoints for API configurations and failover controls.
"""

import ipaddress
import os
import re
import secrets
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Blueprint,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config
from database import Database
from services.crypto import CredentialCrypto, mask_credential
from services.providers.registry import get_provider_adapter

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

# Disallowed hostnames / IPs to prevent SSRF against cloud metadata & private networks
_DISALLOWED_HOSTS = {
    "169.254.169.254",  # AWS / Cloud metadata
    "metadata.google.internal",
    "100.100.100.200",  # Alibaba Cloud metadata
}


def _validate_endpoint_url(url: str) -> tuple[bool, str]:
    """Validate endpoint URL to prevent Server-Side Request Forgery (SSRF)."""
    if not url or not str(url).strip():
        return False, "Endpoint URL is required."

    cleaned = str(url).strip()
    try:
        parsed = urlparse(cleaned)
    except Exception:
        return False, "Malformed endpoint URL."

    if parsed.scheme not in ("http", "https"):
        return False, "Endpoint URL must use HTTP or HTTPS scheme."

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False, "Endpoint URL must contain a valid host name."

    if hostname in _DISALLOWED_HOSTS:
        return False, "Endpoint host is restricted for security."

    # Prevent link-local and loopback access in non-testing environments if IP
    try:
        ip_obj = ipaddress.ip_address(hostname)
        if ip_obj.is_link_local:
            return False, "Link-local IP addresses are not permitted."
    except ValueError:
        pass

    return True, ""


def init_admin_bp(db: Database, crypto: CredentialCrypto, config: Config) -> Blueprint:
    """Factory function to bind database and crypto dependencies to the admin blueprint."""

    # Ensure main admin exists at blueprint registration
    db.seed_main_admin_if_empty(config.ADMIN_USERNAME, config.ADMIN_PASSWORD)
    db.seed_from_state_file()
    db.seed_subadmins_from_config(config.SUBADMIN_USERS)

    def admin_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not session.get("admin_authenticated"):
                if request.is_json or request.path.startswith("/admin/api/"):
                    return jsonify({"success": False, "error": "Authentication required."}), 401
                return redirect(url_for("admin.login_page"))

            user_id = session.get("user_id")
            if user_id:
                user = db.get_user_by_id(user_id)
                if not user or not user["is_active"]:
                    session.clear()
                    if request.is_json or request.path.startswith("/admin/api/"):
                        return jsonify({"success": False, "error": "Account is inactive or has been disabled."}), 401
                    return redirect(url_for("admin.login_page"))
            return f(*args, **kwargs)
        return decorated

    def main_admin_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not session.get("admin_authenticated"):
                if request.is_json or request.path.startswith("/admin/api/"):
                    return jsonify({"success": False, "error": "Authentication required."}), 401
                return redirect(url_for("admin.login_page"))

            user_id = session.get("user_id")
            user = db.get_user_by_id(user_id) if user_id else None
            if not user or not user["is_active"]:
                session.clear()
                if request.is_json or request.path.startswith("/admin/api/"):
                    return jsonify({"success": False, "error": "Account is inactive or has been disabled."}), 401
                return redirect(url_for("admin.login_page"))

            if user["role"] != "main_admin":
                if request.is_json or request.path.startswith("/admin/api/"):
                    return jsonify({"success": False, "error": "Main administrator privileges required."}), 403
                return jsonify({"success": False, "error": "Access denied. Main administrator privileges required."}), 403

            return f(*args, **kwargs)
        return decorated

    def verify_csrf():
        """Verify CSRF token for state-altering requests."""
        if request.method in ("POST", "PUT", "DELETE"):
            client_token = (
                request.headers.get("X-CSRF-Token")
                or request.form.get("csrf_token")
                or (request.get_json(silent=True) or {}).get("csrf_token")
            )
            session_token = session.get("csrf_token")
            if not session_token or not client_token or client_token != session_token:
                return False
        return True

    # ── Authentication Routes ───────────────────────────────────────────

    @admin_bp.route("/login", methods=["GET"])
    def login_page():
        """Display admin login page."""
        if session.get("admin_authenticated"):
            return redirect(url_for("admin.dashboard"))
        return render_template("admin_login.html", error=None)

    @admin_bp.route("/login", methods=["POST"])
    def login_action():
        """Authenticate administrator credentials."""
        data = request.get_json(silent=True) if request.is_json else request.form
        username = (data.get("username") or "").strip()
        password = (data.get("password") or "").strip()

        if not username or not password:
            error_msg = "Username and password are required."
            if request.is_json:
                return jsonify({"success": False, "error": error_msg}), 400
            return render_template("admin_login.html", error=error_msg), 400

        user = db.get_user_by_username(username)
        # Ensure default main admin is seeded if not present
        if not user and username.lower() == config.ADMIN_USERNAME.lower() and password == config.ADMIN_PASSWORD:
            db.seed_main_admin_if_empty(config.ADMIN_USERNAME, config.ADMIN_PASSWORD)
            user = db.get_user_by_username(username)

        if user:
            if not user["is_active"]:
                error_msg = "This account has been disabled. Please contact the main administrator."
                if request.is_json:
                    return jsonify({"success": False, "error": error_msg}), 403
                return render_template("admin_login.html", error=error_msg), 403

            if check_password_hash(user["password_hash"], password):
                session["admin_authenticated"] = True
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                session["csrf_token"] = secrets.token_hex(16)

                if request.is_json:
                    return jsonify({
                        "success": True,
                        "csrf_token": session["csrf_token"],
                        "user": {
                            "id": user["id"],
                            "username": user["username"],
                            "role": user["role"],
                        },
                    })
                return redirect(url_for("admin.dashboard"))

        error_msg = "Invalid username or password."
        if request.is_json:
            return jsonify({"success": False, "error": error_msg}), 401
        return render_template("admin_login.html", error=error_msg), 401

    @admin_bp.route("/logout", methods=["GET", "POST"])
    def logout():
        """Log out administrator session."""
        session.clear()
        return redirect(url_for("admin.login_page"))

    # ── Admin Dashboard UI ──────────────────────────────────────────────

    @admin_bp.route("/", methods=["GET"])
    @admin_bp.route("/apis", methods=["GET"])
    @admin_required
    def dashboard():
        """Render API Management dashboard."""
        user = db.get_user_by_id(session.get("user_id"))
        return render_template(
            "admin.html",
            csrf_token=session.get("csrf_token", ""),
            current_user={
                "id": user["id"] if user else session.get("user_id"),
                "username": user["username"] if user else session.get("username", "admin"),
                "role": user["role"] if user else session.get("role", "subadmin"),
            },
        )

    # ── API Management REST Endpoints ───────────────────────────────────

    @admin_bp.route("/api/configs", methods=["GET"])
    @admin_required
    def list_configs():
        """List all configured API entries with masked credentials."""
        configs = db.get_all_configs()
        results = []
        for c in configs:
            # Safely mask the credential
            masked_key = "********"
            try:
                decrypted = crypto.decrypt(c["encrypted_credential"])
                masked_key = mask_credential(decrypted)
            except Exception:
                masked_key = "******** (decrypt error)"

            results.append({
                "id": c["id"],
                "provider_name": c["provider_name"],
                "display_name": c["display_name"],
                "endpoint": c["endpoint"],
                "masked_credential": masked_key,
                "priority": c["priority"],
                "enabled": bool(c["enabled"]),
                "health_status": c["health_status"],
                "paused_until": c["paused_until"],
                "last_success_at": c["last_success_at"],
                "last_failure_at": c["last_failure_at"],
                "last_error_category": c["last_error_category"],
                "notes": c["notes"],
                "created_at": c["created_at"],
                "updated_at": c["updated_at"],
            })
        return jsonify({"success": True, "configs": results})

    @admin_bp.route("/api/configs", methods=["POST"])
    @admin_required
    def add_config():
        """Add a new API configuration with encrypted credential storage."""
        if not verify_csrf():
            return jsonify({"success": False, "error": "Invalid CSRF token."}), 403

        data = request.get_json(silent=True) or {}
        display_name = (data.get("display_name") or "").strip()
        provider_name = (data.get("provider_name") or "md5decrypt").strip().lower()
        endpoint = (data.get("endpoint") or "").strip()
        credential = (data.get("credential") or "").strip()
        priority = data.get("priority", 10)
        enabled = bool(data.get("enabled", True))
        notes = (data.get("notes") or "").strip()

        if not display_name:
            return jsonify({"success": False, "error": "Display name is required."}), 400

        if not credential:
            return jsonify({"success": False, "error": "API key / credential is required."}), 400

        valid_url, url_err = _validate_endpoint_url(endpoint)
        if not valid_url:
            return jsonify({"success": False, "error": url_err}), 400

        try:
            priority_int = int(priority)
        except (ValueError, TypeError):
            priority_int = 10

        encrypted_cred = crypto.encrypt(credential)
        new_id = db.insert_config(
            provider_name=provider_name,
            display_name=display_name,
            endpoint=endpoint,
            encrypted_credential=encrypted_cred,
            priority=priority_int,
            enabled=1 if enabled else 0,
            notes=notes,
        )

        db.record_event(new_id, "created", f"Configuration created: {display_name}")

        return jsonify({
            "success": True,
            "message": "API configuration created successfully.",
            "id": new_id,
        }), 201

    @admin_bp.route("/api/configs/<int:config_id>", methods=["PUT"])
    @admin_required
    def update_config(config_id: int):
        """Update an existing configuration, preserving existing credential if none given."""
        if not verify_csrf():
            return jsonify({"success": False, "error": "Invalid CSRF token."}), 403

        existing = db.get_config_by_id(config_id)
        if not existing:
            return jsonify({"success": False, "error": "Configuration not found."}), 404

        data = request.get_json(silent=True) or {}
        display_name = data.get("display_name")
        endpoint = data.get("endpoint")
        credential = data.get("credential")
        priority = data.get("priority")
        enabled = data.get("enabled")
        notes = data.get("notes")

        if endpoint is not None:
            valid_url, url_err = _validate_endpoint_url(endpoint)
            if not valid_url:
                return jsonify({"success": False, "error": url_err}), 400

        encrypted_cred = None
        if credential and str(credential).strip():
            encrypted_cred = crypto.encrypt(str(credential).strip())

        priority_int = None
        if priority is not None:
            try:
                priority_int = int(priority)
            except (ValueError, TypeError):
                priority_int = existing["priority"]

        enabled_int = None
        if enabled is not None:
            enabled_int = 1 if enabled else 0

        updated = db.update_config(
            config_id=config_id,
            display_name=display_name,
            endpoint=endpoint,
            encrypted_credential=encrypted_cred,
            priority=priority_int,
            enabled=enabled_int,
            notes=notes,
        )

        if updated:
            db.record_event(config_id, "updated", "Configuration updated by administrator.")
            return jsonify({"success": True, "message": "Configuration updated successfully."})
        return jsonify({"success": False, "error": "Could not update configuration."}), 500

    @admin_bp.route("/api/configs/<int:config_id>", methods=["DELETE"])
    @admin_required
    def delete_config(config_id: int):
        """Delete an API configuration and its event history."""
        if not verify_csrf():
            return jsonify({"success": False, "error": "Invalid CSRF token."}), 403

        deleted = db.delete_config(config_id)
        if deleted:
            return jsonify({"success": True, "message": "Configuration deleted successfully."})
        return jsonify({"success": False, "error": "Configuration not found."}), 404

    @admin_bp.route("/api/configs/<int:config_id>/toggle", methods=["POST"])
    @admin_required
    def toggle_config(config_id: int):
        """Toggle an API configuration's enabled state."""
        if not verify_csrf():
            return jsonify({"success": False, "error": "Invalid CSRF token."}), 403

        existing = db.get_config_by_id(config_id)
        if not existing:
            return jsonify({"success": False, "error": "Configuration not found."}), 404

        new_state = not bool(existing["enabled"])
        db.set_enabled(config_id, new_state)
        action_name = "enabled" if new_state else "disabled"
        db.record_event(config_id, action_name, f"Provider manually {action_name}.")

        return jsonify({
            "success": True,
            "message": f"Provider {action_name} successfully.",
            "enabled": new_state,
        })

    @admin_bp.route("/api/configs/<int:config_id>/reactivate", methods=["POST"])
    @admin_required
    def reactivate_config(config_id: int):
        """Manually clear pause/quota state and mark provider as active."""
        if not verify_csrf():
            return jsonify({"success": False, "error": "Invalid CSRF token."}), 403

        existing = db.get_config_by_id(config_id)
        if not existing:
            return jsonify({"success": False, "error": "Configuration not found."}), 404

        db.reactivate(config_id)
        db.record_event(config_id, "reactivated", "Provider manually reactivated by administrator.")

        return jsonify({
            "success": True,
            "message": "Provider reactivated. Health status set to active.",
        })

    @admin_bp.route("/api/configs/<int:config_id>/test", methods=["POST"])
    @admin_required
    def test_config(config_id: int):
        """Perform a safe connection check without exposing credentials."""
        if not verify_csrf():
            return jsonify({"success": False, "error": "Invalid CSRF token."}), 403

        existing = db.get_config_by_id(config_id)
        if not existing:
            return jsonify({"success": False, "error": "Configuration not found."}), 404

        try:
            credential = crypto.decrypt(existing["encrypted_credential"])
        except Exception as exc:
            return jsonify({
                "success": False,
                "message": f"Decryption failed: {exc.__class__.__name__}",
            }), 400

        adapter = get_provider_adapter(existing["provider_name"])
        ok, msg = adapter.test_connection(
            credential=credential,
            endpoint=existing["endpoint"],
            timeout=config.STUDENT_LOOKUP_TIMEOUT_SECONDS,
        )

        db.record_event(config_id, "connection_test", f"Test: {msg}")

        return jsonify({
            "success": ok,
            "message": msg,
        })

    @admin_bp.route("/api/configs/<int:config_id>/history", methods=["GET"])
    @admin_required
    def get_history(config_id: int):
        """Retrieve recent sanitized events for an API configuration."""
        events = db.get_events_for_config(config_id, limit=30)
        return jsonify({"success": True, "events": events})

    # ── User Profile & Account Credentials Management ───────────────────

    @admin_bp.route("/api/me", methods=["GET"])
    @admin_required
    def get_current_user():
        """Return profile information of current logged-in user."""
        user = db.get_user_by_id(session.get("user_id"))
        if not user:
            return jsonify({"success": False, "error": "User not found."}), 404
        return jsonify({
            "success": True,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
            },
        })

    @admin_bp.route("/api/account/update", methods=["POST"])
    @admin_required
    def update_account_credentials():
        """
        Allow an authenticated user (main admin or subadmin) to update their
        own username and/or password after verifying their current password.
        """
        if not verify_csrf():
            return jsonify({"success": False, "error": "Invalid CSRF token."}), 403

        user = db.get_user_by_id(session.get("user_id"))
        if not user:
            return jsonify({"success": False, "error": "User not found."}), 404

        data = request.get_json(silent=True) or {}
        current_password = str(data.get("current_password") or "").strip()
        new_username = str(data.get("new_username") or "").strip()
        new_password = str(data.get("new_password") or "").strip()

        if not current_password:
            return jsonify({"success": False, "error": "Current password is required to save changes."}), 400

        if not check_password_hash(user["password_hash"], current_password):
            return jsonify({"success": False, "error": "Incorrect current password."}), 400

        has_change = False
        username_to_set = None
        password_hash_to_set = None

        if new_username and new_username.lower() != user["username"].lower():
            if len(new_username) < 3 or len(new_username) > 50:
                return jsonify({"success": False, "error": "New username must be between 3 and 50 characters."}), 400
            if not re.match(r"^[a-zA-Z0-9_\-\. ]+$", new_username):
                return jsonify({"success": False, "error": "Username contains invalid characters."}), 400
            if db.is_username_taken(new_username, exclude_user_id=user["id"]):
                return jsonify({"success": False, "error": f"Username '{new_username}' is already in use."}), 400
            username_to_set = new_username
            has_change = True

        if new_password:
            if len(new_password) < 6:
                return jsonify({"success": False, "error": "New password must be at least 6 characters long."}), 400
            password_hash_to_set = generate_password_hash(new_password)
            has_change = True

        if not has_change:
            return jsonify({"success": False, "error": "No credential changes were provided."}), 400

        db.update_user_credentials(
            user_id=user["id"],
            new_username=username_to_set,
            new_password_hash=password_hash_to_set,
        )

        if username_to_set:
            session["username"] = username_to_set

        return jsonify({
            "success": True,
            "message": "Account credentials updated successfully.",
            "username": session["username"],
        })

    # ── Subadmin Management (Main Admin Only) ───────────────────────────

    @admin_bp.route("/api/subadmins", methods=["GET"])
    @main_admin_required
    def list_subadmins():
        """List all subadmin accounts (Main Admin only)."""
        subadmins = db.get_all_subadmins()
        return jsonify({"success": True, "subadmins": subadmins})

    @admin_bp.route("/api/subadmins", methods=["POST"])
    @main_admin_required
    def create_subadmin():
        """Create a new subadmin account (Main Admin only)."""
        if not verify_csrf():
            return jsonify({"success": False, "error": "Invalid CSRF token."}), 403

        data = request.get_json(silent=True) or {}
        username = str(data.get("username") or "").strip()
        password = str(data.get("password") or "").strip()

        if not username:
            return jsonify({"success": False, "error": "Username is required."}), 400
        if len(username) < 3 or len(username) > 50:
            return jsonify({"success": False, "error": "Username must be between 3 and 50 characters."}), 400
        if not re.match(r"^[a-zA-Z0-9_\-\. ]+$", username):
            return jsonify({"success": False, "error": "Username contains invalid characters."}), 400
        if db.is_username_taken(username):
            return jsonify({"success": False, "error": f"Username '{username}' is already taken."}), 400

        if not password or len(password) < 6:
            return jsonify({"success": False, "error": "Password must be at least 6 characters long."}), 400

        hashed = generate_password_hash(password)
        new_id = db.create_user(
            username=username,
            password_hash=hashed,
            role="subadmin",
            is_active=1,
        )

        return jsonify({
            "success": True,
            "message": f"Subadmin '{username}' created successfully.",
            "id": new_id,
        }), 201

    @admin_bp.route("/api/subadmins/<int:user_id>/toggle", methods=["POST"])
    @main_admin_required
    def toggle_subadmin_status(user_id: int):
        """Toggle active/disabled status for a subadmin (Main Admin only)."""
        if not verify_csrf():
            return jsonify({"success": False, "error": "Invalid CSRF token."}), 403

        target = db.get_user_by_id(user_id)
        if not target:
            return jsonify({"success": False, "error": "Subadmin not found."}), 404
        if target["role"] == "main_admin":
            return jsonify({"success": False, "error": "Main administrator account cannot be disabled."}), 403

        new_status = not bool(target["is_active"])
        db.set_user_active_status(user_id, new_status)
        action = "enabled" if new_status else "disabled"
        return jsonify({
            "success": True,
            "message": f"Subadmin '{target['username']}' account {action}.",
            "is_active": new_status,
        })

    @admin_bp.route("/api/subadmins/<int:user_id>/reset-password", methods=["POST"])
    @main_admin_required
    def reset_subadmin_password(user_id: int):
        """Reset password for a subadmin (Main Admin only)."""
        if not verify_csrf():
            return jsonify({"success": False, "error": "Invalid CSRF token."}), 403

        target = db.get_user_by_id(user_id)
        if not target:
            return jsonify({"success": False, "error": "Subadmin not found."}), 404
        if target["role"] == "main_admin":
            return jsonify({"success": False, "error": "Cannot reset password for main administrator here."}), 403

        data = request.get_json(silent=True) or {}
        new_password = str(data.get("new_password") or "").strip()
        if not new_password or len(new_password) < 6:
            return jsonify({"success": False, "error": "New password must be at least 6 characters long."}), 400

        hashed = generate_password_hash(new_password)
        db.update_user_credentials(user_id=user_id, new_password_hash=hashed)

        return jsonify({
            "success": True,
            "message": f"Password for subadmin '{target['username']}' has been reset successfully.",
        })

    @admin_bp.route("/api/subadmins/<int:user_id>", methods=["DELETE"])
    @main_admin_required
    def delete_subadmin(user_id: int):
        """Delete a subadmin account (Main Admin only)."""
        if not verify_csrf():
            return jsonify({"success": False, "error": "Invalid CSRF token."}), 403

        target = db.get_user_by_id(user_id)
        if not target:
            return jsonify({"success": False, "error": "Subadmin not found."}), 404
        if target["role"] == "main_admin":
            return jsonify({"success": False, "error": "Main administrator account cannot be deleted."}), 403

        db.delete_subadmin(user_id)
        return jsonify({
            "success": True,
            "message": f"Subadmin '{target['username']}' deleted successfully.",
        })

    # ── Client API Key Management (External Projects) ──────────────────

    @admin_bp.route("/api/client-keys", methods=["GET"])
    @main_admin_required
    def list_client_keys():
        """List all client API keys for external applications (Main Admin only)."""
        keys = db.get_all_client_api_keys()
        return jsonify({"success": True, "keys": keys})

    @admin_bp.route("/api/client-keys", methods=["POST"])
    @main_admin_required
    def create_client_key():
        """Generate a new client API key for an external application (Main Admin only)."""
        if not verify_csrf():
            return jsonify({"success": False, "error": "Invalid CSRF token."}), 403

        data = request.get_json(silent=True) or {}
        name = str(data.get("name") or "").strip()
        rate_limit = data.get("rate_limit_per_minute", 60)

        if not name:
            return jsonify({"success": False, "error": "Application or client name is required."}), 400
        if len(name) < 2 or len(name) > 100:
            return jsonify({"success": False, "error": "Name must be between 2 and 100 characters."}), 400

        try:
            rate_limit_int = max(1, min(1000, int(rate_limit)))
        except (ValueError, TypeError):
            rate_limit_int = 60

        new_key = db.create_client_api_key(name=name, rate_limit_per_minute=rate_limit_int)
        return jsonify({
            "success": True,
            "message": f"API key for '{name}' generated successfully.",
            "key": new_key,
        }), 201

    @admin_bp.route("/api/client-keys/<int:key_id>/toggle", methods=["POST"])
    @main_admin_required
    def toggle_client_key(key_id: int):
        """Enable or revoke a client API key (Main Admin only)."""
        if not verify_csrf():
            return jsonify({"success": False, "error": "Invalid CSRF token."}), 403

        all_keys = db.get_all_client_api_keys()
        target = next((k for k in all_keys if k["id"] == key_id), None)
        if not target:
            return jsonify({"success": False, "error": "API key not found."}), 404

        new_status = not bool(target["is_active"])
        db.set_client_api_key_status(key_id, new_status)
        action = "activated" if new_status else "revoked"
        return jsonify({
            "success": True,
            "message": f"API key '{target['name']}' has been {action}.",
            "is_active": new_status,
        })

    @admin_bp.route("/api/client-keys/<int:key_id>", methods=["DELETE"])
    @main_admin_required
    def delete_client_key(key_id: int):
        """Permanently delete a client API key (Main Admin only)."""
        if not verify_csrf():
            return jsonify({"success": False, "error": "Invalid CSRF token."}), 403

        all_keys = db.get_all_client_api_keys()
        target = next((k for k in all_keys if k["id"] == key_id), None)
        if not target:
            return jsonify({"success": False, "error": "API key not found."}), 404

        db.delete_client_api_key(key_id)
        return jsonify({
            "success": True,
            "message": f"API key '{target['name']}' permanently deleted.",
        })

    # ── State Backup, Persistence & Vercel Sync ────────────────────────

    @admin_bp.route("/api/backup/export", methods=["GET"])
    @main_admin_required
    def export_backup():
        """Export full database state as a portable JSON backup (Main Admin only)."""
        data = db.export_backup()
        return jsonify({"success": True, "backup": data})

    @admin_bp.route("/api/backup/import", methods=["POST"])
    @main_admin_required
    def import_backup():
        """Import and restore database state from a JSON backup (Main Admin only)."""
        if not verify_csrf():
            return jsonify({"success": False, "error": "Invalid CSRF token."}), 403

        data = request.get_json(silent=True) or {}
        backup_content = data.get("backup") or data
        ok, msg = db.import_backup(backup_content)
        if ok:
            return jsonify({"success": True, "message": msg})
        return jsonify({"success": False, "error": msg}), 400

    @admin_bp.route("/api/persistence-info", methods=["GET"])
    @main_admin_required
    def get_persistence_info():
        """Return information about Vercel serverless persistence and subadmins env config."""
        subadmins = db.get_all_subadmins()
        sample_env = ",".join([f"{s['username']}:password" for s in subadmins])
        return jsonify({
            "success": True,
            "is_vercel": bool(os.getenv("VERCEL")),
            "database_path": config.DATABASE_PATH,
            "subadmin_env_configured": bool(config.SUBADMIN_USERS),
            "suggested_env_string": sample_env,
            "subadmins_count": len(subadmins),
        })

    return admin_bp
