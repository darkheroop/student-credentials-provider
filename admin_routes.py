"""
Administrative routes and controllers for dynamic API key management.

Provides server-side authentication, CSRF validation, SSRF protection,
and CRUD endpoints for API configurations and failover controls.
"""

import ipaddress
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

    def admin_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not session.get("admin_authenticated"):
                if request.is_json or request.path.startswith("/admin/api/"):
                    return jsonify({"success": False, "error": "Authentication required."}), 401
                return redirect(url_for("admin.login_page"))
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

        if username == config.ADMIN_USERNAME and password == config.ADMIN_PASSWORD:
            session["admin_authenticated"] = True
            session["csrf_token"] = secrets.token_hex(16)

            if request.is_json:
                return jsonify({"success": True, "csrf_token": session["csrf_token"]})
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
        return render_template("admin.html", csrf_token=session.get("csrf_token", ""))

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

    return admin_bp
