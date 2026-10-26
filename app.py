"""
Student Credentials Provider – Flask application.

Provides a web UI and REST API for verifying student credentials and records
via the Student Lookup Service (supporting both offline demo and live external provider).
"""

import os
import time
from functools import wraps

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

from config import Config
from services.student_lookup import StudentLookupService, HashLookupService

# ── Application factory ────────────────────────────────────────────────

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
config = Config()
app.secret_key = config.SECRET_KEY

CORS(app)

student_lookup_service = StudentLookupService(config)
hash_lookup_service = student_lookup_service  # Backward compatibility alias

# ── In-memory rate limiter ──────────────────────────────────────────────

_rate_limit_store: dict[str, list[float]] = {}


def _cleanup_timestamps(timestamps: list[float], window: float) -> list[float]:
    """Remove timestamps older than *window* seconds."""
    cutoff = time.time() - window
    return [ts for ts in timestamps if ts > cutoff]


def rate_limit(func):
    """Decorator that enforces per-IP rate limiting based on config."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        client_ip = request.remote_addr or "unknown"
        now = time.time()
        window = 60.0  # one minute

        # Get (or create) the timestamp list for this IP
        timestamps = _rate_limit_store.get(client_ip, [])
        timestamps = _cleanup_timestamps(timestamps, window)

        if len(timestamps) >= config.RATE_LIMIT_PER_MINUTE:
            return jsonify({
                "success": False,
                "error": "Rate limit exceeded. Please try again later.",
            }), 429

        timestamps.append(now)
        _rate_limit_store[client_ip] = timestamps

        return func(*args, **kwargs)

    return wrapper


# ── Security headers ───────────────────────────────────────────────────

@app.after_request
def set_security_headers(response):
    """Attach security-related HTTP headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
        "script-src 'self' 'unsafe-eval' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    return response


# ── Page routes ─────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Render the main landing page and Student Lookup dashboard."""
    return render_template("index.html")


@app.route("/about")
def about():
    """Render the about page."""
    return render_template("about.html")


@app.route("/documentation")
def documentation():
    """Render the technical documentation page."""
    return render_template("documentation.html")


@app.route("/learn")
def learn():
    """Render the educational learning center page."""
    return render_template("learn.html")


# ── API routes ──────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def api_health():
    """Return a simple health-check payload without exposing secrets."""
    return jsonify({
        "status": "healthy",
        "mode": config.STUDENT_LOOKUP_MODE,
        "service": "Student Credentials Provider",
        "version": "1.0.0",
    })


@app.route("/api/student-lookup", methods=["POST"])
@app.route("/api/lookup", methods=["POST"])  # Backward compatibility alias
@rate_limit
def api_student_lookup():
    """
    Look up a student record or credential via the configured service.

    Expects JSON body::

        {"lookup_input": "<digest or test value>", "algorithm_type": "md5"}
        # Or {"hash": "<value>", "algorithm": "md5"} for backward compatibility

    Returns a normalised JSON response.
    """
    # ── Validate Content-Type ───────────────────────────────────────
    if not request.is_json:
        return jsonify({
            "success": False,
            "status": "invalid_input",
            "error": "Content-Type must be application/json.",
            "message": "Content-Type must be application/json.",
        }), 400

    # ── Parse JSON body ─────────────────────────────────────────────
    try:
        data = request.get_json(force=False)
    except Exception:
        return jsonify({
            "success": False,
            "status": "invalid_input",
            "error": "Malformed JSON in request body.",
            "message": "Malformed JSON in request body.",
        }), 400

    if data is None:
        return jsonify({
            "success": False,
            "status": "invalid_input",
            "error": "Malformed JSON in request body.",
            "message": "Malformed JSON in request body.",
        }), 400

    # ── Extract & validate fields ───────────────────────────────────
    lookup_input = data.get("lookup_input") or data.get("hash")
    algorithm_type = data.get("algorithm_type") or data.get("algorithm")

    if not lookup_input or not str(lookup_input).strip():
        return jsonify({
            "success": False,
            "status": "invalid_input",
            "error": "Missing required field: 'lookup_input'.",
            "message": "Please provide a valid lookup value and supported algorithm.",
        }), 400

    if not algorithm_type or not str(algorithm_type).strip():
        return jsonify({
            "success": False,
            "status": "invalid_input",
            "error": "Missing required field: 'algorithm_type'.",
            "message": "Please provide a valid lookup value and supported algorithm.",
        }), 400

    # ── Perform lookup ──────────────────────────────────────────────
    result = student_lookup_service.student_lookup(str(lookup_input), str(algorithm_type))

    status_code = 200 if result.get("success") else 400
    return jsonify(result), status_code


@app.route("/api/demo-student-lookup", methods=["POST"])
@app.route("/api/demo-lookup", methods=["POST"])  # Backward compatibility alias
@rate_limit
def api_demo_student_lookup():
    """
    Always perform a demo-mode Student Lookup using synthetic test data.

    Same request / response contract as ``/api/student-lookup``.
    """
    # ── Validate Content-Type ───────────────────────────────────────
    if not request.is_json:
        return jsonify({
            "success": False,
            "status": "invalid_input",
            "error": "Content-Type must be application/json.",
            "message": "Content-Type must be application/json.",
        }), 400

    # ── Parse JSON body ─────────────────────────────────────────────
    try:
        data = request.get_json(force=False)
    except Exception:
        return jsonify({
            "success": False,
            "status": "invalid_input",
            "error": "Malformed JSON in request body.",
            "message": "Malformed JSON in request body.",
        }), 400

    if data is None:
        return jsonify({
            "success": False,
            "status": "invalid_input",
            "error": "Malformed JSON in request body.",
            "message": "Malformed JSON in request body.",
        }), 400

    # ── Extract & validate fields ───────────────────────────────────
    lookup_input = data.get("lookup_input") or data.get("hash")
    algorithm_type = data.get("algorithm_type") or data.get("algorithm")

    if not lookup_input or not str(lookup_input).strip():
        return jsonify({
            "success": False,
            "status": "invalid_input",
            "error": "Missing required field: 'lookup_input'.",
            "message": "Please provide a valid lookup value and supported algorithm.",
        }), 400

    if not algorithm_type or not str(algorithm_type).strip():
        return jsonify({
            "success": False,
            "status": "invalid_input",
            "error": "Missing required field: 'algorithm_type'.",
            "message": "Please provide a valid lookup value and supported algorithm.",
        }), 400

    # ── Force demo-mode lookup ──────────────────────────────────────
    cleaned_input = str(lookup_input).strip().lower()
    cleaned_algo = str(algorithm_type).strip().lower()

    valid, error_msg = student_lookup_service.validate_lookup_input(cleaned_input, cleaned_algo)
    if not valid:
        return jsonify({
            "success": False,
            "status": "invalid_input",
            "found": False,
            "lookup_input": cleaned_input,
            "hash": cleaned_input,
            "algorithm": cleaned_algo,
            "algorithm_type": cleaned_algo,
            "plaintext": None,
            "mode": "demo",
            "message": error_msg,
            "error": error_msg,
            "duration": 0.0,
        }), 400

    result = student_lookup_service._demo_student_lookup(cleaned_input, cleaned_algo)
    return jsonify(result), 200


# ── Error handlers ──────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(error):
    """Handle 404 Not Found."""
    if request.path.startswith("/api/"):
        return jsonify({
            "success": False,
            "error": "The requested API endpoint was not found.",
        }), 404
    return render_template("index.html"), 404


@app.errorhandler(405)
def method_not_allowed(error):
    """Handle 405 Method Not Allowed."""
    return jsonify({
        "success": False,
        "error": "HTTP method not allowed for this endpoint.",
    }), 405


@app.errorhandler(500)
def internal_server_error(error):
    """Handle 500 Internal Server Error (never expose stack traces)."""
    return jsonify({
        "success": False,
        "error": "An internal server error occurred. Please try again later.",
    }), 500


# ── Entry-point ────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=False, port=5000)
