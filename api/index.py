"""
Vercel Serverless Function entry point for Student Credentials Provider.
Exports the Flask application for Vercel's Python runtime.
"""

import sys
import os
import traceback
from urllib.parse import parse_qs, urlencode

# Ensure the root project directory is on the Python module search path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

_app_instance = None
_init_error = None

try:
    from app import app as _flask_app
    _app_instance = _flask_app
except Exception:
    _init_error = traceback.format_exc()


class VercelPathFixMiddleware:
    """
    WSGI middleware that normalizes PATH_INFO and SCRIPT_NAME on Vercel.

    When Vercel rewrites requests to /api/index?__path=$1, the captured path
    is stored in the __path query parameter. This middleware reconstructs
    the clean client-intended PATH_INFO and removes __path from QUERY_STRING.
    """

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        if _init_error:
            start_response("500 Internal Server Error", [("Content-Type", "text/plain; charset=utf-8")])
            return [f"Serverless Init Error:\n{_init_error}".encode("utf-8")]

        qs_raw = environ.get("QUERY_STRING", "")
        if "__path=" in qs_raw or qs_raw.startswith("__path"):
            qs = parse_qs(qs_raw, keep_blank_values=True)
            if "__path" in qs:
                captured = qs.pop("__path")[0]
                environ["PATH_INFO"] = "/" + captured.lstrip("/")
                environ["QUERY_STRING"] = urlencode(qs, doseq=True)
                environ["SCRIPT_NAME"] = ""
        else:
            # Fallback for direct invocations or legacy rewrites
            matched_path = environ.get("HTTP_X_MATCHED_PATH")
            path_info = environ.get("PATH_INFO", "")

            if matched_path and not matched_path.startswith(("/api/index", "/api/index.py")):
                clean_path = matched_path.split("?")[0]
                environ["PATH_INFO"] = clean_path if clean_path else "/"
                environ["SCRIPT_NAME"] = ""
            elif path_info.startswith(("/api/index.py", "/api/index")):
                for prefix in ("/api/index.py", "/api/index"):
                    if path_info.startswith(prefix):
                        clean_path = path_info[len(prefix):]
                        environ["PATH_INFO"] = clean_path if clean_path else "/"
                        environ["SCRIPT_NAME"] = ""
                        break

        if not environ.get("PATH_INFO"):
            environ["PATH_INFO"] = "/"

        try:
            return self.wsgi_app(environ, start_response)
        except Exception:
            err = traceback.format_exc()
            start_response("500 Internal Server Error", [("Content-Type", "text/plain; charset=utf-8")])
            return [f"Serverless Request Error:\n{err}".encode("utf-8")]


if _app_instance is not None:
    _app_instance.wsgi_app = VercelPathFixMiddleware(_app_instance.wsgi_app)
    app = _app_instance
    application = _app_instance
else:
    def _fallback_app(environ, start_response):
        start_response("500 Internal Server Error", [("Content-Type", "text/plain; charset=utf-8")])
        return [f"Serverless Startup Error:\n{_init_error}".encode("utf-8")]

    app = _fallback_app
    application = _fallback_app
