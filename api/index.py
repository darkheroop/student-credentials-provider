"""
Vercel Serverless Function entry point for Student Credentials Provider.
Exports the Flask application for Vercel's Python runtime.
"""

import sys
import os

# Ensure the root project directory is on the Python module search path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import app


class VercelPathFixMiddleware:
    """
    WSGI middleware that normalizes PATH_INFO and SCRIPT_NAME on Vercel.

    When Vercel rewrites requests to /api/index, PATH_INFO or SCRIPT_NAME may
    contain the internal serverless destination rather than the original route.
    This middleware reconstructs the clean client-intended path.
    """

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        environ["ORIGINAL_PATH_INFO"] = environ.get("PATH_INFO", "")
        matched_path = environ.get("HTTP_X_MATCHED_PATH")
        path_info = environ.get("PATH_INFO", "")

        # Check HTTP_X_MATCHED_PATH first (if it represents a user route)
        if matched_path and not matched_path.startswith(("/api/index", "/api/index.py")):
            clean_path = matched_path.split("?")[0]
            environ["PATH_INFO"] = clean_path if clean_path else "/"
            environ["SCRIPT_NAME"] = ""
        else:
            # Strip /api/index.py or /api/index prefix if present
            for prefix in ("/api/index.py", "/api/index"):
                if path_info.startswith(prefix):
                    clean_path = path_info[len(prefix):]
                    environ["PATH_INFO"] = clean_path if clean_path else "/"
                    environ["SCRIPT_NAME"] = ""
                    break

        if not environ.get("PATH_INFO"):
            environ["PATH_INFO"] = "/"

        return self.wsgi_app(environ, start_response)


# Apply middleware to Flask application
app.wsgi_app = VercelPathFixMiddleware(app.wsgi_app)

# Export for WSGI / ASGI runners
application = app
