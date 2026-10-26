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

# Export the application for WSGI / ASGI runners
application = app
