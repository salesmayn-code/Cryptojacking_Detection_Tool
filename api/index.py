"""
Vercel Serverless Function Entrypoint for CryptoDetect FastAPI Backend.
Routes all /api/* requests to the FastAPI application in backend.main.
"""
import os
import sys

_ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

from backend.main import app  # noqa: E402, F401
