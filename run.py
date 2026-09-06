"""
Entry point — starts the 3GPP Log Analyzer FastAPI application.
Run: python run.py
"""

import os
import sys

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_dirs=["app", "templates", "static"],
        log_level="info",
    )
