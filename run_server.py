"""
Convenience launcher for the AI SIEM Full-Stack Web Application.

Run from PowerShell:
    python run_server.py

Then open your browser at:
    http://127.0.0.1:8000
"""

import os
import sys
import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0" if (os.environ.get("PORT") or os.environ.get("RENDER")) else "127.0.0.1")
    print("=" * 70)
    print(" AI SIEM System for Cyber Threat Detection (ANN Event Profiles)")
    print("=" * 70)
    print(f" * Backend:  FastAPI on http://{host}:{port}/api")
    print(f" * Frontend: Modern Cyber SOC Dashboard on http://{host}:{port}")
    print(f" * API Docs: Interactive Swagger UI on http://{host}:{port}/docs")
    print("=" * 70)
    uvicorn.run("backend.main:app", host=host, port=port, reload=False)
