"""
Agent Download Route - Serves agent installer and provides setup endpoint
"""
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path
import hashlib
import os
from datetime import datetime

router = APIRouter()

# Path to agent executable
AGENT_DIR = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) / '..' / 'monitoring_agent'
AGENT_LATEST_VERSION = "1.0"
AGENT_LATEST_EXE = AGENT_DIR / 'dist' / 'CryptoDetect-Agent-v1.exe'
AGENT_LEGACY_VERSION = "1.0"
AGENT_LEGACY_EXE = AGENT_LATEST_EXE


def _agent_payload(path: Path, version: str) -> dict:
    filename = f"CryptoDetect-Agent-v{version}.exe"
    mtime = datetime.fromtimestamp(path.stat().st_mtime).isoformat() if path.exists() else None
    return {
        "available": path.exists(),
        "filename": filename,
        "agent_version": version,
        "size_bytes": path.stat().st_size if path.exists() else 0,
        "checksum": _exe_sha256(path),
        "last_modified": mtime,
        "platform": "Windows",
        "download_url": f"/api/agent/download?version={version}",
    }


def _resolve_agent(version: str | None) -> tuple[Path, str]:
    if version and str(version).startswith("7"):
        return AGENT_LEGACY_EXE, AGENT_LEGACY_VERSION
    return AGENT_LATEST_EXE, AGENT_LATEST_VERSION


def _exe_sha256(path: Path) -> str | None:
    """Compute SHA-256 checksum of the agent binary for update verification."""
    if not path.exists():
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@router.get("/download")
async def download_agent(version: str | None = None):
    """Download the monitoring agent executable"""
    exe_path, resolved_version = _resolve_agent(version)
    exe_path = exe_path.resolve()
    
    if not exe_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Agent executable v{resolved_version} not built yet. Run 'python build_exe.py' in monitoring_agent/."
        )
    
    return FileResponse(
        path=str(exe_path),
        filename=f"CryptoDetect-Agent-v{resolved_version}.exe",
        media_type="application/octet-stream",
        headers={"Cache-Control": "no-store, no-cache, max-age=0"}
    )

@router.get("/status")
async def agent_download_status():
    """Check if agent executable is available for download + version/checksum info"""
    latest = _agent_payload(AGENT_LATEST_EXE.resolve(), AGENT_LATEST_VERSION)
    legacy = _agent_payload(AGENT_LEGACY_EXE.resolve(), AGENT_LEGACY_VERSION)

    status = dict(latest)
    status["legacy"] = legacy
    return status

@router.get("/setup-instructions")
async def setup_instructions():
    """Get agent setup instructions"""
    return {
        "steps": [
            {
                "step": 1,
                "title": "Download Agent",
                "description": "Download the latest CryptoDetect-Agent-v1.exe from the button above"
            },
            {
                "step": 2,
                "title": "Run Agent",
                "description": "Double-click the downloaded file to run it"
            },
            {
                "step": 3,
                "title": "Configure Credentials",
                "description": "Enter your System ID, API Key, and backend URL in the setup window"
            },
            {
                "step": 4,
                "title": "Monitoring Starts",
                "description": "Use tray menu Start Monitoring to begin secure metrics upload"
            }
        ],
        "notes": [
            "The agent runs as a tray application in the background",
            "Metrics are collected every 5 seconds",
            "Data is sent to the backend every 30 seconds by default (with 10-second heartbeats)",
            "Send interval can be tuned with AGENT_BATCH_SIZE",
            "System ID and API Key are validated before monitoring starts",
            "Stop monitoring from tray menu Stop Monitoring"
        ]
    }
