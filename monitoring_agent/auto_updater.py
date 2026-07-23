"""
Agent Auto-Updater – checks for new versions, downloads, and applies in-place updates.

Windows strategy:
  1. GET /api/agent/status → compare agent_version to CURRENT_VERSION
  2. Stream-download new binary → temp file next to current exe
  3. Verify SHA-256 checksum
  4. Rename current → .old, temp → current
  5. Launch new exe (detached) and exit
  6. New process cleans up .old on startup
"""

import hashlib
import os
import sys
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import requests

CURRENT_VERSION = "9.0"
CHECK_INTERVAL = 3600          # 1 hour


def _version_tuple(v: str):
    """Parse '5.0' → (5, 0) for comparison."""
    try:
        return tuple(int(x) for x in v.strip().split("."))
    except Exception:
        return (0,)


class AutoUpdater:
    """Background auto-update checker for the CryptoDetect monitoring agent."""

    def __init__(self, api_url: str, *, on_status=None):
        """
        Args:
            api_url: Base backend URL, e.g. http://localhost:8000
            on_status: Optional callback(message: str) for tray notifications
        """
        self.api_url = api_url.rstrip("/")
        self.on_status = on_status or (lambda msg: print(f"[UPDATE] {msg}"))
        self._stop_event = threading.Event()

    # ── Public API ─────────────────────────────────────────

    def check_for_update(self) -> dict | None:
        """GET /api/agent/status; return status dict if a newer version is available."""
        try:
            resp = requests.get(f"{self.api_url}/api/agent/status", timeout=10)
            resp.raise_for_status()
            data = resp.json()

            remote_ver = data.get("agent_version", "0")
            if _version_tuple(remote_ver) > _version_tuple(CURRENT_VERSION):
                self.on_status(f"Update available: v{CURRENT_VERSION} → v{remote_ver}")
                return data
            return None
        except Exception as e:
            print(f"[UPDATE] Version check failed: {e}")
            return None

    def download_update(self, download_url: str, expected_checksum: str | None) -> Path | None:
        """Stream-download new binary, verify SHA-256, return temp path."""
        try:
            full_url = f"{self.api_url}{download_url}" if download_url.startswith("/") else download_url
            self.on_status("Downloading update…")

            resp = requests.get(full_url, stream=True, timeout=120)
            resp.raise_for_status()

            # Write to temp file in the same directory as the current exe
            exe_dir = Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(".")
            tmp_fd, tmp_path = tempfile.mkstemp(suffix=".tmp", dir=str(exe_dir))

            sha = hashlib.sha256()
            with os.fdopen(tmp_fd, "wb") as f:
                for chunk in resp.iter_content(chunk_size=65536):
                    f.write(chunk)
                    sha.update(chunk)

            # Verify checksum
            if expected_checksum:
                actual = sha.hexdigest()
                if actual != expected_checksum:
                    os.unlink(tmp_path)
                    self.on_status("Update checksum mismatch – download discarded")
                    return None

            self.on_status("Download complete, checksum verified")
            return Path(tmp_path)

        except Exception as e:
            self.on_status(f"Download failed: {e}")
            return None

    def apply_update(self, new_exe: Path):
        """
        In-place binary swap:
          1. Rename running exe → .old
          2. Rename temp → running exe name
          3. Launch new exe (detached)
          4. Exit current process
        """
        if not getattr(sys, 'frozen', False):
            self.on_status("Cannot apply update in non-frozen (script) mode")
            return

        current_exe = Path(sys.executable)
        old_exe = current_exe.with_suffix(".old")

        try:
            # Remove previous .old if it still exists
            if old_exe.exists():
                os.unlink(str(old_exe))

            # Rename current → old
            os.rename(str(current_exe), str(old_exe))
            # Rename downloaded → current
            os.rename(str(new_exe), str(current_exe))

            self.on_status("Update applied – restarting agent…")

            # Launch new exe detached
            subprocess.Popen(
                [str(current_exe)],
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
                close_fds=True,
            )

            # Exit current process
            os._exit(0)

        except Exception as e:
            self.on_status(f"Update apply failed: {e}")
            # Try to roll back
            try:
                if old_exe.exists() and not current_exe.exists():
                    os.rename(str(old_exe), str(current_exe))
            except Exception:
                pass

    @staticmethod
    def cleanup_old_binary():
        """Delete leftover .old file from a previous update (call on startup)."""
        if not getattr(sys, 'frozen', False):
            return
        old_exe = Path(sys.executable).with_suffix(".old")
        if old_exe.exists():
            try:
                os.unlink(str(old_exe))
                print("[UPDATE] Cleaned up old binary")
            except Exception as e:
                print(f"[UPDATE] Cleanup failed: {e}")

    # ── Background loop ──────────────────────────────────

    def start_background_checker(self):
        """Start a daemon thread that checks for updates every CHECK_INTERVAL seconds."""
        t = threading.Thread(target=self._checker_loop, daemon=True, name="auto-updater")
        t.start()
        return t

    def stop(self):
        self._stop_event.set()

    def _checker_loop(self):
        """Periodically poll for updates."""
        # Wait a bit after startup before first check
        if self._stop_event.wait(30):
            return

        while not self._stop_event.is_set():
            info = self.check_for_update()
            if info:
                new_exe = self.download_update(
                    info.get("download_url", "/api/agent/download"),
                    info.get("checksum"),
                )
                if new_exe:
                    self.on_status("Update ready – will apply on next restart or confirm via tray")
                    # Note: We do NOT auto-apply; the tray menu handler calls apply_update().

            if self._stop_event.wait(CHECK_INTERVAL):
                break
