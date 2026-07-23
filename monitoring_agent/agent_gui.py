"""Windows tray application for CryptoDetect monitoring agent."""

import logging
import platform
import threading
import time
import webbrowser
from pathlib import Path
import os
import json
import subprocess

import requests
import psutil

try:
    import tkinter as tk
    from tkinter import messagebox
except Exception:  # pragma: no cover
    tk = None
    messagebox = None

try:
    import ctypes
except Exception:  # pragma: no cover
    ctypes = None

try:
    import pystray
    from pystray import MenuItem as Item
    from PIL import Image, ImageDraw
except Exception:  # pragma: no cover
    pystray = None
    Item = None
    Image = None
    ImageDraw = None

from enhanced_agent import MonitoringAgent, load_config, save_config
from auto_updater import AutoUpdater, CURRENT_VERSION


APP_NAME = "CryptoDetect Agent"
DEFAULT_BACKEND = "http://localhost:8000"
DEFAULT_DASHBOARD = "http://localhost:3000"
LOG_DIR = Path.home() / ".cryptodetect"
LOG_FILE = LOG_DIR / "agent_gui.log"


LOG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


class AgentTrayApp:
    def __init__(self):
        self.config = load_config() or {}
        self.agent = None
        self.agent_thread = None
        self.icon = None
        self.root = None
        self.status_var = None
        self.action_var = None
        self._pending_update = None       # Path to downloaded update binary

        # Clean up leftover .old binary from a previous update
        AutoUpdater.cleanup_old_binary()

        # Initialise auto-updater (needs api_url from config)
        api_url = self.config.get("api_url", DEFAULT_BACKEND)
        self.updater = AutoUpdater(api_url, on_status=lambda msg: logging.info(msg))

    def _create_icon(self):
        if Image is None:
            return None

        image = Image.new("RGB", (64, 64), color=(24, 34, 54))
        draw = ImageDraw.Draw(image)
        draw.rectangle((8, 8, 56, 56), outline=(72, 126, 245), width=3)
        draw.text((19, 21), "CD", fill=(72, 126, 245))
        return image

    def _is_running(self):
        return self.agent_thread is not None and self.agent_thread.is_alive()

    def _validate_setup(self, system_id: str, api_key: str, api_url: str) -> tuple[bool, str]:
        if not system_id.strip() or not api_key.strip():
            return False, "System ID and API key are required"

        try:
            health = requests.get(f"{api_url}/health", timeout=6)
            if health.status_code != 200:
                return False, f"Backend health check failed: {health.status_code}"

            payload = {
                "system_id": system_id.strip(),
                "api_key": api_key.strip(),
                "device_name": platform.node() or "unknown-device",
            }
            resp = requests.post(f"{api_url}/api/auth/agent/validate", json=payload, timeout=8)
            if resp.status_code != 200:
                return False, f"Validation request failed: {resp.status_code}"

            data = resp.json()
            if not data.get("valid"):
                return False, "System ID and API key do not match"

            return True, "Validated"
        except requests.RequestException as exc:
            return False, f"Connection error: {exc}"

    def _show_message(self, title: str, body: str):
        if messagebox is not None:
            try:
                root = tk.Tk()
                root.withdraw()
                root.attributes("-topmost", True)
                root.lift()
                messagebox.showinfo(title, body, parent=root)
                root.destroy()
                return
            except Exception:
                pass
        if ctypes is not None and os.name == "nt":
            try:
                flags = 0x40 | 0x00040000 | 0x00010000
                ctypes.windll.user32.MessageBoxW(0, body, title, flags)
                return
            except Exception:
                pass
        logging.info("%s: %s", title, body)

    def _set_action(self, message: str):
        if self.action_var is not None:
            self.action_var.set(message)

    def _menu_status_text(self, _item=None):
        return "Status: Running" if self._is_running() else "Status: Stopped"

    def _status_label_text(self):
        if not self.config:
            return "Status: Not configured"
        return "Status: Running" if self._is_running() else "Status: Stopped"

    def _set_high_priority(self):
        if os.name != "nt":
            return
        try:
            psutil.Process(os.getpid()).nice(psutil.HIGH_PRIORITY_CLASS)
        except Exception as exc:
            logging.warning("Failed to set high priority: %s", exc)

    def _run_on_ui(self, fn):
        if self.root is None:
            return
        try:
            self.root.after(0, fn)
        except Exception:
            pass

    def _show_window(self):
        if self.root is None:
            return
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def _hide_window(self):
        if self.root is None:
            return
        self.root.withdraw()

    def _on_minimize(self, _event=None):
        if self.root is None:
            return
        if self.root.state() == "iconic":
            self._hide_window()

    def _on_close(self):
        self._hide_window()
        self._set_action("Minimized to tray")

    def _build_main_window(self):
        if tk is None:
            self._show_message(APP_NAME, "Tkinter is unavailable. Please install it or run tray-only mode.")
            return

        self.root = tk.Tk()
        self.root.title(APP_NAME)
        self.root.geometry("480x420")
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.bind("<Unmap>", self._on_minimize)

        self.status_var = tk.StringVar(value=self._status_label_text())
        self.action_var = tk.StringVar(value="Ready")

        header = tk.Frame(self.root, padx=16, pady=12)
        header.pack(fill="x")
        tk.Label(header, text=APP_NAME, font=("Segoe UI", 14, "bold")).pack(anchor="w")
        tk.Label(header, text=f"Version v{CURRENT_VERSION}", fg="#555555").pack(anchor="w")

        status_frame = tk.Frame(self.root, padx=16, pady=8)
        status_frame.pack(fill="x")
        tk.Label(status_frame, textvariable=self.status_var, font=("Segoe UI", 11, "bold")).pack(anchor="w")
        tk.Label(status_frame, textvariable=self.action_var, fg="#444444").pack(anchor="w", pady=(4, 0))

        config_frame = tk.LabelFrame(self.root, text="Current Configuration", padx=12, pady=8)
        config_frame.pack(fill="x", padx=16, pady=8)
        system_id = self.config.get("system_id", "Not set")
        api_url = self.config.get("api_url", DEFAULT_BACKEND)
        tk.Label(config_frame, text=f"System ID: {system_id}").pack(anchor="w")
        tk.Label(config_frame, text=f"Backend: {api_url}").pack(anchor="w")

        button_frame = tk.Frame(self.root, padx=16, pady=12)
        button_frame.pack(fill="x")

        tk.Button(button_frame, text="Start Monitoring", width=20, command=self.start_monitoring).grid(row=0, column=0, padx=6, pady=6)
        tk.Button(button_frame, text="Stop Monitoring", width=20, command=self.stop_monitoring).grid(row=0, column=1, padx=6, pady=6)
        tk.Button(button_frame, text="Open Dashboard", width=20, command=self.open_dashboard).grid(row=1, column=0, padx=6, pady=6)
        tk.Button(button_frame, text="Configure", width=20, command=self.open_setup).grid(row=1, column=1, padx=6, pady=6)
        tk.Button(button_frame, text="View Logs", width=20, command=self.view_logs).grid(row=2, column=0, padx=6, pady=6)
        tk.Button(button_frame, text="Check Updates", width=20, command=self.check_for_updates).grid(row=2, column=1, padx=6, pady=6)

        footer = tk.Frame(self.root, padx=16, pady=12)
        footer.pack(fill="x")
        tk.Button(footer, text="Exit", command=self.exit_app, width=12).pack(side="right")

    def _prompt_setup_via_powershell(self):
        cfg = self.config or {}
        default_system = str(cfg.get("system_id", "")).replace("'", "''")
        default_api_key = str(cfg.get("api_key", "")).replace("'", "''")
        default_api_url = str(cfg.get("api_url", DEFAULT_BACKEND)).replace("'", "''")

        script = f"""
Add-Type -AssemblyName Microsoft.VisualBasic
$sid = [Microsoft.VisualBasic.Interaction]::InputBox('Enter System ID', 'CryptoDetect Agent Setup', '{default_system}')
if ([string]::IsNullOrWhiteSpace($sid)) {{ Write-Output ''; exit 1 }}
$key = [Microsoft.VisualBasic.Interaction]::InputBox('Enter API Key', 'CryptoDetect Agent Setup', '{default_api_key}')
if ([string]::IsNullOrWhiteSpace($key)) {{ Write-Output ''; exit 1 }}
$url = [Microsoft.VisualBasic.Interaction]::InputBox('Enter Backend URL', 'CryptoDetect Agent Setup', '{default_api_url}')
if ([string]::IsNullOrWhiteSpace($url)) {{ $url = '{DEFAULT_BACKEND}' }}
@{{ system_id = $sid; api_key = $key; api_url = $url }} | ConvertTo-Json -Compress
"""
        try:
            completed = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                capture_output=True,
                text=True,
                timeout=180,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            output = (completed.stdout or "").strip()
            if completed.returncode != 0 or not output:
                return
            data = json.loads(output)

            system_id = str(data.get("system_id") or "").strip()
            api_key = str(data.get("api_key") or "").strip()
            api_url = str(data.get("api_url") or DEFAULT_BACKEND).strip()
            ok, reason = self._validate_setup(system_id, api_key, api_url)
            if not ok:
                self._show_message(APP_NAME, f"Configuration validation failed: {reason}")
                return

            save_config(system_id, api_key, api_url)
            self.config = {"system_id": system_id, "api_key": api_key, "api_url": api_url}
            self._show_message(APP_NAME, "Configuration saved.")
        except Exception as exc:
            self._show_message(APP_NAME, f"Configure failed: {exc}")

    def _open_setup_window(self):
        if tk is None:
            self._prompt_setup_via_powershell()
            return

        cfg = self.config or {}

        window = tk.Tk()
        window.title("CryptoDetect Agent Setup")
        window.geometry("480x260")
        window.resizable(False, False)

        tk.Label(window, text="System ID").pack(anchor="w", padx=16, pady=(16, 2))
        system_id_var = tk.StringVar(value=cfg.get("system_id", ""))
        tk.Entry(window, textvariable=system_id_var, width=55).pack(padx=16)

        tk.Label(window, text="API Key").pack(anchor="w", padx=16, pady=(12, 2))
        api_key_var = tk.StringVar(value=cfg.get("api_key", ""))
        tk.Entry(window, textvariable=api_key_var, width=55, show="*").pack(padx=16)

        tk.Label(window, text="Backend URL").pack(anchor="w", padx=16, pady=(12, 2))
        api_url_var = tk.StringVar(value=cfg.get("api_url", DEFAULT_BACKEND))
        tk.Entry(window, textvariable=api_url_var, width=55).pack(padx=16)

        status_label = tk.Label(window, text="", fg="red")
        status_label.pack(anchor="w", padx=16, pady=(10, 0))

        def save_and_close(start_after=False):
            system_id = system_id_var.get().strip()
            api_key = api_key_var.get().strip()
            api_url = api_url_var.get().strip() or DEFAULT_BACKEND

            ok, reason = self._validate_setup(system_id, api_key, api_url)
            if not ok:
                status_label.config(text=reason)
                return

            save_config(system_id, api_key, api_url)
            self.config = {"system_id": system_id, "api_key": api_key, "api_url": api_url}
            logging.info("Configuration updated for system %s", system_id)
            
            # If the agent is already running, we MUST stop it so it can restart with new credentials
            was_running = self._is_running()
            if was_running:
                self.stop_monitoring()

            window.destroy()

            if start_after or was_running:
                # Small delay to ensure the thread fully exits before starting a new one
                time.sleep(0.5)
                self.start_monitoring()

        button_frame = tk.Frame(window)
        button_frame.pack(fill="x", padx=16, pady=16)

        tk.Button(button_frame, text="Save", command=lambda: save_and_close(False)).pack(side="left")
        tk.Button(button_frame, text="Save and Start", command=lambda: save_and_close(True)).pack(side="left", padx=8)
        tk.Button(button_frame, text="Cancel", command=window.destroy).pack(side="right")

        window.mainloop()

    def open_setup(self):
        threading.Thread(target=self._open_setup_window, daemon=True).start()

    def start_monitoring(self):
        if self._is_running():
            self._show_message(APP_NAME, "Monitoring is already running.")
            self._set_action("Monitoring already running")
            return

        config = load_config() or {}
        system_id = config.get("system_id")
        api_key = config.get("api_key")
        api_url = config.get("api_url", DEFAULT_BACKEND)

        if not system_id or not api_key:
            self._show_message(APP_NAME, "Configuration is missing. Open Configure first.")
            self._set_action("Configuration required")
            self.open_setup()
            return

        ok, reason = self._validate_setup(system_id, api_key, api_url)
        if not ok:
            self._show_message(APP_NAME, f"Unable to start monitoring: {reason}")
            self._set_action("Start failed")
            return

        self.agent = MonitoringAgent(system_id=system_id, api_key=api_key, api_url=api_url, verbose=False)

        def _run_agent():
            logging.info("Monitoring started for system %s", system_id)
            try:
                self.agent.run()
            except Exception as exc:
                logging.exception("Monitoring thread failed: %s", exc)
            finally:
                logging.info("Monitoring thread ended")

        self.agent_thread = threading.Thread(target=_run_agent, daemon=True)
        self.agent_thread.start()
        self._show_message(APP_NAME, "Monitoring started.")
        if self.status_var is not None:
            self.status_var.set(self._status_label_text())
        self._set_action("Monitoring started")
        if self.icon:
            self.icon.update_menu()

    def stop_monitoring(self):
        if not self._is_running() or self.agent is None:
            self._show_message(APP_NAME, "Monitoring is not running.")
            self._set_action("Monitoring not running")
            return

        self.agent.stop()
        for _ in range(20):
            if not self._is_running():
                break
            time.sleep(0.2)

        self._show_message(APP_NAME, "Monitoring stopped.")
        if self.status_var is not None:
            self.status_var.set(self._status_label_text())
        self._set_action("Monitoring stopped")
        if self.icon:
            self.icon.update_menu()

    def _stop_monitoring_silent(self):
        if not self._is_running() or self.agent is None:
            return
        self.agent.stop()
        for _ in range(20):
            if not self._is_running():
                break
            time.sleep(0.2)

    @staticmethod
    def _resolve_dashboard_url(api_url: str) -> str:
        base = (api_url or DEFAULT_BACKEND).rstrip("/")
        lowered = base.lower()
        if lowered.endswith(":8000"):
            return f"{base[:-5]}:3000"
        return base

    def open_dashboard(self):
        config = load_config() or {}
        api_url = config.get("api_url", DEFAULT_BACKEND)
        dashboard_url = self._resolve_dashboard_url(api_url) or DEFAULT_DASHBOARD
        webbrowser.open(dashboard_url)
        self._set_action("Dashboard opened")

    def view_logs(self):
        if not LOG_FILE.exists():
            LOG_FILE.touch()
        try:
            os.startfile(str(LOG_FILE))
        except Exception:
            self._show_message(APP_NAME, f"Log file: {LOG_FILE}")
        self._set_action("Logs opened")

    def exit_app(self):
        try:
            self._stop_monitoring_silent()
        except Exception:
            pass
        if self.icon:
            self.icon.stop()
        if self.root is not None:
            try:
                self.root.destroy()
            except Exception:
                pass

    def check_for_updates(self):
        """Manual 'Check for Updates' handler from tray menu."""
        def _do_check():
            info = self.updater.check_for_update()
            if info is None:
                self._show_message(APP_NAME, f"You are running the latest version (v{CURRENT_VERSION}).")
                self._set_action("No updates available")
                return

            remote_ver = info.get('agent_version', '?')
            if messagebox is not None:
                try:
                    root = tk.Tk()
                    root.withdraw()
                    do_update = messagebox.askyesno(
                        APP_NAME,
                        f"A new version (v{remote_ver}) is available.\n"
                        f"Current version: v{CURRENT_VERSION}\n\n"
                        "Download and install now?"
                    )
                    root.destroy()
                    if not do_update:
                        return
                except Exception:
                    pass

            new_exe = self.updater.download_update(
                info.get("download_url", "/api/agent/download"),
                info.get("checksum"),
            )
            if new_exe:
                self._pending_update = new_exe
                self.updater.apply_update(new_exe)
            else:
                self._show_message(APP_NAME, "Update download failed. Please try again later.")
                self._set_action("Update failed")

        threading.Thread(target=_do_check, daemon=True).start()

    def _build_tray_menu(self):
        return pystray.Menu(
            Item(self._menu_status_text, None, enabled=False),
            Item("Show Window", lambda icon, item: self._run_on_ui(self._show_window)),
            Item("Start Monitoring", lambda icon, item: self._run_on_ui(self.start_monitoring)),
            Item("Stop Monitoring", lambda icon, item: self._run_on_ui(self.stop_monitoring)),
            Item("Open Dashboard", lambda icon, item: self._run_on_ui(self.open_dashboard)),
            Item("Configure", lambda icon, item: self._run_on_ui(self.open_setup)),
            Item("Check for Updates", lambda icon, item: self._run_on_ui(self.check_for_updates)),
            Item("View Logs", lambda icon, item: self._run_on_ui(self.view_logs)),
            Item("Exit", lambda icon, item: self._run_on_ui(self.exit_app)),
        )

    def _start_tray(self):
        if pystray is None:
            return
        if self.icon is None:
            self.icon = pystray.Icon(APP_NAME, self._create_icon(), APP_NAME, self._build_tray_menu())
            threading.Thread(target=self.icon.run, daemon=True).start()

    def run(self):
        if pystray is None:
            self._show_message(APP_NAME, "pystray and Pillow are required for tray mode.")
            return

        self._set_high_priority()

        # Start background auto-update checker
        self.updater.start_background_checker()

        self._build_main_window()
        self._start_tray()
        if self.root is not None:
            self.root.mainloop()


def main():
    app = AgentTrayApp()
    app.run()


if __name__ == "__main__":
    main()
