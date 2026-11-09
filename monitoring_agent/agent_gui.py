"""Windows tray application and endpoint security console for CryptoDetect v1.0."""

import ctypes
import json
import logging
import os
import platform
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

import psutil
import requests

try:
    import tkinter as tk
    from tkinter import messagebox
except Exception:  # pragma: no cover
    tk = None
    messagebox = None

try:
    import pystray
    from pystray import MenuItem as Item
    from PIL import Image, ImageDraw, ImageTk
except Exception:  # pragma: no cover
    pystray = None
    Item = None
    Image = None
    ImageDraw = None
    ImageTk = None

from enhanced_agent import MonitoringAgent, load_config, save_config
from auto_updater import AutoUpdater, CURRENT_VERSION


APP_NAME = "CryptoDetect Agent"
WINDOW_TITLE = f"{APP_NAME} v{CURRENT_VERSION}"
DEFAULT_BACKEND = "http://localhost:8000"
DEFAULT_DASHBOARD = "http://localhost:3000"
LOG_DIR = Path.home() / ".cryptodetect"
LOG_FILE = LOG_DIR / "agent_gui.log"
LOCK_FILE = LOG_DIR / "agent_gui.lock"

SINGLE_INSTANCE_MUTEX_NAME = "Local\\CryptoDetect_Agent_SingleInstance_Mutex_v1"
WAKEUP_EVENT_NAME = "Local\\CryptoDetect_Agent_Wakeup_Event_v1"
ERROR_ALREADY_EXISTS = 183
WAIT_OBJECT_0 = 0

# Dark Slate Security Console Palette (matches Web UI Dark Theme)
PALETTE = {
    "bg_window": "#090d16",
    "bg_card": "#0f172a",
    "bg_elevated": "#162033",
    "bg_input": "#090d16",
    "border": "#1e293b",
    "border_subtle": "#26354d",
    "border_focus": "#3b82f6",
    "text_primary": "#f8fafc",
    "text_secondary": "#94a3b8",
    "text_muted": "#64748b",
    "primary": "#2563eb",
    "primary_hover": "#3b82f6",
    "accent_cyan": "#38bdf8",
    "success": "#10b981",
    "success_bg": "#064e3b",
    "success_border": "#059669",
    "warning": "#f59e0b",
    "danger": "#ef4444",
    "danger_hover": "#dc2626",
    "btn_secondary": "#162033",
    "btn_secondary_hover": "#1e293b",
}

LOG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


def _enable_dpi_awareness():
    """Enable Windows High-DPI awareness so fonts render crisply without blurry bitmap stretching."""
    if os.name != "nt" or ctypes is None:
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def _focus_existing_window():
    """Bring the existing CryptoDetect Agent window to the foreground if visible."""
    if os.name != "nt" or ctypes is None:
        return
    try:
        user32 = ctypes.windll.user32
        hwnd = user32.FindWindowW(None, WINDOW_TITLE)
        if hwnd:
            SW_RESTORE = 9
            user32.ShowWindow(hwnd, SW_RESTORE)
            user32.SetForegroundWindow(hwnd)
    except Exception:
        pass


class SingleInstanceGuard:
    """Prevents multiple agent GUI processes from running simultaneously and signals the primary instance."""

    def __init__(self):
        self.mutex_handle = None
        self.event_handle = None
        self.lock_fp = None
        self.is_primary = False

    def acquire(self) -> bool:
        if os.name == "nt" and ctypes is not None:
            try:
                kernel32 = ctypes.windll.kernel32
                self.event_handle = kernel32.CreateEventW(None, True, False, WAKEUP_EVENT_NAME)
                self.mutex_handle = kernel32.CreateMutexW(None, False, SINGLE_INSTANCE_MUTEX_NAME)
                last_err = kernel32.GetLastError()
                if last_err == ERROR_ALREADY_EXISTS:
                    if self.event_handle:
                        kernel32.SetEvent(self.event_handle)
                    _focus_existing_window()
                    return False
                self.is_primary = True
                return True
            except Exception as exc:
                logging.warning("Mutex guard fallback triggered: %s", exc)

        # Fallback file lock
        try:
            import msvcrt

            self.lock_fp = open(LOCK_FILE, "w")
            msvcrt.locking(self.lock_fp.fileno(), msvcrt.LK_NBLCK, 1)
            self.lock_fp.write(str(os.getpid()))
            self.lock_fp.flush()
            self.is_primary = True
            return True
        except Exception:
            _focus_existing_window()
            return False

    def check_wakeup_signal(self) -> bool:
        """Return True if a second launch requested this primary instance to show its window."""
        if os.name == "nt" and ctypes is not None and self.event_handle:
            try:
                kernel32 = ctypes.windll.kernel32
                res = kernel32.WaitForSingleObject(self.event_handle, 0)
                if res == WAIT_OBJECT_0:
                    kernel32.ResetEvent(self.event_handle)
                    return True
            except Exception:
                pass
        return False

    def release(self):
        if os.name == "nt" and ctypes is not None:
            try:
                kernel32 = ctypes.windll.kernel32
                if self.mutex_handle:
                    kernel32.CloseHandle(self.mutex_handle)
                    self.mutex_handle = None
                if self.event_handle:
                    kernel32.CloseHandle(self.event_handle)
                    self.event_handle = None
            except Exception:
                pass
        if self.lock_fp is not None:
            try:
                self.lock_fp.close()
            except Exception:
                pass
            self.lock_fp = None


def create_shield_icon(size: int = 64):
    """Render an anti-aliased shield + telemetry pulse icon via 4x supersampling."""
    if Image is None or ImageDraw is None:
        return None

    scale = 4
    canvas_size = size * scale
    img = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Outer rounded slate badge
    pad = int(canvas_size * 0.06)
    radius = int(canvas_size * 0.22)
    draw.rounded_rectangle(
        (pad, pad, canvas_size - pad, canvas_size - pad),
        radius=radius,
        fill=(15, 23, 42, 255),
        outline=(59, 130, 246, 255),
        width=max(2, int(canvas_size * 0.045)),
    )

    # Shield polygon inside badge
    cx = canvas_size // 2
    top_y = int(canvas_size * 0.20)
    side_y = int(canvas_size * 0.30)
    mid_y = int(canvas_size * 0.56)
    bot_y = int(canvas_size * 0.80)
    half_w = int(canvas_size * 0.27)

    shield_pts = [
        (cx, top_y),
        (cx + half_w, side_y),
        (cx + int(half_w * 0.82), mid_y),
        (cx, bot_y),
        (cx - int(half_w * 0.82), mid_y),
        (cx - half_w, side_y),
    ]
    draw.polygon(
        shield_pts,
        fill=(30, 58, 138, 130),
        outline=(59, 130, 246, 255),
    )

    # Telemetry pulse line across the shield
    pulse_y = int(canvas_size * 0.50)
    pulse_pts = [
        (cx - int(half_w * 0.58), pulse_y),
        (cx - int(half_w * 0.22), pulse_y),
        (cx - int(half_w * 0.08), pulse_y - int(canvas_size * 0.12)),
        (cx + int(half_w * 0.10), pulse_y + int(canvas_size * 0.11)),
        (cx + int(half_w * 0.24), pulse_y),
        (cx + int(half_w * 0.58), pulse_y),
    ]
    draw.line(pulse_pts, fill=(56, 189, 248, 255), width=max(2, int(canvas_size * 0.055)))

    resample_filter = getattr(getattr(Image, "Resampling", Image), "LANCZOS", Image.BICUBIC)
    return img.resize((size, size), resample=resample_filter)


def _mask_api_key(raw_key: str) -> str:
    if not raw_key:
        return "Not configured"
    cleaned = str(raw_key).strip()
    if len(cleaned) <= 4:
        return "••••••••••••"
    return f"••••••••••••{cleaned[-4:]}"


def _fit_and_center_window(window, min_width: int = 580, extra_height: int = 12):
    """Measure the exact DPI-scaled child widget bounds and size/center the window so nothing clips."""
    window.update_idletasks()
    req_w = max(min_width, window.winfo_reqwidth() + 8)
    req_h = window.winfo_reqheight() + extra_height
    screen_w = window.winfo_screenwidth()
    screen_h = window.winfo_screenheight()
    pos_x = max(20, (screen_w - req_w) // 2)
    pos_y = max(20, (screen_h - req_h) // 2)
    window.geometry(f"{req_w}x{req_h}+{pos_x}+{pos_y}")
    window.minsize(req_w, req_h)


class AgentTrayApp:
    def __init__(self):
        _enable_dpi_awareness()
        self.instance_guard = SingleInstanceGuard()
        self.config = load_config() or {}
        self.agent = None
        self.agent_thread = None
        self.icon = None
        self.root = None
        self.setup_window = None
        self._window_icon_photo = None
        self._header_logo_photo = None
        self.status_var = None
        self.action_var = None
        self.system_id_var = None
        self.api_key_masked_var = None
        self.api_url_var = None
        self.cpu_var = None
        self.mem_var = None
        self.queue_var = None
        self.status_pill_label = None
        self.cpu_bar_canvas = None
        self.cpu_bar_fill = None
        self.mem_bar_canvas = None
        self.mem_bar_fill = None
        self._pending_update = None

        AutoUpdater.cleanup_old_binary()

        api_url = self.config.get("api_url", DEFAULT_BACKEND)
        self.updater = AutoUpdater(api_url, on_status=lambda msg: logging.info(msg))

    def _create_icon(self, size: int = 64):
        return create_shield_icon(size=size)

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
        if messagebox is not None and self.root is not None:
            try:
                messagebox.showinfo(title, body, parent=self.root)
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
            try:
                self.action_var.set(message)
            except Exception:
                pass

    def _menu_status_text(self, _item=None):
        return "Status: Running" if self._is_running() else "Status: Stopped"

    def _status_label_text(self):
        if not self.config:
            return "○ UNCONFIGURED"
        return "● ACTIVE" if self._is_running() else "○ STOPPED"

    def _refresh_config_labels(self):
        cfg = self.config or {}
        if self.system_id_var is not None:
            self.system_id_var.set(cfg.get("system_id") or "Not configured")
        if self.api_key_masked_var is not None:
            self.api_key_masked_var.set(_mask_api_key(cfg.get("api_key", "")))
        if self.api_url_var is not None:
            self.api_url_var.set(cfg.get("api_url") or DEFAULT_BACKEND)
        if self.status_var is not None:
            self.status_var.set(self._status_label_text())
        if self.status_pill_label is not None:
            running = self._is_running()
            self.status_pill_label.config(
                bg=PALETTE["success_bg"] if running else PALETTE["bg_elevated"],
                fg=PALETTE["success"] if running else PALETTE["text_secondary"],
                highlightbackground=PALETTE["success_border"] if running else PALETTE["border_subtle"],
            )

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
        try:
            self.root.deiconify()
            self.root.state("normal")
            self.root.lift()
            self.root.focus_force()
        except Exception:
            pass

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
        self._set_action("Minimized to system tray")

    def _make_flat_button(self, parent, text, command, variant="secondary", width=None, padx=14, pady=8):
        bg_map = {
            "primary": (PALETTE["primary"], PALETTE["primary_hover"], "#ffffff", PALETTE["border_focus"]),
            "danger": (PALETTE["bg_elevated"], PALETTE["danger_hover"], "#fca5a5", "#7f1d1d"),
            "secondary": (PALETTE["btn_secondary"], PALETTE["btn_secondary_hover"], PALETTE["text_primary"], PALETTE["border_subtle"]),
        }
        bg, hover_bg, fg, border_col = bg_map.get(variant, bg_map["secondary"])
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=hover_bg,
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            padx=padx,
            pady=pady,
            cursor="hand2",
            font=("Segoe UI", 9, "bold"),
            highlightthickness=1,
            highlightbackground=border_col,
            highlightcolor=PALETTE["border_focus"],
        )
        if width is not None:
            btn.config(width=width)
        btn.bind("<Enter>", lambda _e: btn.config(bg=hover_bg))
        btn.bind("<Leave>", lambda _e: btn.config(bg=bg))
        return btn

    def _update_live_telemetry(self):
        if self.root is None:
            return
        try:
            # Check if a second .exe click signaled us to restore the window
            if self.instance_guard.check_wakeup_signal():
                self._show_window()
                self._set_action("Window restored (single-instance guard)")

            cpu_pct = psutil.cpu_percent(interval=None)
            mem_pct = psutil.virtual_memory().percent
            if self.cpu_var is not None:
                self.cpu_var.set(f"{cpu_pct:4.1f}%")
            if self.mem_var is not None:
                self.mem_var.set(f"{mem_pct:4.1f}%")

            if self.cpu_bar_canvas is not None and self.cpu_bar_fill is not None:
                bar_w = max(120, self.cpu_bar_canvas.winfo_width())
                w = max(3, int((min(100.0, cpu_pct) / 100.0) * bar_w))
                self.cpu_bar_canvas.coords(self.cpu_bar_fill, 0, 0, w, 6)
            if self.mem_bar_canvas is not None and self.mem_bar_fill is not None:
                bar_w = max(120, self.mem_bar_canvas.winfo_width())
                w = max(3, int((min(100.0, mem_pct) / 100.0) * bar_w))
                self.mem_bar_canvas.coords(self.mem_bar_fill, 0, 0, w, 6)

            if self.queue_var is not None:
                pending_count = 0
                if self.agent is not None and hasattr(self.agent, "_pending_lock"):
                    try:
                        with self.agent._pending_lock:
                            pending_count = len(getattr(self.agent, "pending", []))
                    except Exception:
                        pending_count = 0
                self.queue_var.set(f"{pending_count} / 60")

            self._refresh_config_labels()
        except Exception:
            pass
        finally:
            try:
                self.root.after(1500, self._update_live_telemetry)
            except Exception:
                pass

    def _build_main_window(self):
        if tk is None:
            self._show_message(APP_NAME, "Tkinter is unavailable. Please install it or run tray-only mode.")
            return

        self.root = tk.Tk()
        self.root.title(WINDOW_TITLE)
        self.root.configure(bg=PALETTE["bg_window"])
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.bind("<Unmap>", self._on_minimize)

        # Apply anti-aliased shield icon to window titlebar
        if ImageTk is not None:
            try:
                icon_img = self._create_icon(32)
                if icon_img is not None:
                    self._window_icon_photo = ImageTk.PhotoImage(icon_img)
                    self.root.iconphoto(True, self._window_icon_photo)
            except Exception:
                pass

        self.status_var = tk.StringVar(value=self._status_label_text())
        self.action_var = tk.StringVar(value="Ready · 5s Poll / 30s Batch Pipeline")
        self.system_id_var = tk.StringVar(value=self.config.get("system_id") or "Not configured")
        self.api_key_masked_var = tk.StringVar(value=_mask_api_key(self.config.get("api_key", "")))
        self.api_url_var = tk.StringVar(value=self.config.get("api_url") or DEFAULT_BACKEND)
        self.cpu_var = tk.StringVar(value="0.0%")
        self.mem_var = tk.StringVar(value="0.0%")
        self.queue_var = tk.StringVar(value="0 / 60")

        outer = tk.Frame(self.root, bg=PALETTE["bg_window"], padx=18, pady=16)
        outer.pack(fill="both", expand=True)

        # ── 1. Top Header Bar ───────────────────────────────────────────
        header = tk.Frame(
            outer,
            bg=PALETTE["bg_card"],
            padx=16,
            pady=14,
            highlightthickness=1,
            highlightbackground=PALETTE["border"],
        )
        header.pack(fill="x", pady=(0, 12))

        header_left = tk.Frame(header, bg=PALETTE["bg_card"])
        header_left.pack(side="left", fill="y")

        if ImageTk is not None:
            logo_img = self._create_icon(42)
            if logo_img is not None:
                self._header_logo_photo = ImageTk.PhotoImage(logo_img)
                tk.Label(
                    header_left,
                    image=self._header_logo_photo,
                    bg=PALETTE["bg_card"],
                    bd=0,
                ).pack(side="left", padx=(0, 12))

        title_box = tk.Frame(header_left, bg=PALETTE["bg_card"])
        title_box.pack(side="left")
        tk.Label(
            title_box,
            text="CryptoDetect Endpoint Agent",
            font=("Segoe UI", 12, "bold"),
            fg=PALETTE["text_primary"],
            bg=PALETTE["bg_card"],
        ).pack(anchor="w")
        host_label = platform.node() or "Local-Host"
        tk.Label(
            title_box,
            text=f"v{CURRENT_VERSION} · SHA-256 Verified · {host_label}",
            font=("Segoe UI", 8),
            fg=PALETTE["text_secondary"],
            bg=PALETTE["bg_card"],
        ).pack(anchor="w", pady=(2, 0))

        self.status_pill_label = tk.Label(
            header,
            textvariable=self.status_var,
            font=("Consolas", 9, "bold"),
            padx=12,
            pady=5,
            bg=PALETTE["bg_elevated"],
            fg=PALETTE["text_secondary"],
            highlightthickness=1,
            highlightbackground=PALETTE["border_subtle"],
        )
        self.status_pill_label.pack(side="right", padx=(16, 0))

        # ── 2. Live Host Telemetry Strip (3 Uniform Columns) ────────────
        telemetry_row = tk.Frame(outer, bg=PALETTE["bg_window"])
        telemetry_row.pack(fill="x", pady=(0, 12))
        telemetry_row.columnconfigure(0, weight=1, uniform="telemetry")
        telemetry_row.columnconfigure(1, weight=1, uniform="telemetry")
        telemetry_row.columnconfigure(2, weight=1, uniform="telemetry")

        # CPU Card
        cpu_card = tk.Frame(
            telemetry_row,
            bg=PALETTE["bg_card"],
            padx=14,
            pady=12,
            highlightthickness=1,
            highlightbackground=PALETTE["border"],
        )
        cpu_card.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        tk.Label(cpu_card, text="HOST CPU", font=("Segoe UI", 8, "bold"), fg=PALETTE["text_muted"], bg=PALETTE["bg_card"]).pack(anchor="w")
        tk.Label(cpu_card, textvariable=self.cpu_var, font=("Consolas", 15, "bold"), fg=PALETTE["text_primary"], bg=PALETTE["bg_card"]).pack(anchor="w", pady=(4, 8))
        self.cpu_bar_canvas = tk.Canvas(cpu_card, height=6, bg=PALETTE["bg_elevated"], highlightthickness=0)
        self.cpu_bar_canvas.pack(fill="x")
        self.cpu_bar_fill = self.cpu_bar_canvas.create_rectangle(0, 0, 4, 6, fill=PALETTE["primary_hover"], width=0)

        # Memory Card
        mem_card = tk.Frame(
            telemetry_row,
            bg=PALETTE["bg_card"],
            padx=14,
            pady=12,
            highlightthickness=1,
            highlightbackground=PALETTE["border"],
        )
        mem_card.grid(row=0, column=1, sticky="nsew", padx=6)
        tk.Label(mem_card, text="HOST MEMORY", font=("Segoe UI", 8, "bold"), fg=PALETTE["text_muted"], bg=PALETTE["bg_card"]).pack(anchor="w")
        tk.Label(mem_card, textvariable=self.mem_var, font=("Consolas", 15, "bold"), fg=PALETTE["text_primary"], bg=PALETTE["bg_card"]).pack(anchor="w", pady=(4, 8))
        self.mem_bar_canvas = tk.Canvas(mem_card, height=6, bg=PALETTE["bg_elevated"], highlightthickness=0)
        self.mem_bar_canvas.pack(fill="x")
        self.mem_bar_fill = self.mem_bar_canvas.create_rectangle(0, 0, 4, 6, fill=PALETTE["success"], width=0)

        # Retry Queue Card
        q_card = tk.Frame(
            telemetry_row,
            bg=PALETTE["bg_card"],
            padx=14,
            pady=12,
            highlightthickness=1,
            highlightbackground=PALETTE["border"],
        )
        q_card.grid(row=0, column=2, sticky="nsew", padx=(6, 0))
        tk.Label(q_card, text="RETRY QUEUE", font=("Segoe UI", 8, "bold"), fg=PALETTE["text_muted"], bg=PALETTE["bg_card"]).pack(anchor="w")
        tk.Label(q_card, textvariable=self.queue_var, font=("Consolas", 15, "bold"), fg=PALETTE["accent_cyan"], bg=PALETTE["bg_card"]).pack(anchor="w", pady=(4, 4))
        tk.Label(q_card, text="Disk-backed FIFO", font=("Segoe UI", 8), fg=PALETTE["text_secondary"], bg=PALETTE["bg_card"]).pack(anchor="w")

        # ── 3. Endpoint Identity & Configuration Card ───────────────────
        config_card = tk.Frame(
            outer,
            bg=PALETTE["bg_card"],
            padx=16,
            pady=14,
            highlightthickness=1,
            highlightbackground=PALETTE["border"],
        )
        config_card.pack(fill="x", pady=(0, 12))

        tk.Label(
            config_card,
            text="ENDPOINT CONFIGURATION & CREDENTIALS",
            font=("Segoe UI", 8, "bold"),
            fg=PALETTE["text_muted"],
            bg=PALETTE["bg_card"],
        ).pack(anchor="w", pady=(0, 8))

        spec_grid = tk.Frame(config_card, bg=PALETTE["bg_card"])
        spec_grid.pack(fill="x")
        spec_grid.columnconfigure(1, weight=1)

        def _add_spec_row(row_idx, label_text, var_obj):
            tk.Label(
                spec_grid,
                text=label_text,
                font=("Segoe UI", 9),
                fg=PALETTE["text_secondary"],
                bg=PALETTE["bg_card"],
                anchor="w",
            ).grid(row=row_idx, column=0, sticky="w", padx=(0, 18), pady=3)
            tk.Label(
                spec_grid,
                textvariable=var_obj,
                font=("Consolas", 9, "bold"),
                fg=PALETTE["text_primary"],
                bg=PALETTE["bg_card"],
                anchor="w",
            ).grid(row=row_idx, column=1, sticky="w", pady=3)

        _add_spec_row(0, "System ID:", self.system_id_var)
        _add_spec_row(1, "API Key:", self.api_key_masked_var)
        _add_spec_row(2, "Backend Endpoint:", self.api_url_var)

        # ── 4. Action Control Grid (2 Uniform Columns) ──────────────────
        controls_card = tk.Frame(
            outer,
            bg=PALETTE["bg_card"],
            padx=16,
            pady=14,
            highlightthickness=1,
            highlightbackground=PALETTE["border"],
        )
        controls_card.pack(fill="x", pady=(0, 12))
        controls_card.columnconfigure(0, weight=1, uniform="actions")
        controls_card.columnconfigure(1, weight=1, uniform="actions")

        self._make_flat_button(controls_card, "Start Monitoring", self.start_monitoring, variant="primary").grid(
            row=0, column=0, sticky="ew", padx=(0, 6), pady=4
        )
        self._make_flat_button(controls_card, "Stop Monitoring", self.stop_monitoring, variant="danger").grid(
            row=0, column=1, sticky="ew", padx=(6, 0), pady=4
        )
        self._make_flat_button(controls_card, "Open Web Console", self.open_dashboard, variant="secondary").grid(
            row=1, column=0, sticky="ew", padx=(0, 6), pady=4
        )
        self._make_flat_button(controls_card, "Configure Credentials", self.open_setup, variant="secondary").grid(
            row=1, column=1, sticky="ew", padx=(6, 0), pady=4
        )
        self._make_flat_button(controls_card, "View Agent Logs", self.view_logs, variant="secondary").grid(
            row=2, column=0, sticky="ew", padx=(0, 6), pady=4
        )
        self._make_flat_button(controls_card, "Check for Updates", self.check_for_updates, variant="secondary").grid(
            row=2, column=1, sticky="ew", padx=(6, 0), pady=4
        )

        # ── 5. Footer Status & Window Controls Bar ──────────────────────
        footer = tk.Frame(outer, bg=PALETTE["bg_window"])
        footer.pack(fill="x", pady=(2, 0))

        tk.Label(
            footer,
            textvariable=self.action_var,
            font=("Segoe UI", 8),
            fg=PALETTE["text_secondary"],
            bg=PALETTE["bg_window"],
            anchor="w",
        ).pack(side="left", fill="x", expand=True)

        self._make_flat_button(footer, "Exit Agent", self.exit_app, variant="danger", padx=12, pady=5).pack(side="right")
        self._make_flat_button(footer, "Hide to Tray", self._on_close, variant="secondary", padx=12, pady=5).pack(
            side="right", padx=(0, 8)
        )

        # Fit window dynamically to exact DPI-scaled widget bounds so nothing is ever cut off
        _fit_and_center_window(self.root, min_width=600, extra_height=8)

        # Kick off live host telemetry & single-instance wakeup listener
        psutil.cpu_percent(interval=None)
        self.root.after(300, self._update_live_telemetry)

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
            self._refresh_config_labels()
            self._show_message(APP_NAME, "Configuration saved.")
        except Exception as exc:
            self._show_message(APP_NAME, f"Configure failed: {exc}")

    def _open_setup_window(self):
        if tk is None:
            self._prompt_setup_via_powershell()
            return

        if self.setup_window is not None:
            try:
                if self.setup_window.winfo_exists():
                    self.setup_window.lift()
                    self.setup_window.focus_force()
                    return
            except Exception:
                self.setup_window = None

        cfg = self.config or {}
        standalone_root = False
        if self.root is not None:
            window = tk.Toplevel(self.root)
            window.transient(self.root)
        else:
            window = tk.Tk()
            standalone_root = True

        self.setup_window = window
        window.title("Configure Endpoint Credentials")
        window.configure(bg=PALETTE["bg_window"])
        window.resizable(False, False)

        container = tk.Frame(
            window,
            bg=PALETTE["bg_card"],
            padx=20,
            pady=18,
            highlightthickness=1,
            highlightbackground=PALETTE["border"],
        )
        container.pack(fill="both", expand=True, padx=16, pady=16)

        tk.Label(
            container,
            text="Endpoint Credential Setup",
            font=("Segoe UI", 11, "bold"),
            fg=PALETTE["text_primary"],
            bg=PALETTE["bg_card"],
        ).pack(anchor="w")
        tk.Label(
            container,
            text="Bind this host to your CryptoDetect operator account.",
            font=("Segoe UI", 8),
            fg=PALETTE["text_secondary"],
            bg=PALETTE["bg_card"],
        ).pack(anchor="w", pady=(2, 14))

        tk.Label(
            container,
            text="SYSTEM ID",
            font=("Segoe UI", 8, "bold"),
            fg=PALETTE["text_muted"],
            bg=PALETTE["bg_card"],
        ).pack(anchor="w")
        system_id_var = tk.StringVar(value=cfg.get("system_id", ""))
        sid_entry = tk.Entry(
            container,
            textvariable=system_id_var,
            font=("Consolas", 10),
            bg=PALETTE["bg_input"],
            fg=PALETTE["text_primary"],
            insertbackground=PALETTE["primary_hover"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=PALETTE["border_subtle"],
            highlightcolor=PALETTE["border_focus"],
        )
        sid_entry.pack(fill="x", pady=(4, 12), ipady=6)

        tk.Label(
            container,
            text="ENDPOINT API KEY",
            font=("Segoe UI", 8, "bold"),
            fg=PALETTE["text_muted"],
            bg=PALETTE["bg_card"],
        ).pack(anchor="w")
        key_row = tk.Frame(container, bg=PALETTE["bg_card"])
        key_row.pack(fill="x", pady=(4, 12))

        api_key_var = tk.StringVar(value=cfg.get("api_key", ""))
        show_key_state = {"visible": False}
        key_entry = tk.Entry(
            key_row,
            textvariable=api_key_var,
            show="•",
            font=("Consolas", 10),
            bg=PALETTE["bg_input"],
            fg=PALETTE["text_primary"],
            insertbackground=PALETTE["primary_hover"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=PALETTE["border_subtle"],
            highlightcolor=PALETTE["border_focus"],
        )
        key_entry.pack(side="left", fill="x", expand=True, ipady=6)

        def toggle_key_visibility():
            show_key_state["visible"] = not show_key_state["visible"]
            key_entry.config(show="" if show_key_state["visible"] else "•")
            toggle_btn.config(text="Hide" if show_key_state["visible"] else "Show")

        toggle_btn = self._make_flat_button(key_row, "Show", toggle_key_visibility, variant="secondary", width=6, pady=6)
        toggle_btn.pack(side="left", padx=(8, 0))

        tk.Label(
            container,
            text="BACKEND API URL",
            font=("Segoe UI", 8, "bold"),
            fg=PALETTE["text_muted"],
            bg=PALETTE["bg_card"],
        ).pack(anchor="w")
        api_url_var = tk.StringVar(value=cfg.get("api_url", DEFAULT_BACKEND))
        url_entry = tk.Entry(
            container,
            textvariable=api_url_var,
            font=("Consolas", 10),
            bg=PALETTE["bg_input"],
            fg=PALETTE["text_primary"],
            insertbackground=PALETTE["primary_hover"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=PALETTE["border_subtle"],
            highlightcolor=PALETTE["border_focus"],
        )
        url_entry.pack(fill="x", pady=(4, 10), ipady=6)

        status_label = tk.Label(
            container,
            text="",
            font=("Segoe UI", 8, "bold"),
            fg=PALETTE["danger"],
            bg=PALETTE["bg_card"],
        )
        status_label.pack(anchor="w", pady=(2, 10))

        def save_and_close(start_after=False):
            system_id = system_id_var.get().strip()
            api_key = api_key_var.get().strip()
            api_url = api_url_var.get().strip() or DEFAULT_BACKEND

            status_label.config(text="Validating credentials with backend...", fg=PALETTE["accent_cyan"])
            window.update_idletasks()

            ok, reason = self._validate_setup(system_id, api_key, api_url)
            if not ok:
                status_label.config(text=reason, fg=PALETTE["danger"])
                return

            save_config(system_id, api_key, api_url)
            self.config = {"system_id": system_id, "api_key": api_key, "api_url": api_url}
            self._refresh_config_labels()
            logging.info("Configuration updated for system %s", system_id)

            was_running = self._is_running()
            if was_running:
                self._stop_monitoring_silent()

            self.setup_window = None
            window.destroy()

            if start_after or was_running:
                self.start_monitoring()

        button_frame = tk.Frame(container, bg=PALETTE["bg_card"])
        button_frame.pack(fill="x", pady=(4, 0))

        self._make_flat_button(button_frame, "Save & Start", lambda: save_and_close(True), variant="primary").pack(side="left")
        self._make_flat_button(button_frame, "Save Only", lambda: save_and_close(False), variant="secondary").pack(
            side="left", padx=8
        )
        self._make_flat_button(button_frame, "Cancel", window.destroy, variant="secondary").pack(side="right")

        _fit_and_center_window(window, min_width=520, extra_height=8)

        if standalone_root:
            window.mainloop()

    def open_setup(self):
        if self.root is not None:
            self._run_on_ui(self._open_setup_window)
        else:
            threading.Thread(target=self._open_setup_window, daemon=True).start()

    def start_monitoring(self):
        if self._is_running():
            self._show_message(APP_NAME, "Monitoring is already running.")
            self._set_action("Monitoring already active")
            return

        config = load_config() or {}
        system_id = config.get("system_id")
        api_key = config.get("api_key")
        api_url = config.get("api_url", DEFAULT_BACKEND)

        if not system_id or not api_key:
            self._show_message(APP_NAME, "Configuration is missing. Open Configure Credentials first.")
            self._set_action("Configuration required")
            self.open_setup()
            return

        ok, reason = self._validate_setup(system_id, api_key, api_url)
        if not ok:
            self._show_message(APP_NAME, f"Unable to start monitoring: {reason}")
            self._set_action(f"Start failed: {reason}")
            return

        self.config = config
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
        self._refresh_config_labels()
        self._set_action("Monitoring active · 5s collection / 30s batch upload")
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

        self._refresh_config_labels()
        self._set_action("Monitoring stopped by operator")
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
        self._set_action("Opened web console in browser")

    def view_logs(self):
        if not LOG_FILE.exists():
            LOG_FILE.touch()
        try:
            os.startfile(str(LOG_FILE))
        except Exception:
            self._show_message(APP_NAME, f"Log file: {LOG_FILE}")
        self._set_action("Opened agent log file")

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
        self.instance_guard.release()

    def check_for_updates(self):
        """Manual 'Check for Updates' handler."""
        self._set_action("Checking backend for signed agent updates...")

        def _do_check():
            info = self.updater.check_for_update()
            if info is None:
                self._show_message(APP_NAME, f"You are running the latest version (v{CURRENT_VERSION}).")
                self._set_action(f"Up to date (v{CURRENT_VERSION})")
                return

            remote_ver = info.get("agent_version", "?")
            if messagebox is not None and self.root is not None:
                try:
                    do_update = messagebox.askyesno(
                        APP_NAME,
                        f"A new version (v{remote_ver}) is available.\n"
                        f"Current version: v{CURRENT_VERSION}\n\n"
                        "Download and verify SHA-256 update now?",
                        parent=self.root,
                    )
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
                self._show_message(APP_NAME, "Update download or SHA-256 verification failed.")
                self._set_action("Update verification failed")

        threading.Thread(target=_do_check, daemon=True).start()

    def _build_tray_menu(self):
        return pystray.Menu(
            Item(self._menu_status_text, None, enabled=False),
            Item("Open Console", lambda icon, item: self._run_on_ui(self._show_window), default=True),
            Item("Start Monitoring", lambda icon, item: self._run_on_ui(self.start_monitoring)),
            Item("Stop Monitoring", lambda icon, item: self._run_on_ui(self.stop_monitoring)),
            Item("Open Web Dashboard", lambda icon, item: self._run_on_ui(self.open_dashboard)),
            Item("Configure Credentials", lambda icon, item: self._run_on_ui(self.open_setup)),
            Item("Check for Updates", lambda icon, item: self._run_on_ui(self.check_for_updates)),
            Item("View Logs", lambda icon, item: self._run_on_ui(self.view_logs)),
            Item("Exit", lambda icon, item: self._run_on_ui(self.exit_app)),
        )

    def _start_tray(self):
        if pystray is None:
            return
        if self.icon is None:
            self.icon = pystray.Icon(APP_NAME, self._create_icon(64), APP_NAME, self._build_tray_menu())
            threading.Thread(target=self.icon.run, daemon=True).start()

    def run(self):
        # Single-instance check: if already running, signal the existing window to open and exit immediately
        if not self.instance_guard.acquire():
            logging.info("Another instance of %s is already running; restored existing window and exiting.", APP_NAME)
            return

        if pystray is None:
            self._show_message(APP_NAME, "pystray and Pillow are required for tray mode.")
            self.instance_guard.release()
            return

        self._set_high_priority()
        self.updater.start_background_checker()

        try:
            self._build_main_window()
            self._start_tray()
            if self.root is not None:
                self.root.mainloop()
        finally:
            self.instance_guard.release()


def main():
    app = AgentTrayApp()
    app.run()


if __name__ == "__main__":
    main()
