#!/usr/bin/env python3
"""FRP TOOL - desktop GUI (Tkinter front-end for frp_portal.py).

What the window offers:

    * Wi-Fi name (SSID) and password fields
    * Start / Stop buttons for the hotspot + captive portal
    * an "Android DNS probe dance" switch (the Android 14+ popup fix)
    * a live log pane fed by the portal's own console output

The portal runs in a worker thread, so the window stays responsive and Stop
reuses the normal shutdown path (firewall rules removed, hotspot stopped,
DNS/HTTP servers closed). Pressing Start without Administrator rights asks for
UAC, restarts the GUI elevated and starts the portal with the same settings.

Only the Python standard library is used. The packaged build (see
build_exe.bat / INSTALL.md) contains its own interpreter, so the target PC
needs neither Python nor pip.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

if getattr(sys, "frozen", False):
    ROOT = Path(sys.executable).resolve().parent
else:
    ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import frp_portal                       # noqa: E402
from core import windows                # noqa: E402

CONFIG_PATH = "config.json"
FINISHED = object()                     # log-queue sentinel: portal thread gone

# Windows 11 lets the hotspot choose its own band and often picks 5 GHz, which
# 2.4 GHz-only phones never see. 2.4 GHz is the compatible default.
BANDS = {"2.4 GHz": "2.4", "5 GHz": "5", "Auto (Windows picks)": "auto"}
BAND_LABELS = {value: label for label, value in BANDS.items()}


class QueueWriter:
    """Stand-in for sys.stdout that forwards printed text to the log pane."""

    def __init__(self, q: "queue.Queue") -> None:
        self._q = q

    def write(self, text: str) -> int:
        if text:
            self._q.put(text)
        return len(text)

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return False


class PortalGUI:
    def __init__(self, root: tk.Tk, opts: argparse.Namespace) -> None:
        self.root = root
        self.log_q: "queue.Queue" = queue.Queue()
        self.worker: threading.Thread | None = None
        self.exit_code = 0
        self.admin = windows.is_admin()

        self.ssid, self.password, self.dance, self.band = self._load_settings()
        if opts.ssid is not None:
            self.ssid = opts.ssid
        if opts.password is not None:
            self.password = opts.password
        if opts.dance is not None:
            self.dance = opts.dance
        if opts.band is not None:
            self.band = opts.band

        self._build()
        sys.stdout = QueueWriter(self.log_q)     # capture the portal's output
        sys.stderr = sys.stdout
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(150, self._drain_log)
        if opts.autostart:
            self.root.after(300, self.start_portal)

    # ---- settings ---------------------------------------------------------
    def _load_settings(self) -> tuple[str, str, bool, str]:
        ssid, password, dance, band = "FRP TOOL", "12345678", False, "2.4"
        try:
            data = json.loads((ROOT / CONFIG_PATH).read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            return ssid, password, dance, band
        if isinstance(data, dict):
            ssid = str(data.get("ssid") or ssid)
            password = str(data.get("password") or password)
            dance = bool(data.get("android_dns_dance"))
            band = str(data.get("hotspot_band") or band).strip().lower()
        return ssid, password, dance, band

    def _save_settings(self, ssid: str, password: str, dance: bool, band: str) -> None:
        """Keep the last-used values in config.json (best effort, never fatal)."""
        path = ROOT / CONFIG_PATH
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig")) if path.is_file() else {}
            if not isinstance(data, dict):
                return
            data["ssid"] = ssid
            data["password"] = password
            data["android_dns_dance"] = dance
            data["hotspot_band"] = band
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        except OSError:
            pass

    # ---- layout -----------------------------------------------------------
    def _build(self) -> None:
        self.root.title("FRP TOOL - Wi-Fi captive portal")
        self.root.geometry("660x600")
        self.root.minsize(560, 500)

        outer = ttk.Frame(self.root, padding=16)
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text="FRP TOOL", font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(
            outer, foreground="#5a6478",
            text="Start the Wi-Fi hotspot and its captive portal.",
        ).pack(anchor="w", pady=(2, 12))

        box = ttk.LabelFrame(outer, text=" Hotspot ", padding=12)
        box.pack(fill="x")
        box.columnconfigure(1, weight=1)

        ttk.Label(box, text="Wi-Fi name (SSID)").grid(row=0, column=0, sticky="w", pady=4)
        self.ssid_var = tk.StringVar(value=self.ssid)
        self.ssid_entry = ttk.Entry(box, textvariable=self.ssid_var)
        self.ssid_entry.grid(row=0, column=1, sticky="ew", padx=(12, 0), pady=4)

        ttk.Label(box, text="Password").grid(row=1, column=0, sticky="w", pady=4)
        self.pw_var = tk.StringVar(value=self.password)
        self.pw_entry = ttk.Entry(box, textvariable=self.pw_var)
        self.pw_entry.grid(row=1, column=1, sticky="ew", padx=(12, 0), pady=4)
        ttk.Label(box, text="8-63 characters", foreground="#5a6478").grid(
            row=3, column=1, sticky="w", padx=(12, 0))

        ttk.Label(box, text="Network band").grid(row=2, column=0, sticky="w", pady=4)
        self.band_var = tk.StringVar(value=BAND_LABELS.get(self.band, "2.4 GHz"))
        self.band_box = ttk.Combobox(box, textvariable=self.band_var, state="readonly",
                                     values=list(BANDS), width=20)
        self.band_box.grid(row=2, column=1, sticky="w", padx=(12, 0), pady=4)
        ttk.Label(box, text="2.4 GHz is seen by every phone",
                  foreground="#5a6478").grid(row=4, column=1, sticky="w", padx=(12, 0))

        self.dance_var = tk.BooleanVar(value=self.dance)
        ttk.Checkbutton(
            outer, variable=self.dance_var,
            text="Android DNS probe dance (fixes the missing sign-in popup on Android 14+)",
        ).pack(anchor="w", pady=(14, 0))
        ttk.Label(
            outer, foreground="#5a6478",
            text="Experimental, but it changes no network adapter settings.",
        ).pack(anchor="w", padx=(24, 0))

        bar = ttk.Frame(outer)
        bar.pack(fill="x", pady=(16, 10))
        self.start_btn = ttk.Button(bar, text="Start", command=self.start_portal)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(bar, text="Stop", command=self.stop_portal,
                                   state="disabled")
        self.stop_btn.pack(side="left", padx=(8, 0))
        self.status_var = tk.StringVar(value="Stopped")
        ttk.Label(bar, textvariable=self.status_var, foreground="#3d4759").pack(
            side="left", padx=(14, 0))

        log_box = ttk.LabelFrame(outer, text=" Log ", padding=8)
        log_box.pack(fill="both", expand=True)
        self.log = tk.Text(log_box, height=14, wrap="none", state="disabled",
                           font=("Consolas", 9), background="#f7f8fb",
                           foreground="#1d2433", borderwidth=1, relief="solid")
        scroll = ttk.Scrollbar(log_box, command=self.log.yview)
        self.log.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.log.pack(side="left", fill="both", expand=True)
        self._append(
            "Ready. Set the Wi-Fi name and password, then press Start.\n"
            "Administrator rights are required; Start will ask for them.\n"
        )

    # ---- log --------------------------------------------------------------
    def _append(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _drain_log(self) -> None:
        chunks: list[str] = []
        finished = False
        while True:
            try:
                item = self.log_q.get_nowait()
            except queue.Empty:
                break
            if item is FINISHED:
                finished = True
            else:
                chunks.append(item)
        if chunks:
            self._append("".join(chunks))
        if finished:
            self.worker = None
            self.start_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            self.status_var.set("Stopped" if self.exit_code == 0
                                else f"Stopped (exit code {self.exit_code})")
        self.root.after(150, self._drain_log)

    # ---- portal control ---------------------------------------------------
    def start_portal(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        ssid = self.ssid_var.get().strip()
        password = self.pw_var.get()
        dance = bool(self.dance_var.get())
        band = BANDS.get(self.band_var.get(), "2.4")

        if not ssid:
            messagebox.showerror("FRP TOOL", "The Wi-Fi name (SSID) cannot be empty.")
            return
        if password and not 8 <= len(password) <= 63:
            messagebox.showerror(
                "FRP TOOL",
                "The password must be 8-63 characters long, or empty for an open network.",
            )
            return

        self._save_settings(ssid, password, dance, band)

        if not self.admin:
            # Relaunch elevated, carrying the settings the user just typed.
            extra = ["--ssid", ssid, "--password", password, "--band", band]
            if dance:
                extra.append("--dance")
            if _relaunch_elevated(extra + ["--autostart"]):
                self.root.destroy()
            else:
                messagebox.showerror(
                    "FRP TOOL",
                    "Administrator rights are required to use ports 53/80.\n\n"
                    "Start the program again and accept the Windows prompt.",
                )
            return

        argv = ["--no-elevate", "--ssid", ssid, "--password", password,
                "--band", band]
        if dance:
            argv.append("--android-dns-dance")

        self._clear_log()
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_var.set("Starting...")
        self.worker = threading.Thread(
            target=self._portal_target, args=(argv,), daemon=True, name="portal")
        self.worker.start()

    def _portal_target(self, argv: list[str]) -> None:
        code = 0
        try:
            code = frp_portal.main(argv)
        except SystemExit as exc:                  # argparse handled --help
            code = int(exc.code or 0)
        except Exception as exc:                    # noqa: BLE001
            print(f"[ERROR] {exc}")
            code = 1
        self.exit_code = code
        self.log_q.put(FINISHED)

    def stop_portal(self) -> None:
        if not (self.worker and self.worker.is_alive()):
            return
        self.stop_btn.configure(state="disabled")
        self.status_var.set("Stopping...")
        frp_portal.request_stop()

    def close(self) -> None:
        if self.worker and self.worker.is_alive():
            if not messagebox.askyesno("FRP TOOL",
                                       "The portal is still running. Stop it and quit?"):
                return
            frp_portal.request_stop()
            self.worker.join(timeout=20)
        sys.stdout = sys.__stdout__ if sys.__stdout__ is not None else open(os.devnull, "w")
        self.root.destroy()


def _relaunch_elevated(extra: list[str]) -> bool:
    """Restart this GUI through UAC. True when the elevated copy started."""
    if getattr(sys, "frozen", False):
        exe, prefix = sys.executable, []
    else:
        exe, prefix = sys.executable, [str(Path(__file__).resolve())]
    params = subprocess.list2cmdline(prefix + extra)
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
    except OSError:
        return False
    return int(rc) > 32


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="FRP TOOL - desktop GUI")
    p.add_argument("--ssid", default=None)
    p.add_argument("--password", default=None)
    p.add_argument("--dance", dest="dance", action="store_true", default=None,
                   help="pre-tick the Android DNS probe dance")
    p.add_argument("--band", dest="band", choices=("auto", "2.4", "5"), default=None,
                   help="hotspot band to pre-select")
    p.add_argument("--autostart", action="store_true",
                   help="start the portal as soon as the window opens")
    return p.parse_args(argv)


def main(argv=None) -> int:
    opts = parse_args(argv)
    if not windows.is_admin():
        # Administrator rights are mandatory: without them the portal cannot
        # use ports 53/80 or control the hotspot.
        if _relaunch_elevated(list(sys.argv[1:])):
            return 0
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "FRP TOOL",
            "This program must run as Administrator.\n\n"
            "Accept the Windows User Account Control prompt, or right-click "
            "the program and choose 'Run as administrator'.",
        )
        root.destroy()
        return 1
    try:                              # crisp text on high-DPI displays
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:                 # noqa: BLE001 - pre-8.1 or already set
        pass
    root = tk.Tk()
    PortalGUI(root, opts)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
