"""Small console logger that mirrors the ESP32 Serial output style.

Optionally mirrors every line to a UTF-8 log file (see --log-file), which is
handy when diagnosing a phone that does not show the captive portal popup.
"""

from __future__ import annotations

import datetime
import threading
from pathlib import Path

_lock = threading.RLock()          # reentrant: section() holds it while emitting
_file = None                 # type: ignore[assignment]
_file_path = ""


def _ts() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


def set_log_file(path) -> str:
    """Enable (or disable, with an empty path) mirroring to a log file."""
    global _file, _file_path
    with _lock:
        if _file is not None:
            try:
                _file.close()
            except OSError:
                pass
        _file, _file_path = None, ""
        if not path:
            return ""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        _file = p.open("a", encoding="utf-8", buffering=1)
        _file_path = str(p)
        return _file_path


def close_log_file() -> None:
    set_log_file("")


def _emit(line: str) -> None:
    with _lock:
        print(line, flush=True)
        if _file is not None:
            try:
                _file.write(line + "\n")
                _file.flush()
            except OSError:
                pass


def log(message: str, level: str = "INFO") -> None:
    _emit(f"[{_ts()}] [{level:<5}] {message}")


def ok(message: str) -> None:
    log(message, "OK")


def warn(message: str) -> None:
    log(message, "WARN")


def error(message: str) -> None:
    log(message, "ERROR")


def section(title: str) -> None:
    with _lock:                    # keep the banner together under HTTP logging
        _emit("")
        _emit("=" * 56)
        _emit(f"  {title}")
        _emit("=" * 56)


def rule(char: str = "-", width: int = 56) -> None:
    with _lock:
        _emit(char * width)
