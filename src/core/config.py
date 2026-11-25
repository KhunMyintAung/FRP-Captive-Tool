"""Configuration loading for the FRP Tool portal."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from types import SimpleNamespace

DNS_MODES = ("smart", "intercept_all", "selective")
BANDS = ("auto", "2.4", "5")

DEFAULTS = {
    # --- Wi-Fi hotspot (same defaults as esp32_sd_frp.ino) ---
    "ssid": "FRP TOOL",
    "password": "12345678",
    # "" = auto detect the IP that Windows ICS assigns to the hotspot adapter
    # (normally 192.168.137.1). The ESP32 used a fixed 192.168.4.1.
    "portal_ip": "",
    "use_existing_hotspot": False,   # keep the SSID/password already set in Windows
    "stop_hotspot_on_exit": True,
    # Windows 11 24H2+ lets the hotspot choose its own band and often picks
    # 5 GHz, which phones that only scan 2.4 GHz never see. "2.4" is the most
    # compatible choice; "5" is faster; "auto" restores the Windows default.
    "hotspot_band": "2.4",
    "no_hotspot": False,            # serve DNS+HTTP only; never touch WinRT Mobile Hotspot

    # --- servers ---
    "dns_port": 53,
    "http_port": 80,
    "dns_ttl": 30,
    "verbose_dns": False,
    # smart          -> real names -> portal IP, sanity-check names -> NXDOMAIN
    # intercept_all  -> original ESP32 DNSServer("*") behaviour (everything -> portal IP)
    # selective      -> only OS probe hostnames -> portal IP, everything else -> NXDOMAIN
    "dns_mode": "smart",
    "capport_api": True,            # RFC 8908 /.well-known/captive-portal JSON
    "log_http": True,               # log every HTTP request with its status code
    "log_file": "",                 # optional file that also receives the console log
    # Samsung/OEM connectivity checkers GET / on the gateway with a Java
    # (Dalvik) User-Agent. A 200 there reads as "internet works" and the OS
    # suppresses the sign-in UI, so answer those probes with a 302 to
    # /index.html instead. Real browsers are unaffected.
    "redirect_os_probes": True,

    # --- Android 14+ private-IP DNS probe workaround (EXPERIMENTAL) --------
    # AOSP NetworkMonitor refuses to run its HTTP captive-portal probe when the
    # probe hostname resolves to an RFC1918 address. This workaround answers A
    # records with a non-RFC1918 address instead of the portal IP.
    # 192.0.2.1 is RFC 5737 TEST-NET-1: not site-local (so Java's check passes)
    # and not routable on the Internet (so it cannot collide with a real host).
    #
    # OFF by default: unless the address is already assigned to this PC, the
    # workaround has to add a secondary IP to the ICS hotspot adapter. That can
    # interfere with WinNAT/DHCP for Wi-Fi clients, and an unclean exit leaves
    # the address behind. The plain portal IP is the known-good configuration
    # (iPhone popup works, phones can connect). Enable explicitly to experiment.
    "android_compat": False,
    "android_probe_ip": "192.0.2.1",

    # --- adapter-free Android probe workaround (EXPERIMENTAL) --------------
    # AOSP resolves the HTTP probe host twice: once for the private-IP gate,
    # once for the actual HTTP connection. android_dns_dance answers the FIRST
    # lookup with a non-site-local address (TTL 0, never cached) and every
    # later lookup with the real portal IP. No IP is added to any adapter, so
    # Wi-Fi association / WinNAT cannot be disturbed. Off by default.
    "android_dns_dance": False,
    "android_dance_ip": "192.0.2.1",

    # --- content roots (relative to the project folder) ---
    "web_root": "web",              # LittleFS /index.html equivalent
    "shared_root": "shared",        # SD card equivalent
    "download_chunk": 65536,        # 256 on the ESP32; 64 KB is sane on a PC
    "download_idle_timeout": 15,    # seconds, same as DOWNLOAD_IDLE_TIMEOUT

    # --- misc ---
    "status_interval": 10,
    "open_browser": False,
}


def load(path: Path, root: Path, overrides: dict) -> SimpleNamespace:
    """Merge config.json -> DEFAULTS -> explicit CLI overrides."""
    values = dict(DEFAULTS)

    if path.is_file():
        try:
            with path.open("r", encoding="utf-8-sig") as fh:
                user = json.load(fh)
            if not isinstance(user, dict):
                raise ValueError("config.json must contain a JSON object")
            unknown = set(user) - set(DEFAULTS)
            if unknown:
                raise ValueError("unknown config key(s): " + ", ".join(sorted(unknown)))
            values.update(user)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Cannot read {path}: {exc}") from exc

    for key, value in overrides.items():
        if value is not None:
            values[key] = value

    # Resolve content folders against the project root.
    for key in ("web_root", "shared_root"):
        p = Path(values[key])
        values[key] = p if p.is_absolute() else (root / p)
    values["web_root"] = values["web_root"].resolve()
    values["shared_root"] = values["shared_root"].resolve()

    # Basic validation.
    if not 8 <= len(str(values["password"])) <= 63 and values["password"] != "":
        raise RuntimeError("Hotspot password must be 8-63 characters (or empty for an open AP).")
    if not 1 <= int(values["dns_port"]) <= 65535 or not 1 <= int(values["http_port"]) <= 65535:
        raise RuntimeError("Ports must be between 1 and 65535.")
    values["download_chunk"] = max(1024, int(values["download_chunk"]))
    values["download_idle_timeout"] = max(1, int(values["download_idle_timeout"]))

    values["hotspot_band"] = str(values["hotspot_band"]).strip().lower()
    if values["hotspot_band"] not in BANDS:
        raise RuntimeError(
            f"hotspot_band must be one of {', '.join(BANDS)} (got {values['hotspot_band']!r})."
        )

    values["dns_mode"] = str(values["dns_mode"]).strip().lower()
    if values["dns_mode"] not in DNS_MODES:
        raise RuntimeError(
            f"dns_mode must be one of {', '.join(DNS_MODES)} (got {values['dns_mode']!r})."
        )
    for key in ("capport_api", "log_http", "no_hotspot", "verbose_dns",
                "use_existing_hotspot", "stop_hotspot_on_exit", "open_browser",
                "android_compat", "android_dns_dance", "redirect_os_probes"):
        values[key] = bool(values[key])

    try:
        probe_ip = ipaddress.IPv4Address(str(values["android_probe_ip"]).strip())
    except ipaddress.AddressValueError as exc:
        raise RuntimeError(f"android_probe_ip is not a valid IPv4 address: {exc}") from exc
    values["android_probe_ip"] = str(probe_ip)

    try:
        values["android_dance_ip"] = str(
            ipaddress.IPv4Address(str(values["android_dance_ip"]).strip()))
    except ipaddress.AddressValueError as exc:
        raise RuntimeError(f"android_dance_ip is not a valid IPv4 address: {exc}") from exc

    log_file = str(values["log_file"] or "").strip()
    if log_file:
        p = Path(log_file)
        values["log_file"] = (p if p.is_absolute() else root / p).resolve()
    else:
        values["log_file"] = ""

    values["root"] = root.resolve()
    values["config_path"] = path.resolve()
    return SimpleNamespace(**values)
