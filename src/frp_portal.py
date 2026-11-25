#!/usr/bin/env python3
"""
FRP TOOL - Windows captive portal
=================================

Python port of esp32_sd_frp.ino. Replaces every ESP32 subsystem:

    WiFi.softAP(ssid, password)   -> WinRT NetworkOperatorTetheringManager
    DNSServer("*", apIP)          -> core/dns.py   (catch-all UDP 53)
    WebServer(80)                 -> core/http.py  (ThreadingHTTPServer)
    LittleFS /index.html          -> web/index.html + web/assets/
    SD card /download/<file>      -> shared/<file>
    Serial monitor                -> console log

Run as Administrator (start.bat does this for you). Requires only the Python
standard library plus the Windows PowerShell 5.1 that ships with Windows.

Startup order matters: our DNS server must bind UDP 53 BEFORE the hotspot is
started, otherwise Windows ICS claims the port with its own DNS proxy and the
captive portal never triggers. ICS DHCP on UDP 67 is left alone so clients
still receive IP addresses.

Two Android-specific details (both learned from real-device tests) live in
core/dns.py: DNS sanity-check names must get NXDOMAIN, and A records must not
be RFC1918 or Android 14+ cancels its HTTP probe before sending it. The latter
has an EXPERIMENTAL opt-in workaround (--android-compat) that answers with a
non-RFC1918 address. It is OFF by default because adding a secondary IP to the
ICS adapter can break Wi-Fi client connectivity. A third, adapter-free option
(--android-dns-dance) uses the fact that AOSP resolves the probe hostname
twice: the first lookup only feeds the private-IP gate. A third Samsung-specific
detail lives in core/http.py: the phone's Java/Dalvik checker GETs / on the
gateway IP, and that request must be a 302 rather than the 200 portal page.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path

if getattr(sys, "frozen", False):
    # Packaged build (PyInstaller): web/, shared/ and config.json live next to
    # the .exe, so users can edit them without unpacking the bundle.
    ROOT = Path(sys.executable).resolve().parent
else:
    ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Set by the GUI's Stop button. The status loop watches it, so a GUI stop runs
# through the same finally block as Ctrl+C (firewall rules, hotspot, servers).
STOP = threading.Event()


def request_stop() -> None:
    """Ask a running portal to shut down cleanly (safe from any thread)."""
    STOP.set()

from core import config, windows                     # noqa: E402
from core.dns import (  # noqa: E402
    CaptiveDNS, classify, is_private_probe_ip,
)
from core.http import PortalHTTPServer, PortalHandler  # noqa: E402
from core.log import (  # noqa: E402
    close_log_file, error, log, ok, rule, section, set_log_file, warn,
)


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="FRP TOOL - Windows Wi-Fi hotspot with an auto-popup captive portal",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  start.bat\n"
            "  python frp_portal.py --ssid \"My Portal\" --password 12345678\n"
            "  python frp_portal.py --use-existing-hotspot --keep-hotspot\n"
            "  start.bat --log-file portal.log      (recommended for phone testing)\n"
            "  python frp_portal.py --no-elevate      (from an already elevated shell)\n"
        ),
    )
    p.add_argument("--config", default="config.json", help="config file (default: config.json)")
    p.add_argument("--ssid", help="hotspot SSID")
    p.add_argument("--password", help="WPA2 passphrase (8-63 chars)")
    p.add_argument("--ip", dest="portal_ip", help="override the detected portal IP")
    p.add_argument("--band", dest="hotspot_band", choices=("auto", "2.4", "5"),
                   default=None,
                   help="hotspot radio band: 2.4 (default, most compatible), "
                        "5 (faster) or auto (Windows picks; may hide the SSID "
                        "from 2.4 GHz-only phones)")
    p.add_argument("--http-port", type=int, help="HTTP port (80 required for real captive portals)")
    p.add_argument("--dns-port", type=int, help="DNS port (53 required for real captive portals)")
    p.add_argument("--web", dest="web_root", help="folder holding index.html")
    p.add_argument("--shared", dest="shared_root", help="folder holding downloadable files")
    p.add_argument("--use-existing-hotspot", action="store_true", default=None,
                    help="do not overwrite the SSID/password configured in Windows")
    p.add_argument("--keep-hotspot", action="store_true", default=None,
                    help="leave the hotspot running when the tool exits")
    p.add_argument("--open-browser", action="store_true", default=None,
                    help="open the portal locally for a quick preview")
    p.add_argument("--verbose-dns", action="store_true", default=None,
                    help="log every DNS query")
    p.add_argument("--dns-mode", choices=("smart", "intercept_all", "selective"),
                    default=None,
                    help="smart (default): NXDOMAIN for Android sanity-check names; "
                         "intercept_all: ESP32 DNSServer('*') behaviour; "
                         "selective: only OS probe hostnames resolve")
    p.add_argument("--no-capport-api", dest="capport_api", action="store_false", default=None,
                    help="disable the RFC 8908 /.well-known/captive-portal JSON endpoint")
    p.add_argument("--android-compat", dest="android_compat", action="store_true",
                    default=None,
                    help="EXPERIMENTAL: answer DNS A records with a non-RFC1918 address "
                         "so Android 14+ does not skip its HTTP captive-portal probe. "
                         "May add a temporary secondary IP to the hotspot adapter")
    p.add_argument("--no-android-compat", dest="android_compat", action="store_false",
                    default=None,
                    help="explicitly disable the workaround (this is the default)")
    p.add_argument("--android-probe-ip", default=None,
                    help="non-RFC1918 address for A records (default: 192.0.2.1). "
                         "If this PC already owns the address, no adapter change is made")
    p.add_argument("--android-dns-dance", dest="android_dns_dance", action="store_true",
                    default=None,
                    help="EXPERIMENTAL, adapter-free: first DNS lookup of a hostname gets "
                         "a non-site-local IP (TTL 0), later lookups get the portal IP. "
                         "Lets Android 14+ past its private-IP gate without changing any adapter")
    p.add_argument("--no-android-dns-dance", dest="android_dns_dance",
                    action="store_false", default=None,
                    help="disable the probe dance (this is the default)")
    p.add_argument("--android-dance-ip", default=None,
                    help="non-site-local IP for the first lookup (default: 192.0.2.1)")
    p.add_argument("--no-log-http", dest="log_http", action="store_false", default=None,
                    help="disable the one-line-per-request HTTP access log")
    p.add_argument("--no-redirect-os-probes", dest="redirect_os_probes",
                    action="store_false", default=None,
                    help="serve the 200 portal page to Java/Dalvik OS probes on / "
                         "instead of a 302 (restores the exact .ino behaviour)")
    p.add_argument("--redirect-os-probes", dest="redirect_os_probes",
                    action="store_true", default=None,
                    help="302 Samsung/Dalvik probes on / to /index.html (default)")
    p.add_argument("--log-file", default=None,
                    help="also append the console log to this file (great for phone debugging)")
    p.add_argument("--no-hotspot", action="store_true", default=None,
                    help="do not touch the Windows Mobile Hotspot; only run DNS + HTTP "
                         "(use on an existing network or for local testing)")
    p.add_argument("--status-interval", type=int,
                    help="seconds between status lines (default: 10)")
    p.add_argument("--no-elevate", action="store_true",
                    help="skip the UAC prompt (use when already elevated)")
    p.add_argument("--auto-stop", type=int, default=0,
                    help="shut down gracefully after N seconds (0 = run until Ctrl+C)")
    return p.parse_args(argv)


def check_web_root(cfg) -> None:
    """Port of checkFileSystem()."""
    section("WEB ASSETS  (LittleFS equivalent)")
    index = cfg.web_root / "index.html"
    if index.is_file():
        ok(f"/index.html  ({index.stat().st_size} bytes)")
    else:
        warn("/index.html NOT FOUND - the portal will return HTTP 500")
    icon = cfg.web_root / "assets" / "settings.svg"
    if icon.is_file():
        ok("/assets/settings.svg")
    else:
        log("[INFO] /assets/settings.svg not found (optional)")
    count = sum(1 for p in cfg.web_root.rglob("*") if p.is_file()) if cfg.web_root.is_dir() else 0
    log(f"Folder: {cfg.web_root}")
    log(f"Total files: {count}")
    rule()


def check_shared_root(cfg) -> None:
    """Port of checkSDCard()."""
    section("SHARED FOLDER  (SD card equivalent)")
    if not cfg.shared_root.is_dir():
        try:
            cfg.shared_root.mkdir(parents=True, exist_ok=True)
            ok(f"Created {cfg.shared_root}")
        except OSError as exc:
            warn(f"Cannot create shared folder: {exc}")
            rule()
            return
    files = [p for p in sorted(cfg.shared_root.rglob("*")) if p.is_file()]
    total = 0
    for p in files:
        try:
            total += p.stat().st_size
        except OSError:
            pass
    ok("Shared folder mounted")
    log(f"Folder: {cfg.shared_root}")
    log(f"Files: {len(files)}")
    log(f"Total size: {total / (1024 * 1024):.2f} MB")
    for p in files[:8]:
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        log(f"  {p.relative_to(cfg.shared_root).as_posix()}  ({size} bytes)")
    if len(files) > 8:
        log(f"  ... and {len(files) - 8} more")
    rule()


def check_dns_policy(cfg, answer_ip: str) -> None:
    """Show, before any sockets open, how the phone's DNS probes will resolve."""
    section("DNS POLICY  (Android captive-portal compatibility)")
    log(f"Mode: {cfg.dns_mode}   |   A-record address: {answer_ip}")
    samples = (
        "connectivitycheck.gstatic.com", "www.google.com", "captive.apple.com",
        "*google.com", "google.com.onion",
        "www.goooooooooooooooooooooooooooooooooooooooooooooooooooooooooogle.com",
        "216.58.202.4.in-addr.arpa",
    )
    for name in samples:
        decision, reason = classify(name, cfg.dns_mode)
        outcome = "NXDOMAIN" if decision == "nxdomain" else f"A -> {answer_ip}"
        log(f"  {name[:44]:<44} {outcome}" + (f"  [{reason}]" if reason else ""))
    if is_private_probe_ip(answer_ip):
        warn(f"{answer_ip} is site-local: Android 14+ may skip its HTTP probe "
             "and suppress the sign-in popup.")
        log("Known-good default: phones connect reliably. Experimental Samsung "
            "options: --android-dns-dance (adapter-free) or --android-compat.")
    else:
        ok(f"{answer_ip} is not site-local - Android's private-IP probe check will pass.")
    if cfg.dns_mode == "intercept_all":
        warn("intercept_all answers the sanity-check names too - Android may suppress the popup.")
    rule()


def ready_banner(cfg, result: dict, base_url: str, answer_ip: str,
                 alias_works: bool, health: dict | None = None,
                 dance_active: bool = False) -> None:
    section("PORTAL READY")
    log(f"SSID       : {result.get('ssid') or cfg.ssid}")
    log(f"Password   : {cfg.password if not cfg.use_existing_hotspot else '(unchanged)'}")
    log(f"Portal     : {base_url}")
    log(f"Downloads  : {base_url}download/")
    log(f"Web root   : {cfg.web_root}")
    log(f"Shared     : {cfg.shared_root}")
    log(f"Chunk size : {cfg.download_chunk} bytes")
    log(f"Idle time  : {cfg.download_idle_timeout} seconds")
    log(f"DNS mode   : {cfg.dns_mode}  (bogus names -> NXDOMAIN unless intercept_all)")
    log(f"DNS A rec  : {answer_ip}"
        + ("  [Android fix ACTIVE]" if alias_works else "  [portal IP]"))
    log(f"Android fix: {'ON  (experimental)' if cfg.android_compat else 'OFF (default, reliable)'}")
    log(f"Probe dance: {'ON  (experimental, no adapter change)' if dance_active else 'OFF'}")
    log(f"Capport API: {'on  (/.well-known/captive-portal)' if cfg.capport_api else 'off'}")
    log(f"OS probe UA: {'302 -> /index.html (Samsung/Dalvik)' if cfg.redirect_os_probes else 'off (exact .ino behaviour)'}")
    log(f"HTTP log   : {'on' if cfg.log_http else 'off'}"
        + (f"  + file {cfg.log_file}" if cfg.log_file else ""))
    if cfg.no_hotspot:
        log("Hotspot    : NOT managed (--no-hotspot)")
    elif health:
        log(f"Hotspot    : {health.get('state') or '?'} | "
            f"DHCP: {(health.get('dhcp_address') or 'NOT listening')}"
            + (":67" if health.get('dhcp_address') else "") +
            f" | band: {health.get('band') or cfg.hotspot_band}"
            f" | clients: {health.get('clients') or 0}")
    rule()
    log("Connect a phone/PC to the Wi-Fi above; the sign-in page opens by itself.")
    log("If the SSID is not visible, try another hotspot band (--band 2.4 / --band 5)")
    log("or check Windows Settings > Network & Internet > Mobile hotspot.")
    log("Android check: watch for 'GET /generate_204 -> 302' (AOSP) or")
    log("               'GET / -> 302' (Samsung/Dalvik) from the phone.")
    if not cfg.android_compat and not dance_active and is_private_probe_ip(answer_ip):
        log("No Android workaround is active: Android 14+ may skip its HTTP probe.")
        log("If Samsung shows no popup, retry with --android-dns-dance.")
    log("Press Ctrl+C to stop everything.")
    rule()


def main(argv=None) -> int:
    args = parse_args(argv)
    STOP.clear()

    if sys.platform != "win32":
        error("This tool is Windows-only (WinRT Mobile Hotspot + netsh).")
        return 2

    overrides = {
        k: v for k, v in vars(args).items()
        if k not in ("config", "no_elevate", "keep_hotspot") and v is not None
    }
    if args.keep_hotspot:
        overrides["stop_hotspot_on_exit"] = False

    try:
        cfg = config.load(ROOT / args.config, ROOT, overrides)
    except RuntimeError as exc:
        error(str(exc))
        return 2

    if cfg.log_file:
        try:
            path = set_log_file(cfg.log_file)
            log(f"Log file: {path}")
        except OSError as exc:
            warn(f"Cannot open the log file: {exc}")

    if not args.no_elevate and not windows.is_admin():
        log("Binding UDP 53 / TCP 80 needs Administrator rights - requesting elevation...")
        windows.elevate()                 # does not return
    if not windows.is_admin():
        warn("Not running elevated. Port binding or firewall rules may fail.")

    section("        FRP WINDOWS PORTAL        ")
    log("Python port of esp32_sd_frp.ino")
    log(f"Config: {cfg.config_path}")
    rule()

    check_web_root(cfg)
    check_shared_root(cfg)
    # The address we intend A records to carry. With android_compat we must
    # also attach it to the hotspot adapter (done after the hotspot is up).
    # Only meaningful for a real portal (managed hotspot + ports 53/80).
    android_fix = bool(cfg.android_compat and not cfg.no_hotspot
                       and cfg.http_port == 80 and cfg.dns_port == 53)
    # The alias already makes every A record non-private, so the dance would
    # only add noise. Prefer the alias when both flags were requested.
    dance_active = bool(cfg.android_dns_dance and not android_fix)
    planned_answer_ip = (cfg.android_probe_ip if android_fix
                         else str(cfg.portal_ip or "192.168.137.1"))
    check_dns_policy(cfg, planned_answer_ip)
    if cfg.android_dns_dance and not dance_active:
        log("--android-compat is active, so the probe dance is not needed.")

    dns = CaptiveDNS(
        portal_ip=str(cfg.portal_ip or "192.168.137.1"),
        port=cfg.dns_port, ttl=cfg.dns_ttl, verbose=cfg.verbose_dns,
        mode=cfg.dns_mode,
        dance_ip=cfg.android_dance_ip if dance_active else "",
    )
    httpd: PortalHTTPServer | None = None
    firewall_added = False
    hotspot_started = False
    alias_added = False
    alias_works = False
    rc = 0

    try:
        # --- 0. Self-heal after an unclean exit -----------------------------
        # Killing the console window skips the finally block, which used to
        # leave the experimental alias on the ICS adapter. Clear it up front so
        # a bad previous run can never poison this one.
        stale = windows.remove_probe_alias(cfg.android_probe_ip)
        if stale.get("removed"):
            ok(f"Removed stale {cfg.android_probe_ip} alias left by a previous run")

        # --- 1. Free UDP 53 -------------------------------------------------
        section("PREPARING NETWORK")
        if cfg.no_hotspot:
            log("--no-hotspot: leaving the Windows Mobile Hotspot untouched.")
        else:
            stopped = windows.ps_action("stop")
            if stopped.get("ok"):
                ok(f"Hotspot state before start: {stopped.get('state')}")
            else:
                warn(f"Could not query/stop the hotspot: {stopped.get('message')}")
            log("Hotspot must be OFF here, otherwise ICS owns UDP 53.")

        # --- 2. Bind DNS (before the hotspot!) and HTTP --------------------
        section("STARTING SERVERS")
        dns.start()
        httpd = PortalHTTPServer(("0.0.0.0", cfg.http_port), PortalHandler, cfg, dns)
        httpd.start()
        windows.add_firewall_rules(cfg.http_port, cfg.dns_port)
        firewall_added = True

        # --- 3. Bring the hotspot up ---------------------------------------
        section("STARTING WI-FI HOTSPOT")
        result = {}
        if cfg.no_hotspot:
            log("Skipped (--no-hotspot). DNS + HTTP are serving on the existing network.")
        else:
            ssid = "" if cfg.use_existing_hotspot else cfg.ssid
            password = "" if cfg.use_existing_hotspot else cfg.password
            result = windows.ps_action("start", ssid, password, cfg.hotspot_band)
            if result.get("ok"):
                hotspot_started = True
                ok(f"Access Point started (shared from: {result.get('profile') or '?'})")
                log(f"SSID: {result.get('ssid') or cfg.ssid}")
                log(f"Band: {result.get('band') or cfg.hotspot_band}"
                    + ("  (requested 2.4 GHz)" if cfg.hotspot_band == "2.4"
                       and result.get("band") != "TwoPointFourGigahertz" else ""))
                log(f"Max clients: {result.get('max_clients') or '?'}")
            else:
                warn(f"Automatic hotspot start failed: {result.get('message')}")
                warn("Turn on Windows Settings > Network & Internet > Mobile hotspot manually.")
                warn("The DNS + HTTP servers stay up and will serve clients as soon as it is on.")
                result = windows.ps_action("addresses")

        # --- 3b. Verify the hotspot really serves clients -------------------
        health = {}
        if not cfg.no_hotspot:
            health = windows.ps_action("status")
            state = health.get("state")
            dhcp = health.get("dhcp_address")
            if state == "On" and dhcp:
                ok(f"Hotspot is On; ICS DHCP is listening on {dhcp}:67")
            elif state == "On":
                warn("Hotspot reports On, but ICS DHCP (UDP 67) is NOT listening - "
                     "phones will fail to get an IP address.")
                warn("Turn Mobile Hotspot on once from Windows Settings, then "
                     "restart this tool.")
            else:
                warn(f"Hotspot state is {state!r} - the SSID may not be broadcast "
                     "at all. Check Windows Settings > Mobile hotspot.")

        # --- 4. Discover the IP clients actually use -----------------------
        ip = windows.detect_portal_ip(cfg.portal_ip, result)
        dns.set_portal_ip(ip)
        httpd.set_portal_ip(ip)
        if result.get("dhcp_address"):
            log(f"ICS DHCP endpoint: {result['dhcp_address']}:67")

        # --- 4b. Android 14+ private-IP DNS probe workaround (opt-in) ------
        if android_fix:
            section("ANDROID PROBE WORKAROUND  (experimental)")
            log("AOSP NetworkMonitor skips its HTTP probe when the probe host")
            log("resolves to an RFC1918 address -> no sign-in notification.")
            warn("This changes the ICS adapter's IP configuration. If phones "
                 "cannot connect, restart without --android-compat.")
            if windows.has_local_address(cfg.android_probe_ip):
                # Safest variant: the PC already owns a non-private address,
                # so no IP is added to the hotspot adapter at all.
                alias_works = True
                ok(f"{cfg.android_probe_ip} is already assigned to this PC - "
                   "no adapter change needed")
                dns.set_answer_ip(cfg.android_probe_ip)
            else:
                ifindex = windows.detect_portal_ifindex(ip, result)
                res = windows.add_probe_alias(cfg.android_probe_ip, ip, ifindex)
                if res.get("ok"):
                    alias_added = bool(res.get("added"))
                    alias_works = True
                    ok(f"Alias {cfg.android_probe_ip} is live on "
                       f"'{res.get('interface') or '?'}' (ifIndex {res.get('index') or '?'}, "
                       f"state={res.get('state') or '?'}, DAD restored="
                       f"{bool(res.get('dad_restored'))})"
                       + ("" if alias_added else "  [already present, reused]"))
                    dns.set_answer_ip(cfg.android_probe_ip)
                else:
                    warn(f"Could not add the alias: {res.get('message')}")
                    warn("A records will use the portal IP. Try "
                         "--android-probe-ip with a non-private address this PC "
                         "already owns, or run as Administrator.")
            if alias_works:
                log(f"Portal itself still reachable at {httpd.portal_url()}")
                try:
                    with socket.create_connection(
                            (cfg.android_probe_ip, cfg.http_port), 1.5):
                        ok("Local HTTP delivery to the probe address confirmed")
                except OSError as exc:
                    log(f"Local check inconclusive ({exc}); Wi-Fi clients reach "
                        "it through the gateway, which is what matters.")

        if dns.self_test():
            ok("Local DNS self-test passed")
            if cfg.dns_mode != "intercept_all":
                log(f"Sanity-check names: {dns.sanity_test()}")
        else:
            warn("Local DNS self-test failed - outbound UDP/53 is blocked on this PC.")
            warn("Usually a VPN/antivirus 'DNS leak protection' filter (e.g. SkyVPN).")
            log("That filter is outbound-only, so Wi-Fi clients' inbound DNS still reaches us.")
            log("The DNS POLICY table above shows the decisions without needing a socket.")

        if dance_active:
            section("ANDROID PROBE DANCE  (experimental, adapter-free)")
            log("AOSP resolves the HTTP probe host twice. First lookup (the")
            log("private-IP gate) -> " + cfg.android_dance_ip + " with TTL 0;")
            log("second lookup (the real HTTP connection) -> " + ip + ".")
            log("No IP is added to any adapter, so Wi-Fi/WinNAT is untouched.")
            log("In the log expect: a non-site-local first lookup, then")
            log("'GET /generate_204 -> 302' from the phone's 192.168.137.x IP.")
            rule()

        ready_banner(cfg, result, httpd.portal_url(), dns.answer_ip,
                     alias_works, health, dance_active)
        if cfg.open_browser:
            webbrowser.open(f"http://127.0.0.1:{cfg.http_port}/")

        # --- 5. Status loop ------------------------------------------------
        deadline = time.monotonic() + cfg.auto_stop if cfg.auto_stop else None
        while not STOP.is_set():
            if deadline and time.monotonic() >= deadline:
                log("Auto-stop timer elapsed - shutting down...")
                break
            if STOP.wait(max(0.2, cfg.status_interval)):
                log("Stop requested - shutting down...")
                break
            if not cfg.no_hotspot:
                state = windows.ps_action("status")
                if state.get("ok"):
                    httpd.connected_clients = int(state.get("clients") or 0)
            queries, answered, nxdomain = dns.stats()
            log(f"Clients: {httpd.connected_clients} | "
                f"DNS: {queries} (A {answered} / NXDOMAIN {nxdomain}) | "
                f"HTTP: {httpd.request_count} | "
                f"download busy: {httpd.download_status()['busy']}")

    except KeyboardInterrupt:
        log("Ctrl+C received - shutting down...")
    except Exception as exc:               # noqa: BLE001
        error(f"Fatal error: {exc}")
        rc = 1
    finally:
        section("SHUTDOWN")
        if firewall_added:
            windows.remove_firewall_rules()
            ok("Firewall rules removed")
        if httpd is not None:
            httpd.stop()
            ok("Web server stopped")
        dns.stop()
        ok("DNS server stopped")
        if alias_added:
            # Remove while the hotspot adapter still exists.
            cleanup = windows.remove_probe_alias(cfg.android_probe_ip)
            if cleanup.get("ok"):
                ok(f"Temporary alias {cfg.android_probe_ip} removed")
            else:
                warn(f"Could not remove alias {cfg.android_probe_ip}: "
                     f"{cleanup.get('message')} (it is ActiveStore-only and "
                     "will disappear after a reboot)")
        if cfg.no_hotspot:
            log("Hotspot untouched (--no-hotspot)")
        elif cfg.stop_hotspot_on_exit and hotspot_started:
            state = windows.ps_action("stop")
            if state.get("ok"):
                ok("Hotspot stopped")
            else:
                warn(f"Hotspot stop failed: {state.get('message')}")
        elif not cfg.stop_hotspot_on_exit:
            log("Hotspot left running (stop_hotspot_on_exit = false)")
        rule()
        log("FRP TOOL stopped.")
        close_log_file()

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
