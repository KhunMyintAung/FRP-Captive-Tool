"""Portal HTTP server - the Windows port of the ESP32 WebServer(80).

Routes kept from the .ino:
    /                     -> web/index.html          (was LittleFS /index.html)
    /assets/*, ...        -> static files from web/  (was serveStatic LittleFS)
    /generate_204 etc.    -> 302 to the portal       (captive portal probes)
    <anything else>       -> 302 to the portal       (was onNotFound)
    /status/download      -> {"busy": ...}
    /download/<path>      -> stream a file from shared/  (was the SD card)

Windows extras: /api/files, /api/status, /.well-known/captive-portal (RFC 8908),
HEAD support, Range-less streaming, client-disconnect + idle-timeout handling,
and an access log line for every single HTTP request. A Java/Dalvik (OS-level)
User-Agent asking for / gets a 302 instead of the 200 page: Samsung's own
connectivity checker uses exactly that request, and a 200 reads as "internet OK".
"""

from __future__ import annotations

import json
import mimetypes
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

from .log import log, ok, rule

for _ext, _mime in {
    ".apk": "application/vnd.android.package-archive",
    ".svg": "image/svg+xml",
    ".js": "application/javascript",
    ".json": "application/json",
    ".woff2": "font/woff2",
    ".ico": "image/x-icon",
}.items():
    mimetypes.add_type(_mime, _ext)

# OS connectivity probes. Every one of these must NOT return its "success"
# response, otherwise the OS concludes there is real internet and never pops
# up the portal. A 302 to our page does the trick on Android / iOS / Windows.
PROBE_PATHS = frozenset({
    "/generate_204", "/gen_204", "/connectivitycheck/generate_204",
    "/connecttest.txt", "/ncsi.txt", "/fwlink", "/hotspot-detect.html",
    "/success.txt", "/success", "/success.html",
    "/library/test/success.html", "/canonical.html",
    "/kindle-wifi/wifistub.html", "/wifistub.html",
    "/connectivity-check.html", "/redirect", "/portal.html",
    "/check_network_status.txt", "/generate204",
})

BYTES_PER_MB = 1024 * 1024

# RFC 8908 Captive Portal API. Android 11+ / Windows 11 / iOS ask for this
# document (or send Accept: application/captive+json on a probe URL). It MUST
# be a 200 with the exact media type - a 302 here breaks detection.
CAPTIVE_API_PATHS = frozenset({
    "/.well-known/captive-portal",
    "/api/captive-portal",
    "/capport/api",
})
CAPTIVE_MIME = "application/captive+json"

# Requests for a missing image/font/stylesheet are NOT navigation or an OS
# probe: they must get a plain 404 so the browser's error handler can show a
# fallback. Redirecting them to the portal page downloads ~15 KB of HTML per
# icon and, worse, fires note_portal_visit() once per icon, which keeps
# resetting the Android DNS probe-dance cycle. Probe paths (.txt/.html) are
# deliberately absent so they still get the captive 302.
STATIC_ASSET_EXTS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".bmp", ".ico",
    ".css", ".js", ".mjs", ".woff", ".woff2", ".ttf", ".eot", ".map",
)


def _is_asset_path(low: str) -> bool:
    return low.endswith(STATIC_ASSET_EXTS)


# Non-browser HTTP clients used by OS/OEM connectivity checkers. A real
# browser (Chrome, Safari, the Android sign-in WebView, Samsung Internet) always
# sends a Mozilla/... UA, so it must never be redirected away from the portal
# page. These Java/HttpURLConnection-style UAs are background probes instead.
# Samsung SM-S948B sent: Dalvik/2.1.0 (Linux; U; Android 17; ...)
OS_PROBE_UA_MARKERS = (
    "dalvik/", "java/", "apache-httpclient/", "apache httpclient/",
    "okhttp/", "google-http-java-client/", "captivenetworksupport",
    "wispr", "msftncsi", "ncsi",
)


def _resolve_in(root: Path, rel: str) -> Path | None:
    """Safely map a URL path to a file inside root (no traversal / absolute paths)."""
    rel = unquote(rel).replace("\\", "/").lstrip("/")
    if not rel or "\x00" in rel:
        return None
    parts = [p for p in rel.split("/") if p]
    if not parts or any(p in (".", "..") or ":" in p for p in parts):
        return None
    try:
        candidate = root.joinpath(*parts).resolve()
        if os.path.commonpath([str(candidate), str(root)]) != str(root):
            return None
    except (ValueError, OSError):
        return None
    return candidate


class PortalHTTPServer(ThreadingHTTPServer):
    # SO_REUSEADDR on Windows lets another process hijack the port; keep it off.
    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, address, handler, cfg, dns_server=None):
        self.web_root: Path = cfg.web_root
        self.shared_root: Path = cfg.shared_root
        self.download_chunk: int = cfg.download_chunk
        self.idle_timeout: int = cfg.download_idle_timeout
        self.http_port: int = cfg.http_port
        self.ssid: str = cfg.ssid
        self.dns_server = dns_server
        self.connected_clients = 0
        self.log_http: bool = getattr(cfg, "log_http", True)
        self.capport_api: bool = getattr(cfg, "capport_api", True)
        # Samsung/OEM Java-level probes hit "/" on the gateway IP; give them a
        # 302 instead of a 200 page (see OS_PROBE_UA_MARKERS).
        self.redirect_os_probes: bool = bool(getattr(cfg, "redirect_os_probes", True))
        self.request_count = 0

        self._portal_ip = str(cfg.portal_ip or "192.168.137.1")
        self._lock = threading.Lock()
        self._busy = False
        self._dl = {"file": "", "sent": 0, "total": 0, "started": 0.0}
        try:
            super().__init__(address, handler)
        except OSError as exc:
            raise RuntimeError(
                f"Cannot bind TCP/{address[1]} ({exc}). Another web server (IIS, Apache, "
                "Skype, ...) may be using port 80. Stop it or use --http-port."
            ) from exc

    # ---- shared state -----------------------------------------------------
    def set_portal_ip(self, ip: str) -> None:
        with self._lock:
            self._portal_ip = ip
        ok(f"Portal URL is {self.portal_url()}")

    def portal_url(self) -> str:
        with self._lock:
            ip = self._portal_ip
        suffix = "" if self.http_port == 80 else f":{self.http_port}"
        return f"http://{ip}{suffix}/"

    def acquire_download(self, name: str) -> bool:
        import time
        with self._lock:
            if self._busy:
                return False
            self._busy = True
            self._dl = {"file": name, "sent": 0, "total": 0, "started": time.time()}
            return True

    def update_progress(self, sent: int, total: int) -> None:
        with self._lock:
            if not self._busy:                 # static pages don't touch download state
                return
            self._dl["sent"] = sent
            self._dl["total"] = total

    def release_download(self) -> None:
        with self._lock:
            self._busy = False
            self._dl = {"file": "", "sent": 0, "total": 0, "started": 0.0}

    def download_status(self) -> dict:
        with self._lock:
            busy, d = self._busy, dict(self._dl)
        total = d["total"] or 0
        return {
            "busy": busy,
            "file": d["file"],
            "sent": d["sent"],
            "total": total,
            "percent": round(d["sent"] * 100 / total, 1) if total else 0,
        }

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self.serve_forever, kwargs={"poll_interval": 0.3},
            name="http", daemon=True,
        )
        self._thread.start()
        ok(f"Web server listening on 0.0.0.0:{self.http_port}")

    def stop(self) -> None:
        self.shutdown()
        self.server_close()
        if getattr(self, "_thread", None):
            self._thread.join(timeout=2)


class PortalHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "FRPToolPortal/1.0"
    sys_version = ""

    def log_message(self, fmt, *args):       # we use our own logger
        pass

    def send_response(self, code, message=None):
        # Remember the status so the access log can show what each request got.
        self._status = code
        super().send_response(code, message)

    # ---- verbs ------------------------------------------------------------
    def do_GET(self):
        self._dispatch(head=False)

    def do_HEAD(self):
        self._dispatch(head=True)

    def do_POST(self):
        self._dispatch(head=False, force_redirect=True)

    # ---- helpers ----------------------------------------------------------
    def _json(self, obj: dict, head: bool, status: int = 200,
              content_type: str = "application/json; charset=utf-8") -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Connection", "close")
        self.end_headers()
        if not head:
            try:
                self.wfile.write(body)
            except OSError:
                pass
        self.close_connection = True

    def _captive_api(self, head: bool) -> None:
        """RFC 8908: a 200 + application/captive+json document, never a 302."""
        url = self.server.portal_url()
        self._json({
            "captive": True,
            "user-portal-url": url,
            "venue-info-url": url,
            "can-extend-session": False,
        }, head, content_type=CAPTIVE_MIME)

    def _empty(self, status: int, head: bool, location: str | None = None) -> None:
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def _redirect(self, head: bool = False, target: str | None = None) -> None:
        # `target` is only used for the Samsung "/" case: redirecting "/" back
        # to "/" would loop forever, so send those probes to /index.html,
        # which always serves the page for any User-Agent.
        location = target or self.server.portal_url()
        body = b"Redirecting to captive portal..."
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        if not head:
            try:
                self.wfile.write(body)
            except OSError:
                pass
        self.close_connection = True
        log(f"302 -> {location}  [{self.path}]  client={self.client_address[0]}")
        # Let the DNS "probe dance" start a fresh cycle for this client.
        dns = getattr(self.server, "dns_server", None)
        if dns is not None and hasattr(dns, "note_portal_visit"):
            dns.note_portal_visit(self.client_address[0])

    @staticmethod
    def _mime(path: Path) -> str:
        mime = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        if mime.startswith("text/") or mime in ("application/javascript", "application/json"):
            mime += "; charset=utf-8"
        return mime

    def _is_os_probe_ua(self) -> bool:
        """Java/OEM connectivity checker, not a browser or the sign-in WebView."""
        ua = (self.headers.get("User-Agent") or "").strip().lower()
        return bool(ua) and any(marker in ua for marker in OS_PROBE_UA_MARKERS)

    # ---- routing ----------------------------------------------------------
    def _dispatch(self, head: bool, force_redirect: bool = False) -> None:
        """Route the request and write exactly one access-log line for it."""
        self._status = 0
        server: PortalHTTPServer = self.server
        try:
            self._route(head, force_redirect)
        finally:
            if server.log_http:
                with server._lock:
                    server.request_count += 1
                    number = server.request_count
                ua = (self.headers.get("User-Agent") or "-").replace("\r", " ").replace("\n", " ")
                ua = ua[:87] + "..." if len(ua) > 90 else ua
                host = (self.headers.get("Host") or "-").replace("\r", "").replace("\n", "")
                log(f"HTTP #{number} {self.command} {self.path} -> {self._status or 'ERR'} "
                    f"client={self.client_address[0]} host={host} ua={ua}")

    def _route(self, head: bool, force_redirect: bool = False) -> None:
        path = unquote(urlsplit(self.path).path) or "/"
        low = path.lower().rstrip("/") or "/"
        server: PortalHTTPServer = self.server

        # RFC 8908 Captive Portal API. This MUST be a 200 with the exact media
        # type; a 302 (or a JSON content type) makes clients ignore it.
        if low in CAPTIVE_API_PATHS:
            if server.capport_api:
                self._captive_api(head)
            else:
                self._empty(404, head)
            return

        # Exact esp32_sd_frp.ino behaviour: EVERY OS probe gets a 302, no
        # exceptions. Do not content-negotiate here - a 200 on a probe URL
        # (even a valid RFC 8908 JSON document) leaves the OS without a
        # redirectUrl, so it cannot open the sign-in page. The capport
        # document is served only on its three dedicated API paths above.
        # AOSP NetworkMonitor.sendHttpProbe() reads the "location" header and
        # does NOT follow the redirect (followRedirect is false for probes).
        if force_redirect or low in PROBE_PATHS:
            self._redirect(head)
            return

        # Samsung SM-S948B (Android 17) sends exactly one HTTP request after
        # connecting: GET / with a Dalvik/2.1.0 UA, Host = gateway IP. The .ino
        # served 200 there, and no sign-in UI ever appeared. A 302 is the only
        # thing an OS checker recognises as "captive". /index.html is the same
        # page but is exempt from this rule, so following the redirect cannot
        # loop. Real browsers keep getting the HTML directly at /.
        if (low == "/" and server.redirect_os_probes and self._is_os_probe_ua()):
            self._redirect(head, target=server.portal_url() + "index.html")
            return

        if low == "/" or low == "/index.html":
            index = server.web_root / "index.html"
            if not index.is_file():
                self._error(500, "ERROR: /index.html not found in the web folder", head)
                return
            self._stream(index, head, as_attachment=False)
            return

        if low == "/status/download" or low == "/api/download-status":
            self._json(server.download_status(), head)
            return

        if low == "/api/files":
            self._json(self._file_listing(), head)
            return

        if low == "/api/status":
            dns_queries = server.dns_server.queries if server.dns_server else 0
            self._json({
                "online": True,
                "ssid": server.ssid,
                "portal_ip": server.portal_url(),
                "dns_queries": dns_queries,
                "connected_clients": server.connected_clients,
                "download": server.download_status(),
                "files": len(self._file_listing()["files"]),
            }, head)
            return

        if low == "/favicon.ico":
            icon = server.web_root / "favicon.ico"
            if icon.is_file():
                self._stream(icon, head, as_attachment=False)
            else:
                self._empty(204, head)
            return

        if low == "/wpad.dat":
            self._empty(404, head)
            return

        if low.startswith("/download/") or low == "/download":
            rel = path[len("/download"):].lstrip("/")
            self._download(rel, head)
            return

        # serveStatic(LittleFS) equivalent
        candidate = _resolve_in(server.web_root, path.lstrip("/"))
        if candidate and candidate.is_file():
            self._stream(candidate, head, as_attachment=False)
            return

        # A missing static file is a real 404, not a captive portal probe.
        # Keeps <img> fallbacks instant and avoids resetting the probe dance.
        if _is_asset_path(low):
            self._empty(404, head)
            return

        # onNotFound equivalent: everything else is a captive portal probe
        self._redirect(head)

    def _error(self, status: int, text: str, head: bool) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if not head:
            try:
                self.wfile.write(body)
            except OSError:
                pass
        self.close_connection = True

    # ---- data -------------------------------------------------------------
    def _file_listing(self) -> dict:
        root: Path = self.server.shared_root
        files = []
        if root.is_dir():
            for p in sorted(root.rglob("*")):
                if p.is_file():
                    rel = p.relative_to(root).as_posix()
                    try:
                        size = p.stat().st_size
                    except OSError:
                        continue
                    files.append({
                        "name": rel,
                        "size": size,
                        "url": "/download/" + quote(rel, safe="/"),
                    })
        return {"files": files, "count": len(files), "total_bytes": sum(f["size"] for f in files)}

    # ---- streaming --------------------------------------------------------
    def _stream(self, path: Path, head: bool, as_attachment: bool,
                filename: str | None = None) -> None:
        server: PortalHTTPServer = self.server
        try:
            size = path.stat().st_size
        except OSError:
            self._empty(404, head)
            return

        self.send_response(200)
        self.send_header("Content-Type",
                         "application/octet-stream" if as_attachment else self._mime(path))
        self.send_header("Content-Length", str(size))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        if as_attachment:
            name = filename or path.name
            ascii_name = name.encode("ascii", "replace").decode().replace('"', "")
            self.send_header(
                "Content-Disposition",
                'attachment; filename="' + ascii_name + '"; filename*=UTF-8\'\'' + quote(name),
            )
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        if head:
            return

        # Socket timeout doubles as the ESP32's DOWNLOAD_IDLE_TIMEOUT: if a
        # single write stalls for that long, the transfer is aborted.
        self.connection.settimeout(server.idle_timeout)
        sent, cancelled, timed_out = 0, False, False
        last_logged = 0
        try:
            with path.open("rb") as fh:
                while sent < size:
                    chunk = fh.read(min(server.download_chunk, size - sent))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    sent += len(chunk)
                    server.update_progress(sent, size)
                    if as_attachment and (sent - last_logged >= BYTES_PER_MB or sent >= size):
                        last_logged = sent
                        unit = "B" if size < 1024 else "KB"
                        div = 1 if size < 1024 else 1024
                        log(f"Progress: {sent / div:.0f} {unit} / {size / div:.0f} {unit} "
                            f"({sent * 100 / size:.0f}%)")
                self.wfile.flush()
        except socket.timeout:
            timed_out, cancelled = True, True
            log("[TIMEOUT] Download stopped - no progress")
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            cancelled = True
            log("[CANCELLED] Client disconnected")
        except OSError as exc:
            cancelled = True
            log(f"[CANCELLED] {exc}")
        finally:
            if as_attachment:
                if cancelled:
                    log("[STOP] Closing download connection")
                elif sent >= size:
                    log("[OK] Download completed")
                else:
                    log("[ERROR] Download incomplete")
                log(f"Transferred: {sent} / {size} bytes")
            server.update_progress(sent, size)

    def _download(self, rel: str, head: bool) -> None:
        server: PortalHTTPServer = self.server
        log("========== FILE DOWNLOAD ==========")
        log(f"Requested: {self.path}")
        log(f"Shared file: {rel!r}")

        candidate = _resolve_in(server.shared_root, rel)
        if candidate is None:
            log("[ERROR] Invalid path")
            self._error(403, "Forbidden", head)
            return
        if not candidate.is_file():
            log("[ERROR] File not found")
            self._error(404, "File not found", head)
            return
        if not server.acquire_download(candidate.name):
            log("[BUSY] Download already in progress")
            self._error(503, "Download already in progress", head)
            return

        try:
            log(f"File name: {candidate.name}")
            log(f"File size: {candidate.stat().st_size} bytes")
            log("[OK] HTTP headers sent")
            log("Starting file transfer...")
            self._stream(candidate, head, as_attachment=True, filename=candidate.name)
        finally:
            server.release_download()
            log("Download slot released")
            rule()
