"""Smart catch-all DNS server - the Windows port of the ESP32 DNSServer("*", apIP).

Key Windows detail: ICS (Internet Connection Sharing) starts its own DNS proxy
on 192.168.137.1:53 when the Mobile Hotspot comes up. We therefore bind UDP 53
*before* starting the hotspot, with SO_EXCLUSIVEADDRUSE so no other process
(including ICS) can claim the port afterwards. ICS still runs DHCP on :67, so
clients get IP addresses normally and are told to use our IP for DNS.

Why "smart" is the default
--------------------------
Modern Android (and Samsung MobileWips) run DNS *sanity checks* after seeing a
captive-portal redirect. They resolve names that cannot possibly exist, e.g.::

    *google.com
    google.com.onion
    www.goooooooooooooooooooooooooooooooooooooooooooooooooooooooooogle.com
    216.58.202.4.in-addr.arpa   (PTR)

A plain catch-all answers all of them with the portal IP, so the phone decides
the network is hijacking DNS instead of being a captive portal and suppresses
the "Sign in to network" notification. That is exactly what a real-device test
showed. The ``smart`` mode answers those names with a proper NXDOMAIN (plus an
SOA record, like a real resolver) while still redirecting every real hostname,
so the HTTP probe on /generate_204 reaches our web server and the popup appears.

Second Android trap: the private-IP DNS check
--------------------------------------------
AOSP NetworkMonitor.sendDnsAndHttpProbes() (Android 14+) pre-resolves the
*HTTP* probe hostname and, when the DNS_PROBE_PRIVATE_IP_NO_INTERNET_VERSION
feature is enabled, does this BEFORE sending any HTTP request::

    if (mPrivateIpNoInternetEnabled && probeType == PROBE_HTTP
            && proxy == null && hasPrivateIpAddress(resolvedAddr)) {
        return CaptivePortalProbeResult.PRIVATE_IP;
    }

sendHttpAndHttpsParallelWithFallbackProbes() then converts PRIVATE_IP into a
plain "validation failed" result, so Android reports "no internet" and never
shows the "Sign in to network" notification. 192.168.137.1 is site-local, so a
classic catch-all hits this on every modern Android. iOS does not do this check,
which is why an iPhone gets the popup and a Samsung does not.

The fix is ``set_answer_ip()``: answer A queries with a non-RFC1918 address
that this PC also owns (a temporary secondary IP on the hotspot adapter). The
private-IP test then passes, Android actually sends its HTTP probe, and our
302 on /generate_204 produces the sign-in page. See core/windows.py.

Adapter-free alternative: the "probe dance"
-------------------------------------------
AOSP uses the result of ``sendDnsProbe(host)`` ONLY for the private-IP test
and for logging; ``sendHttpProbe()`` then opens its own HttpURLConnection,
which resolves the hostname a second time. So, if the FIRST A lookup of a
hostname returns a non-site-local address with TTL 0 (never cached), the
private-IP gate passes, and the SECOND lookup can return the real portal IP
so the HTTP probe reaches us. ``dance_ip`` implements exactly that, tracked
per (client, hostname). ``note_portal_visit()`` resets the counter as soon as
the client follows a 302, so each validation cycle starts clean. No address
is added to any adapter, which is why this cannot break Wi-Fi association.

Modes
-----
smart           real names -> portal IP, invalid/sanity names -> NXDOMAIN (default)
intercept_all   exact ESP32 behaviour: every name -> portal IP
selective       only OS connectivity-check hosts -> portal IP, all else NXDOMAIN
"""

from __future__ import annotations

import re
import socket
import struct
import threading
import time

from .log import log, ok

# Python's socket module does not expose this Windows-only option.
# ~SO_REUSEADDR == 0xFFFFFFFB == -5 when passed as a signed int.
SO_EXCLUSIVEADDRUSE = -5

# Windows NCSI checks this hostname's A record against a fixed value. Returning
# the magic address makes the DNS half of the check pass, while our HTTP 302
# on /connecttest.txt makes the HTTP half report a captive portal.
NCSI_HOST = "dns.msftncsi.com"
NCSI_MAGIC_IP = "131.107.255.255"

MODES = ("smart", "intercept_all", "selective")

# Hostnames the operating systems actually probe. In ``selective`` mode these
# are the ONLY names we hijack; everything else gets NXDOMAIN.
PROBE_HOSTS = frozenset({
    # Android / ChromeOS
    "connectivitycheck.gstatic.com", "connectivitycheck.android.com",
    "clients3.google.com", "clients.l.google.com",
    "www.google.com", "google.com", "www.gstatic.com",
    "android.clients.google.com", "play.googleapis.com",
    # Windows NCSI
    "www.msftconnecttest.com", "www.msftncsi.com", "ipv6.msftncsi.com",
    "dns.msftncsi.com", "msftncsi.com", "www.msftncsi.net",
    # Apple
    "captive.apple.com", "www.apple.com", "www.appleiphonecell.com",
    "www.airport.us", "www.thinkdifferent.us", "www.ibook.info",
    # Firefox / others
    "detectportal.firefox.com", "success.mozilla.com",
    "www.neverssl.com", "neverssl.com", "portal.example.com",
})

# RFC 6761 / special-use suffixes: these can never resolve on the public
# Internet, so answering them with an A record is a dead giveaway of DNS
# interception. Reverse-DNS namespaces belong here as well.
INVALID_SUFFIXES = (
    ".onion", ".invalid", ".test", ".local", ".localhost", ".example",
    ".internal", ".home.arpa", ".in-addr.arpa", ".ip6.arpa", ".arpa",
    ".localdomain", ".onion.net",
)

def is_private_probe_ip(ip: str) -> bool:
    """Would Android's hasPrivateIpAddress() reject this DNS answer?

    Mirrors Java's InetAddress.isSiteLocalAddress() / isLinkLocalAddress()
    plus AOSP's isIPv6ULA(). 10/8, 172.16/12, 192.168/16 and 169.254/16 are
    rejected; TEST-NET, CGNAT and ordinary public addresses are accepted.
    """
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if addr.version == 6:
        return addr.is_link_local or addr.is_loopback or addr.is_site_local or addr.is_private
    nets = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "169.254.0.0/16", "127.0.0.0/8", "0.0.0.0/8")
    return any(addr in ipaddress.IPv4Network(n) for n in nets)


_LABEL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_")
# A label made of one repeated character (the gooooo...google.com probe) is a
# deliberate "this must not exist" name. Real hostnames never look like this.
_LONG_RUN = re.compile(r"(.)\1{9,}", re.IGNORECASE)


def _invalid_reason(name: str) -> str:
    """Return a short reason if this name must NOT resolve, else an empty string."""
    if not name or name == ".":
        return "empty name"
    if len(name) > 253:
        return "name too long"
    labels = name.split(".")
    if len(labels) < 2:
        return "single-label name"
    tld = labels[-1]
    if not tld.isalpha() or len(tld) < 2:
        return "numeric / invalid TLD"
    for suffix in INVALID_SUFFIXES:
        if name.endswith(suffix) or name == suffix.lstrip("."):
            return f"special-use domain {suffix}"
    for label in labels:
        if not label or len(label) > 63:
            return "bad label length"
        if any(ch not in _LABEL_CHARS for ch in label):
            return "illegal character"
        if label[0] == "-" or label[-1] == "-":
            return "bad hyphen"
        if _LONG_RUN.search(label):
            return "sanity-check label"
    return ""


def classify(qname: str, mode: str) -> tuple[str, str]:
    """Decide a query: ('answer'|'nxdomain', reason). Pure, easy to unit test."""
    if mode == "intercept_all":
        return "answer", ""
    reason = _invalid_reason(qname)
    if reason:
        return "nxdomain", reason
    if mode == "selective" and qname not in PROBE_HOSTS:
        return "nxdomain", "not an OS probe host"
    return "answer", ""


def _read_name(data: bytes, off: int) -> tuple[str, int]:
    """Decode a DNS name, following compression pointers."""
    labels: list[str] = []
    end = None
    for _ in range(64):
        if off >= len(data):
            raise ValueError("truncated name")
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                raise ValueError("truncated pointer")
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            if end is None:
                end = off + 2
            off = ptr
            continue
        off += 1
        if off + length > len(data):
            raise ValueError("truncated label")
        labels.append(data[off:off + length].decode("ascii", "replace"))
        off += length
    if end is None:
        end = off
    return ".".join(labels).lower(), end


# Minimal authority section, so the NXDOMAIN looks like a real resolver answer
# and clients cache the negative result properly.
_SOA_RDATA = (
    b"\x03dns\x06portal\x00"          # mname: dns.portal.
    b"\x05admin\x06portal\x00"        # rname: admin.portal.
    + struct.pack("!IIIII", 1, 3600, 600, 86400, 30)
)


class CaptiveDNS:
    def __init__(self, portal_ip: str, port: int = 53, ttl: int = 30,
                 verbose: bool = False, mode: str = "smart",
                 answer_ip: str = "", dance_ip: str = "",
                 dance_window: float = 20.0):
        if mode not in MODES:
            raise ValueError(f"unknown DNS mode {mode!r}; expected one of {MODES}")
        self.port = port
        self.ttl = ttl
        self.verbose = verbose
        self.mode = mode
        self._ip = portal_ip
        # When set, A records use this address instead of the portal IP. It
        # must be an address this machine owns (see core/windows.py aliases).
        self._answer_ip = answer_ip
        # Experimental adapter-free Android workaround (see module docstring).
        self._dance_ip = dance_ip
        self._dance_window = max(1.0, float(dance_window))
        self._dance_seen: dict[tuple[str, str], tuple[int, float]] = {}
        self.dance_first_answers = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._seen: set[str] = set()
        self.queries = 0
        self.nxdomain = 0
        self.answered = 0
        self.sock: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def set_portal_ip(self, ip: str) -> None:
        with self._lock:
            self._ip = ip
        ok(f"Portal IP set to {ip}")

    def set_answer_ip(self, ip: str) -> None:
        """Choose the address put into A records (may differ from the portal IP)."""
        with self._lock:
            self._answer_ip = ip
        ok(f"DNS A records now answer with {ip}"
           + ("  (Android private-IP probe workaround)" if ip and ip != self._ip else ""))

    @property
    def answer_ip(self) -> str:
        with self._lock:
            return self._answer_ip or self._ip

    def note_portal_visit(self, client_ip: str) -> None:
        """A client followed a 302: its next validation cycle starts fresh."""
        if not self._dance_ip:
            return
        with self._lock:
            for key in [k for k in self._dance_seen if k[0] == client_ip]:
                del self._dance_seen[key]

    def stats(self) -> tuple[int, int, int]:
        with self._lock:
            return self.queries, self.answered, self.nxdomain

    def start(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1)
            s.bind(("0.0.0.0", self.port))
        except OSError as exc:
            s.close()
            raise RuntimeError(
                f"Cannot bind UDP/{self.port} ({exc}). Another DNS service is running, "
                "or the hotspot was already on. Close it and restart the tool."
            ) from exc
        s.settimeout(0.5)
        self.sock = s
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="dns", daemon=True)
        self._thread.start()
        ok(f"DNS server listening on 0.0.0.0:{self.port} "
           f"(exclusive, mode={self.mode}, all valid A -> {self.answer_ip}"
           + (f", probe dance {self._dance_ip}" if self._dance_ip else "") + ")")

    def _probe(self, name: str, qtype: int = 1, timeout: float = 1.0) -> bytes | None:
        query = (
            struct.pack("!6H", 0xF001, 0x0100, 1, 0, 0, 0)
            + b"".join(bytes([len(l)]) + l.encode("ascii") for l in name.split("."))
            + b"\x00" + struct.pack("!HH", qtype, 1)
        )
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(query, ("127.0.0.1", self.port))
            data, _ = s.recvfrom(512)
            return data
        except OSError:
            return None
        finally:
            s.close()

    def self_test(self, timeout: float = 1.0) -> bool:
        """Round-trip one query against ourselves.

        Some VPN clients install an outbound-only WFP block on remote port 53
        (DNS-leak protection). That breaks this local probe but does NOT affect
        inbound queries from Wi-Fi clients, so a failure is only a diagnostic.
        """
        data = self._probe("portal-test.frptool.com", 1, timeout)
        return bool(data and len(data) > 12 and data[2] & 0x80)

    def sanity_test(self, timeout: float = 0.6) -> str:
        """Verify the four names a phone uses to detect DNS hijacking.

        Returns a compact human-readable result. Useful in the startup banner;
        a failure here means an outbound port-53 block on the host, not a bug
        in the DNS logic (Wi-Fi clients' inbound DNS still works).
        """
        names = ("*google.com", "google.com.onion",
                 "www.goooooooooooooooooooooooooooooooooooooooooooooooooooooooooogle.com",
                 "216.58.202.4.in-addr.arpa")
        results = []
        for name in names:
            data = self._probe(name, 12 if "in-addr.arpa" in name else 1, timeout)
            if data is None:
                results.append(f"{name[:22]}=timeout")
            else:
                rcode = struct.unpack("!H", data[2:4])[0] & 0x000F
                results.append(f"{name[:22]}={'NXDOMAIN' if rcode == 3 else 'rcode' + str(rcode)}")
        return ", ".join(results)

    def stop(self) -> None:
        self._stop.set()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2)

    def _loop(self) -> None:
        assert self.sock is not None
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                response = self._reply(data, addr[0])
            except (ValueError, struct.error, OSError):
                continue
            if response:
                try:
                    self.sock.sendto(response, addr)
                except OSError:
                    pass

    def _reply(self, data: bytes, client: str = "") -> bytes | None:
        if len(data) < 12:
            return None
        tid, flags, qdcount = struct.unpack("!HHH", data[:6])
        if flags & 0x8000 or qdcount < 1:      # response, or no question
            return None

        qname, end = _read_name(data, 12)
        if end + 4 > len(data):
            return None
        qtype, qclass = struct.unpack("!HH", data[end:end + 4])
        question = data[12:end + 4]

        decision, reason = classify(qname, self.mode)

        with self._lock:
            portal_ip = self._answer_ip or self._ip
            self.queries += 1
            if decision == "nxdomain":
                self.nxdomain += 1
            else:
                self.answered += 1

        show = self.verbose or qname not in self._seen
        if show and len(self._seen) < 500:
            self._seen.add(qname)

        if decision == "nxdomain":
            if show:
                log(f"DNS {qname} (type {qtype}) -> NXDOMAIN  [{reason}]")
            # QR + AA + RA + echoed RD + RCODE 3, one echoed question, one SOA.
            rflags = 0x8483 | (flags & 0x0100)
            soa = b"\xc0\x0c" + struct.pack("!HHIH", 6, 1, 30, len(_SOA_RDATA)) + _SOA_RDATA
            return struct.pack("!6H", tid, rflags, 1, 0, 1, 0) + question + soa

        if qclass != 1:
            return struct.pack("!6H", tid, 0x8180, 1, 0, 0, 0) + question

        answer_ip = NCSI_MAGIC_IP if (qname == NCSI_HOST and qtype == 1) else portal_ip
        ttl = self.ttl
        dance_note = ""

        # Adapter-free Android 14+ workaround. sendDnsProbe() (the private-IP
        # gate) resolves first; sendHttpProbe() resolves again. Give the first
        # A lookup a non-site-local answer with TTL 0 so netd cannot cache it,
        # then answer the real portal IP for the HTTP connection itself.
        if self._dance_ip and qtype == 1 and qclass == 1 and qname != NCSI_HOST:
            now = time.monotonic()
            key = (client, qname)
            with self._lock:
                count, started = self._dance_seen.get(key, (0, now))
                if now - started > self._dance_window:
                    count, started = 0, now
                first = count == 0
                self._dance_seen[key] = (count + 1, started)
                if first:
                    self.dance_first_answers += 1
                if len(self._dance_seen) > 500:
                    for k, (_, ts) in list(self._dance_seen.items()):
                        if now - ts > self._dance_window:
                            del self._dance_seen[k]
            ttl = 0
            if first:
                answer_ip = self._dance_ip
                dance_note = "  [probe dance: non-site-local first lookup]"

        # A / IN gets our address; AAAA gets an empty NOERROR so IPv6 clients
        # fall back to IPv4 instead of going off-network.
        if qtype == 1:
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4)
            try:
                answer += socket.inet_aton(answer_ip)
            except OSError:
                answer += socket.inet_aton("192.168.137.1")
            ancount = 1
            resolved = answer_ip
        else:
            answer = b""
            ancount = 0
            resolved = "(no record)"

        if show or dance_note:
            log(f"DNS {qname} (type {qtype}) -> {resolved}{dance_note}")

        # QR + RD + RA, one echoed question, N answers.
        return struct.pack("!6H", tid, 0x8180, 1, ancount, 0, 0) + question + answer
