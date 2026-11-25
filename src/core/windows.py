"""Windows-only glue: elevation, WinRT hotspot, IP detection, firewall rules.

Also manages the temporary non-RFC1918 address used to work around Android's
private-IP DNS probe check (see core/dns.py for the full explanation).
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import subprocess
import sys
from pathlib import Path

from .log import warn

# Windows PowerShell 5.1 must be used explicitly. PowerShell 7 (.NET Core)
# no longer projects WinRT types, so "pwsh" would fail here.
_PS = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"


def _helper_path() -> Path:
    """Locate hotspot.ps1 next to this module, or beside a packaged .exe."""
    candidates = []
    if getattr(sys, "frozen", False):
        # The copy users can see next to the exe wins over the bundled one.
        base = Path(sys.executable).resolve().parent
        candidates += [base / "core" / "hotspot.ps1", base / "hotspot.ps1"]
    candidates.append(Path(__file__).resolve().with_name("hotspot.ps1"))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


_HELPER = _helper_path()

FW_HTTP = "FRP Portal HTTP"
FW_DNS = "FRP Portal DNS"

# Without this every powershell.exe / netsh.exe call would open a console window
# when the tool runs from a GUI build (pythonw / FRP-Tool.exe have no console).
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


# --------------------------------------------------------------------------
# Privileges
# --------------------------------------------------------------------------
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate() -> None:
    """Relaunch this script with UAC elevation, then exit the current process."""
    script = str(Path(sys.argv[0]).resolve())
    params = subprocess.list2cmdline([script, *sys.argv[1:]])
    rc = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, None, 1
    )
    if int(rc) <= 32:
        raise RuntimeError("Administrator elevation was declined.")
    sys.exit(0)


# --------------------------------------------------------------------------
# WinRT helper bridge
# --------------------------------------------------------------------------
def ps_action(action: str, ssid: str = "", passphrase: str = "", band: str = "",
              timeout: int = 45) -> dict:
    """Invoke hotspot.ps1 and return its decoded JSON result."""
    payload = {"action": action, "ssid": ssid, "passphrase": passphrase, "band": band}
    encoded = base64.b64encode(json.dumps(payload, ensure_ascii=False).encode("utf-8")).decode("ascii")
    cmd = [
        str(_PS),
        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", str(_HELPER),
        "-Payload", encoded,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                              creationflags=_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "message": f"helper failed: {exc}", "state": "", "addresses": []}

    text = proc.stdout.decode("utf-8", "replace")
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    err = proc.stderr.decode("utf-8", "replace").strip()
    return {"ok": False, "message": (err or text or "no output from helper").strip()[:400],
            "state": "", "addresses": []}


def detect_portal_ifindex(ip: str, result: dict) -> int:
    """Interface index owning the portal IP, from the helper's address list."""
    for item in result.get("addresses") or []:
        if str(item.get("ip")) == ip:
            try:
                return int(item.get("index") or 0)
            except (TypeError, ValueError):
                return 0
    return 0


def detect_portal_ip(configured: str, result: dict) -> str:
    """Work out the address the hotspot clients will use as gateway + DNS."""
    if configured:
        return configured

    dhcp = str(result.get("dhcp_address") or "").strip()
    if dhcp:
        return dhcp

    addresses = result.get("addresses") or []
    for item in addresses:
        if str(item.get("ip")) == "192.168.137.1":
            return "192.168.137.1"
    for item in addresses:
        ip = str(item.get("ip", ""))
        alias = str(item.get("alias", ""))
        if alias.startswith("Local Area Connection") and ip.endswith(".1"):
            return ip
    return "192.168.137.1"


# --------------------------------------------------------------------------
# Windows Defender Firewall
# --------------------------------------------------------------------------
def _netsh(*args: str) -> tuple[int, str]:
    try:
        proc = subprocess.run(["netsh", *args], capture_output=True, timeout=20,
                              creationflags=_NO_WINDOW)
        return proc.returncode, (proc.stdout + proc.stderr).decode("utf-8", "replace").strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, str(exc)


# --------------------------------------------------------------------------
# Temporary non-private IPv4 alias (Android captive-portal compatibility)
# --------------------------------------------------------------------------
# Android 14+ short-circuits its HTTP captive-portal probe when the probe
# hostname resolves to an RFC1918 address. 192.0.2.1 (RFC 5737 TEST-NET-1)
# is not "site local" to Java's InetAddress, so it passes that check, while
# still being an address this PC owns and can answer HTTP on.
_ADD_ALIAS_PS = r"""
$ErrorActionPreference = 'Stop'
$alias   = '__ALIAS__'
$primary = '__PRIMARY__'
$ifidx   = [int]__IFIDX__
$r = @{ ok = $false; added = $false; index = 0; interface = '';
       state = ''; dad_before = -1; dad_restored = $false; message = '' }
try {
    $t = $null
    if ($ifidx -gt 0) {
        $t = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $ifidx -ErrorAction SilentlyContinue |
             Select-Object -First 1
    }
    if ($null -eq $t) {
        $t = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
             Where-Object { $_.IPAddress -eq $primary } | Select-Object -First 1
    }
    if ($null -eq $t) { throw "no adapter owns $primary (ifIndex $ifidx)" }
    $r.index = [int]$t.InterfaceIndex
    $r.interface = [string]$t.InterfaceAlias

    $found = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
               Where-Object { $_.IPAddress -eq $alias })
    # A leftover address in Tentative (DAD never finished) is useless: remove it.
    # ActiveStore addresses are often reported 'Deprecated' (preferred lifetime
    # 0) but are perfectly usable for receiving, so that state is fine.
    $okStates = @('Preferred', 'Deprecated')
    $bad = @($found | Where-Object { $_.AddressState.ToString() -notin $okStates })
    if ($bad.Count -gt 0) {
        $bad | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        $found = @()
    }

    if ($found.Count -eq 0) {
        # On the ICS virtual adapter, IPv4 DAD never completes and a newly
        # added address stays 'Tentative' forever - Windows then refuses to
        # deliver packets to it. Temporarily turn DAD off, add the address,
        # then restore the original value immediately (the address stays
        # Preferred). Verified empirically on this machine.
        $dadLine = (netsh interface ipv4 show interface $r.index |
                    Select-String 'DAD Transmits')
        if ($dadLine) {
            $m = [regex]::Match($dadLine.ToString(), ':\s*(\d+)')
            if ($m.Success) { $r.dad_before = [int]$m.Groups[1].Value }
        }
        $restore = if ($r.dad_before -ge 0) { $r.dad_before } else { 3 }
        netsh interface ipv4 set interface $r.index dadtransmits=0 | Out-Null
        try {
            New-NetIPAddress -InterfaceIndex $r.index -IPAddress $alias -PrefixLength 32 `
                -SkipAsSource $true -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
        } finally {
            netsh interface ipv4 set interface $r.index "dadtransmits=$restore" | Out-Null
            $r.dad_restored = $true
        }
        $r.added = $true
    }

    $final = Get-NetIPAddress -IPAddress $alias -ErrorAction SilentlyContinue |
             Select-Object -First 1
    if ($null -eq $final) { throw 'alias did not appear on the interface' }
    $r.state = [string]$final.AddressState
    $r.ok = ($r.state -in $okStates)
    if (-not $r.ok) { $r.message = "alias address state is $($r.state)" }
} catch {
    $r.message = [string]$_.Exception.Message
}
$r | ConvertTo-Json -Compress
"""

_REMOVE_ALIAS_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$alias = '__ALIAS__'
$r = @{ ok = $false; removed = 0; message = '' }
try {
    $found = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
               Where-Object { $_.IPAddress -eq $alias })
    foreach ($f in $found) {
        $f | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    }
    $left = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
              Where-Object { $_.IPAddress -eq $alias }).Count
    $r.removed = $found.Count - $left
    $r.ok = ($left -eq 0)
    if (-not $r.ok) { $r.message = 'alias still present' }
} catch {
    $r.message = [string]$_.Exception.Message
}
$r | ConvertTo-Json -Compress
"""


def _ps_json(script: str, timeout: int = 30) -> dict:
    """Run a PowerShell 5.1 script and decode the JSON object it prints."""
    cmd = [
        str(_PS), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-Command", script,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                              creationflags=_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "message": f"PowerShell failed: {exc}"}
    text = proc.stdout.decode("utf-8", "replace")
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    err = proc.stderr.decode("utf-8", "replace").strip()
    return {"ok": False, "message": (err or text or "no output").strip()[:300]}


def add_probe_alias(alias_ip: str, primary_ip: str, ifindex: int = 0) -> dict:
    """Add a non-persistent secondary IPv4 address to the hotspot adapter.

    ActiveStore (not PersistentStore) means it disappears after a reboot, and
    SkipAsSource keeps Windows from using it for its own outbound traffic.
    Returns a dict; ``added`` tells us whether *we* must remove it later.
    """
    script = (_ADD_ALIAS_PS.replace("__ALIAS__", alias_ip)
                          .replace("__PRIMARY__", primary_ip)
                          .replace("__IFIDX__", str(int(ifindex or 0))))
    return _ps_json(script)


def remove_probe_alias(alias_ip: str) -> dict:
    script = _REMOVE_ALIAS_PS.replace("__ALIAS__", alias_ip)
    return _ps_json(script)


_HAS_ADDR_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$ip = '__IP__'
$found = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -eq $ip })
@{ ok = ($found.Count -gt 0); count = [int]$found.Count } | ConvertTo-Json -Compress
"""


def has_local_address(ip: str) -> bool:
    """True if this PC already owns ``ip`` (so no adapter change is needed)."""
    return bool(_ps_json(_HAS_ADDR_PS.replace("__IP__", ip)).get("ok"))


def add_firewall_rules(http_port: int, dns_port: int) -> None:
    remove_firewall_rules()
    specs = [
        (FW_HTTP, "TCP", http_port),
        (FW_DNS, "UDP", dns_port),
    ]
    for name, proto, port in specs:
        rc, out = _netsh(
            "advfirewall", "firewall", "add", "rule",
            f"name={name}", "dir=in", "action=allow",
            f"protocol={proto}", f"localport={port}", "profile=any",
        )
        if rc != 0:
            warn(f"Firewall rule '{name}' could not be added: {out}")
        else:
            from .log import ok
            ok(f"Firewall: allow inbound {proto}/{port}")


def remove_firewall_rules() -> None:
    for name in (FW_HTTP, FW_DNS):
        _netsh("advfirewall", "firewall", "delete", "rule", f"name={name}")
