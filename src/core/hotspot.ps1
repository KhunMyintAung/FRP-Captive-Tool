<#
    WinRT Mobile Hotspot helper for the FRP Tool captive portal.

    Runs under Windows PowerShell 5.1 (built into Windows), because WinRT
    projection is available there. No Add-Type / third-party modules needed.

    All arguments arrive as one base64-encoded JSON payload so that SSIDs and
    passwords containing spaces or quotes survive intact.

    Actions: status | addresses | configure | start | stop
    Output:  a single compressed JSON object on stdout.
#>
param([Parameter(Mandatory = $true)][string]$Payload)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8

$out = @{
    ok            = $true
    action        = ''
    state         = ''
    profile       = ''
    ssid          = ''
    clients       = 0
    max_clients   = 0
    addresses     = @()
    dhcp_address  = ''
    band          = ''
    message       = ''
}

# Windows 11 24H2+ lets the hotspot pick its own band ("Auto"), and it often
# chooses 5 GHz. Phones that only scan 2.4 GHz then never see the SSID, so the
# Python side can request a specific band. Older Windows versions lack the Band
# property entirely - the try/catch keeps them working unchanged.
function Set-Band($ap, [string]$band) {
    if ([string]::IsNullOrEmpty($band) -or $band -eq 'auto') { return }
    try {
        $t = [Windows.Networking.NetworkOperators.TetheringWiFiBand]
        if ($band -eq '2.4') { $ap.Band = $t::TwoPointFourGigahertz }
        elseif ($band -eq '5') { $ap.Band = $t::FiveGigahertz }
    } catch { }
}

function Get-ConnectionProfile {
    $ni = [Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType = WindowsRuntime]
    $p = $ni::GetInternetConnectionProfile()
    if ($null -ne $p) { return $p }
    foreach ($q in $ni::GetConnectionProfiles()) {
        if ($q.GetNetworkConnectivityLevel().ToString() -ne 'None') { return $q }
    }
    return $null
}

function Wait-ForState($tm, $want, $seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        if ($tm.TetheringOperationalState.ToString() -eq $want) { return $true }
        Start-Sleep -Milliseconds 350
    }
    return $false
}

try {
    $cfg = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Payload)) | ConvertFrom-Json
    $out.action = [string]$cfg.action

    $profile = Get-ConnectionProfile
    if ($null -eq $profile) {
        throw 'No active network connection profile found. Enable Wi-Fi or Ethernet first.'
    }
    $out.profile = [string]$profile.ProfileName

    $mgrType = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager, Windows.Networking.NetworkOperators, ContentType = WindowsRuntime]
    $tm = $mgrType::CreateFromConnectionProfile($profile)
    $out.state = $tm.TetheringOperationalState.ToString()

    try { $out.max_clients = [int]$tm.MaxClientCount } catch { }
    try { $out.clients = [int]$tm.GetTetheringClients().Count } catch { }
    try { $out.ssid = [string]$tm.GetCurrentAccessPointConfiguration().Ssid } catch { }

    switch ($out.action) {
        'status' { }

        'addresses' { }

        'configure' {
            if ([string]::IsNullOrEmpty([string]$cfg.ssid)) { throw 'SSID is empty.' }
            $ap = $tm.GetCurrentAccessPointConfiguration()
            $ap.Ssid = [string]$cfg.ssid
            if (-not [string]::IsNullOrEmpty([string]$cfg.passphrase)) {
                $ap.Passphrase = [string]$cfg.passphrase
            }
            Set-Band $ap ([string]$cfg.band)
            $null = $tm.ConfigureAccessPointAsync($ap)
            Start-Sleep -Milliseconds 900
            $out.ssid = [string]$tm.GetCurrentAccessPointConfiguration().Ssid
        }

        'start' {
            # Always restart: the hotspot must be OFF before our DNS socket
            # claims UDP 53, otherwise ICS keeps its own DNS proxy there.
            if ($tm.TetheringOperationalState.ToString() -ne 'Off') {
                $null = $tm.StopTetheringAsync()
                if (-not (Wait-ForState $tm 'Off' 12)) { throw 'Could not stop the existing hotspot.' }
            }

            if (-not [string]::IsNullOrEmpty([string]$cfg.ssid)) {
                $ap = $tm.GetCurrentAccessPointConfiguration()
                $ap.Ssid = [string]$cfg.ssid
                if (-not [string]::IsNullOrEmpty([string]$cfg.passphrase)) {
                    $ap.Passphrase = [string]$cfg.passphrase
                }
                Set-Band $ap ([string]$cfg.band)
                $null = $tm.ConfigureAccessPointAsync($ap)
                Start-Sleep -Milliseconds 900
            }

            $null = $tm.StartTetheringAsync()
            if (-not (Wait-ForState $tm 'On' 20)) {
                throw ('Hotspot did not reach On state (last: ' + $tm.TetheringOperationalState.ToString() + ').')
            }
        }

        'stop' {
            if ($tm.TetheringOperationalState.ToString() -ne 'Off') {
                $null = $tm.StopTetheringAsync()
                if (-not (Wait-ForState $tm 'Off' 12)) { throw 'Could not stop the hotspot.' }
            }
        }

        default { throw ('Unknown action: ' + $out.action) }
    }

    $out.state = $tm.TetheringOperationalState.ToString()
    try { $out.clients = [int]$tm.GetTetheringClients().Count } catch { }
    try { $out.ssid = [string]$tm.GetCurrentAccessPointConfiguration().Ssid } catch { }
    try { $out.band = [string]$tm.GetCurrentAccessPointConfiguration().Band } catch { }

    # ICS starts its DHCP server a few seconds AFTER WinRT reports "On".
    # Waiting here makes dhcp_address (the real client gateway) reliable and
    # lets the Python side detect a hotspot that is On but not serving clients.
    if ($out.action -eq 'start') {
        $dhcpDeadline = (Get-Date).AddSeconds(10)
        while ((Get-Date) -lt $dhcpDeadline) {
            $probe = Get-NetUDPEndpoint -LocalPort 67 -ErrorAction SilentlyContinue |
                     Where-Object { $_.LocalAddress -ne '0.0.0.0' } |
                     Select-Object -First 1
            if ($null -ne $probe) { break }
            Start-Sleep -Milliseconds 400
        }
    }

    $list = @()
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -ne '0.0.0.0') {
            $list += @{ alias = [string]$_.InterfaceAlias; ip = [string]$_.IPAddress; prefix = [int]$_.PrefixLength; index = [int]$_.InterfaceIndex }
        }
    }
    $out.addresses = $list

    # The ICS DHCP endpoint tells us which address clients actually use as
    # their gateway / DNS server. That is the address our portal must answer on.
    try {
        $ep = Get-NetUDPEndpoint -LocalPort 67 -ErrorAction Stop |
              Where-Object { $_.LocalAddress -ne '0.0.0.0' } |
              Select-Object -First 1
        if ($ep) { $out.dhcp_address = [string]$ep.LocalAddress }
    } catch {
        foreach ($line in (netstat -ano -p udp | Select-String ':67\s')) {
            $m = [regex]::Match($line.ToString(), '(\d+\.\d+\.\d+\.\d+):67')
            if ($m.Success) { $out.dhcp_address = $m.Groups[1].Value; break }
        }
    }
}
catch {
    $out.ok = $false
    $out.message = $_.Exception.Message
}

$out | ConvertTo-Json -Compress -Depth 6
