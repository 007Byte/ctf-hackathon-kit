<#
.SYNOPSIS
    Passive Wi-Fi security auditor for Windows (PowerShell 7+ / 5.1-safe).

.DESCRIPTION
    Get-WifiAudit is a PASSIVE auditor (it does NOT crack, deauth, or attack
    anything). It uses the built-in Windows 'netsh wlan' commands to:

      1. Enumerate nearby wireless networks via
         'netsh wlan show networks mode=bssid', parsing SSID, BSSID, signal,
         radio type, channel, authentication and encryption.
      2. Flag weak configurations:
           - Open / no encryption           -> High
           - WEP                            -> High
           - WPA (v1) / TKIP cipher         -> Medium
           - WPA2-Personal (note)           -> Low/info
           - WPA3 / OWE                     -> Good
      3. Enumerate SAVED wireless profiles via 'netsh wlan show profiles' and
         inspect each with 'netsh wlan show profile name=<x> key=clear' to flag
         saved OPEN or weak networks (and optionally surface the stored key).

    Output is a colored console table plus optional -OutFile HTML and -Json.

.PARAMETER OutFile
    Path to write a self-contained styled HTML report. A sibling .json is also
    written when -Json is supplied.

.PARAMETER Json
    Also emit JSON (alongside the HTML report, or to stdout if no -OutFile).

.PARAMETER ShowKeys
    Include stored Wi-Fi passwords (from 'key=clear') for SAVED profiles in the
    console/report. OFF by default for privacy. See the privacy note below.

.PARAMETER SkipProfiles
    Skip the saved-profile audit and only scan nearby networks.

.EXAMPLE
    .\Get-WifiAudit.ps1
    Scan nearby networks and audit saved profiles (keys hidden).

.EXAMPLE
    .\Get-WifiAudit.ps1 -OutFile .\wifi.html -Json
    Write an HTML + JSON report.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-WifiAudit.ps1 -ShowKeys
    Include stored passwords for your own saved networks (use with care).

.NOTES
    ============================ AUTHORIZED USE ONLY ============================
    Passive scanning of broadcast Wi-Fi metadata is generally low-risk, but you
    should still only audit networks you own or are authorized to assess. Do not
    use against networks you do not control.

    PRIVACY NOTE: 'netsh wlan show profile name=<x> key=clear' reveals the stored
    password for YOUR OWN saved networks. -ShowKeys surfaces these in output;
    treat any generated report as sensitive and do not share it. Keys are only
    ever shown for profiles already saved on THIS device by the current user.
    ============================================================================

    Privileges: Listing networks/profiles works as a standard user. 'key=clear'
    requires running in the context of the user/profile owner; admin is not
    strictly required for the current user's profiles but may help.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutFile,

    [Parameter()]
    [switch]$Json,

    [Parameter()]
    [switch]$ShowKeys,

    [Parameter()]
    [switch]$SkipProfiles
)

#region ---------------------------- Helpers ---------------------------------

function Write-WifiBanner {
    [CmdletBinding()] param()
    Write-Host ''
    Write-Host '  ============================================================' -ForegroundColor Cyan
    Write-Host '   Get-WifiAudit  -  Passive Wi-Fi Security Audit' -ForegroundColor Cyan
    Write-Host '   AUTHORIZED USE ONLY. Passive scan; no attacks performed.' -ForegroundColor Yellow
    Write-Host '  ============================================================' -ForegroundColor Cyan
    Write-Host ''
}

function Get-WlanStatus {
    <#
        Inspects 'netsh wlan show interfaces' and returns a status object:
          - HasInterface : a wireless adapter exists
          - LocationBlocked : present but blocked by Location-services permission
          - Usable : queries should succeed
        On Windows 11, netsh wlan requires Location services to be ON for the
        process; otherwise WlanQueryInterface fails with error 5 even though the
        adapter is present.
    #>
    [CmdletBinding()] param()
    $status = [pscustomobject]@{ HasInterface = $false; LocationBlocked = $false; Usable = $false; Raw = $null }
    try {
        $out = & netsh.exe wlan show interfaces 2>&1
        $text = ($out | Out-String)
        $status.Raw = $text

        if ($text -match 'There is no wireless interface|not have any wireless|no wireless interface') {
            return $status   # genuinely no adapter
        }
        if ($text -match 'is not running|service.*not running|AutoConfig.*not running') {
            return $status   # WLAN AutoConfig service stopped
        }
        # Adapter exists if netsh reports interface count or per-interface fields.
        if ($text -match 'interface on the system|There (?:is|are) \d+ interface|Name\s*:\s|SSID\s*:\s') {
            $status.HasInterface = $true
        }
        if ($text -match 'location permission|Location services|WlanQueryInterface returns error 5|requires elevation') {
            $status.HasInterface = $true
            $status.LocationBlocked = $true
            return $status
        }
        # Reached here with an interface and no block -> usable.
        if ($status.HasInterface -and $LASTEXITCODE -eq 0) { $status.Usable = $true }
        elseif ($status.HasInterface) { $status.Usable = $true }
        return $status
    }
    catch { return $status }
}

function Get-NearbyWifiNetworks {
    <#
        Parses 'netsh wlan show networks mode=bssid'. The output groups each SSID
        block followed by one or more "BSSID n" sub-blocks. We track the current
        SSID/auth/encryption and emit one record per BSSID.

        netsh is localized; the regex keys ("Authentication", "Encryption",
        "Signal", "Radio type", "Channel", "BSSID") match English Windows. We
        match on the label up to the colon to stay resilient to spacing.
    #>
    [CmdletBinding()] param()

    $raw = & netsh.exe wlan show networks mode=bssid 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Verbose "netsh wlan show networks failed: $raw"
        return @()
    }

    $networks   = New-Object System.Collections.Generic.List[object]
    $curSsid     = $null
    $curAuth     = $null
    $curEnc      = $null
    $curBssid    = $null
    $curSignal   = $null
    $curRadio    = $null
    $curChannel  = $null

    function _flushBssid {
        if ($null -ne $curBssid) {
            $networks.Add([pscustomobject]@{
                SSID           = if ([string]::IsNullOrWhiteSpace($curSsid)) { '<hidden>' } else { $curSsid }
                BSSID          = $curBssid
                SignalPercent  = $curSignal
                Radio          = $curRadio
                Channel        = $curChannel
                Authentication = $curAuth
                Encryption     = $curEnc
            })
        }
        $script:curBssid = $null; $script:curSignal = $null
        $script:curRadio = $null; $script:curChannel = $null
    }

    foreach ($line in $raw) {
        $l = [string]$line

        # New SSID block. "SSID 1 : MyNetwork"
        if ($l -match '^\s*SSID\s+\d+\s*:\s*(.*)$') {
            _flushBssid
            $curSsid = $Matches[1].Trim()
            $curAuth = $null; $curEnc = $null
            continue
        }
        if ($l -match '^\s*Authentication\s*:\s*(.+)$') { $curAuth = $Matches[1].Trim(); continue }
        if ($l -match '^\s*Encryption\s*:\s*(.+)$')     { $curEnc  = $Matches[1].Trim(); continue }

        # BSSID sub-block. "BSSID 1 : aa:bb:cc:dd:ee:ff"
        if ($l -match '^\s*BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})\s*$') {
            _flushBssid
            $curBssid = $Matches[1].Trim()
            continue
        }
        if ($l -match '^\s*Signal\s*:\s*(\d+)%') { $curSignal = [int]$Matches[1]; continue }
        if ($l -match '^\s*Radio type\s*:\s*(.+)$') { $curRadio = $Matches[1].Trim(); continue }
        if ($l -match '^\s*Channel\s*:\s*(.+)$')   { $curChannel = $Matches[1].Trim(); continue }
    }
    _flushBssid   # flush the final pending BSSID

    return $networks
}

function Get-WifiRisk {
    <#
        Evaluates an authentication + encryption pair and returns
        @{ Severity; Note }. Heuristics based on netsh's English strings.
    #>
    [CmdletBinding()]
    param([string]$Authentication, [string]$Encryption)

    $a = ($Authentication ?? '').Trim()
    $e = ($Encryption ?? '').Trim()
    $au = $a.ToUpperInvariant()
    $eu = $e.ToUpperInvariant()

    if ($au -match 'OPEN' -and ($eu -match 'NONE' -or $eu -eq '')) {
        return @{ Severity = 'High'; Note = 'Open network: traffic is unencrypted and anyone can join.' }
    }
    if ($eu -match 'WEP') {
        return @{ Severity = 'High'; Note = 'WEP is broken and trivially crackable. Replace immediately.' }
    }
    if ($au -match 'WPA3' -or $au -match 'SAE' -or $au -match 'OWE') {
        return @{ Severity = 'Good'; Note = 'WPA3/SAE/OWE: strong modern security.' }
    }
    if ($eu -match 'TKIP') {
        return @{ Severity = 'Medium'; Note = 'TKIP cipher is deprecated and weak. Use WPA2/WPA3 with AES (CCMP).' }
    }
    if ($au -match 'WPA2') {
        if ($au -match 'ENTERPRISE') {
            return @{ Severity = 'Low'; Note = 'WPA2-Enterprise: acceptable; ensure strong server cert validation.' }
        }
        return @{ Severity = 'Low'; Note = 'WPA2-Personal with AES: OK; consider upgrading to WPA3.' }
    }
    if ($au -match 'WPA' -and $au -notmatch 'WPA2|WPA3') {
        return @{ Severity = 'Medium'; Note = 'WPA (v1) is outdated. Upgrade to WPA2/WPA3.' }
    }
    return @{ Severity = 'Low'; Note = "Unrecognized config (Auth='$a', Enc='$e'); review manually." }
}

function Get-SavedWifiProfiles {
    <#
        Enumerates saved profiles via 'netsh wlan show profiles' and inspects
        each with 'show profile name=<x> key=clear' to extract authentication,
        cipher, connection mode and (optionally) the stored key.
    #>
    [CmdletBinding()]
    param([switch]$IncludeKeys)

    $list = & netsh.exe wlan show profiles 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Verbose "netsh wlan show profiles failed: $list"
        return @()
    }

    $names = foreach ($line in $list) {
        if ([string]$line -match '^\s*All User Profile\s*:\s*(.+)$' -or
            [string]$line -match '^\s*User Profile\s*:\s*(.+)$') {
            $Matches[1].Trim()
        }
    }

    $profiles = New-Object System.Collections.Generic.List[object]
    foreach ($name in ($names | Select-Object -Unique)) {
        $args = @('wlan', 'show', 'profile', "name=$name")
        if ($IncludeKeys) { $args += 'key=clear' }
        $detail = & netsh.exe @args 2>&1

        $auth = $null; $cipher = $null; $key = $null; $autoConnect = $null
        foreach ($line in $detail) {
            $l = [string]$line
            if ($l -match '^\s*Authentication\s*:\s*(.+)$')     { $auth = $Matches[1].Trim(); continue }
            if ($l -match '^\s*Cipher\s*:\s*(.+)$')             { $cipher = $Matches[1].Trim(); continue }
            if ($l -match '^\s*Key Content\s*:\s*(.+)$')        { $key = $Matches[1].Trim(); continue }
            if ($l -match '^\s*Connection mode\s*:\s*(.+)$')    { $autoConnect = $Matches[1].Trim(); continue }
        }

        $risk = Get-WifiRisk -Authentication $auth -Encryption $cipher
        $profiles.Add([pscustomobject]@{
            Name           = $name
            Authentication = $auth
            Cipher         = $cipher
            ConnectionMode = $autoConnect
            Key            = if ($IncludeKeys) { $key } else { $null }
            Severity       = $risk.Severity
            Note           = $risk.Note
        })
    }
    return $profiles
}

function ConvertTo-WifiHtml {
    <# Self-contained styled HTML report from the audit result object. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Audit, [switch]$ShowKeys)

    $esc = {
        param($s)
        ([string]$s) -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;'
    }
    $sevClass = { param($s) "sev-$s" }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1"><title>Wi-Fi Audit</title><style>')
    [void]$sb.AppendLine(@'
body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#0f1419;color:#e6e6e6}
header{background:#11202e;padding:24px 32px;border-bottom:3px solid #2b8a8a}
h1{margin:0;font-size:22px;color:#7fdbff}
.warn{background:#3a2a00;color:#ffd166;padding:10px 16px;border-left:4px solid #ffd166;margin:16px 32px;border-radius:4px}
section{margin:24px 32px}h2{color:#7fdbff;border-bottom:1px solid #29404f;padding-bottom:6px}
table{border-collapse:collapse;width:100%;font-size:13px;margin-top:8px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #233544}
th{background:#16242f;color:#9fb3c8}tr:hover{background:#16242f}
.sev-High{color:#ff6b6b;font-weight:bold}.sev-Medium{color:#ffd166;font-weight:bold}
.sev-Low{color:#9fb3c8}.sev-Good{color:#5bd99a;font-weight:bold}
.mono{font-family:Consolas,monospace}footer{margin:32px;font-size:11px;color:#5a6b7a}
'@)
    [void]$sb.AppendLine('</style></head><body>')
    [void]$sb.AppendLine('<header><h1>Passive Wi-Fi Security Audit</h1></header>')
    [void]$sb.AppendLine('<div class="warn"><b>AUTHORIZED USE ONLY.</b> Passive scan. Report may contain sensitive data (BSSIDs, saved profiles, optionally keys) - do not share.</div>')
    [void]$sb.AppendLine(("<section><p>Generated: {0}</p></section>" -f (& $esc $Audit.GeneratedAt)))

    [void]$sb.AppendLine('<section><h2>Nearby Networks</h2>')
    [void]$sb.AppendLine('<table><tr><th>Severity</th><th>SSID</th><th>BSSID</th><th>Signal</th><th>Radio</th><th>Auth</th><th>Encryption</th><th>Note</th></tr>')
    foreach ($n in ($Audit.Networks | Sort-Object @{e={@{High=0;Medium=1;Low=2;Good=3}[$_.Severity]}}, SSID)) {
        [void]$sb.AppendLine(("<tr><td class='{0}'>{1}</td><td>{2}</td><td class='mono'>{3}</td><td>{4}%</td><td>{5}</td><td>{6}</td><td>{7}</td><td>{8}</td></tr>" -f `
            (& $sevClass $n.Severity), (& $esc $n.Severity), (& $esc $n.SSID), (& $esc $n.BSSID),
            $n.SignalPercent, (& $esc $n.Radio), (& $esc $n.Authentication), (& $esc $n.Encryption), (& $esc $n.Note)))
    }
    [void]$sb.AppendLine('</table></section>')

    if ($Audit.Profiles) {
        [void]$sb.AppendLine('<section><h2>Saved Profiles</h2>')
        $keyHdr = if ($ShowKeys) { '<th>Key</th>' } else { '' }
        [void]$sb.AppendLine("<table><tr><th>Severity</th><th>Name</th><th>Auth</th><th>Cipher</th><th>Mode</th>$keyHdr<th>Note</th></tr>")
        foreach ($p in ($Audit.Profiles | Sort-Object @{e={@{High=0;Medium=1;Low=2;Good=3}[$_.Severity]}}, Name)) {
            $keyCell = if ($ShowKeys) { "<td class='mono'>$(& $esc $p.Key)</td>" } else { '' }
            [void]$sb.AppendLine(("<tr><td class='{0}'>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td>{6}<td>{7}</td></tr>" -f `
                (& $sevClass $p.Severity), (& $esc $p.Severity), (& $esc $p.Name), (& $esc $p.Authentication),
                (& $esc $p.Cipher), (& $esc $p.ConnectionMode), $keyCell, (& $esc $p.Note)))
        }
        [void]$sb.AppendLine('</table></section>')
    }
    [void]$sb.AppendLine('<footer>Generated by Get-WifiAudit.ps1 - passive defensive tool. Authorized use only.</footer>')
    [void]$sb.AppendLine('</body></html>')
    return $sb.ToString()
}

#endregion

#region ----------------------------- Main -----------------------------------

function Get-WifiAudit {
    [CmdletBinding()]
    param(
        [string]$OutFile,
        [switch]$Json,
        [switch]$ShowKeys,
        [switch]$SkipProfiles
    )

    Write-WifiBanner

    $wlan = Get-WlanStatus
    if (-not $wlan.HasInterface) {
        Write-Host '  No wireless interface detected, or the WLAN AutoConfig service is stopped.' -ForegroundColor Yellow
        Write-Host '  Ensure Wi-Fi hardware is enabled and the WLAN AutoConfig service is running.' -ForegroundColor Yellow
        return
    }
    if ($wlan.LocationBlocked) {
        Write-Host '  NOTE: Windows is blocking Wi-Fi scan data because Location services are off' -ForegroundColor Yellow
        Write-Host '        for this app/terminal. On Windows 11 "netsh wlan" needs Location ON.' -ForegroundColor Yellow
        Write-Host '        Enable: Settings > Privacy & security > Location (allow desktop apps).' -ForegroundColor Yellow
        Write-Host '        Saved-profile auditing below may still work; nearby-network scan may be empty.' -ForegroundColor Yellow
        Write-Host ''
    }

    if ($ShowKeys) {
        Write-Host '  PRIVACY: -ShowKeys will display stored Wi-Fi passwords for your saved' -ForegroundColor Yellow
        Write-Host '           networks. Output/report is sensitive - handle accordingly.' -ForegroundColor Yellow
        Write-Host ''
    }

    # --- Nearby networks ------------------------------------------------------
    Write-Host '  Scanning nearby wireless networks ...' -ForegroundColor Cyan
    $networks = @(Get-NearbyWifiNetworks)
    foreach ($n in $networks) {
        $risk = Get-WifiRisk -Authentication $n.Authentication -Encryption $n.Encryption
        $n | Add-Member -NotePropertyName Severity -NotePropertyValue $risk.Severity -Force
        $n | Add-Member -NotePropertyName Note     -NotePropertyValue $risk.Note     -Force
    }

    Write-Host ''
    Write-Host '  ==================== NEARBY NETWORKS ====================' -ForegroundColor Cyan
    if ($networks.Count -eq 0) {
        Write-Host '  No networks found (or scan results cached/empty). Try moving or re-running.' -ForegroundColor Yellow
    }
    else {
        $order = @{ High = 0; Medium = 1; Low = 2; Good = 3 }
        foreach ($n in ($networks | Sort-Object { $order[$_.Severity] }, SSID)) {
            $color = switch ($n.Severity) { 'High' { 'Red' } 'Medium' { 'Yellow' } 'Good' { 'Green' } default { 'Gray' } }
            Write-Host ("  [{0,-6}] {1,-24} {2}  {3,3}%  {4,-10} {5}" -f `
                $n.Severity, ($n.SSID.Substring(0, [math]::Min(24, $n.SSID.Length))),
                $n.BSSID, $n.SignalPercent, ($n.Authentication ?? '?'), ($n.Encryption ?? '?')) -ForegroundColor $color
            if ($n.Severity -in 'High', 'Medium') {
                Write-Host ("           -> {0}" -f $n.Note) -ForegroundColor DarkGray
            }
        }
    }

    # --- Saved profiles -------------------------------------------------------
    $profiles = @()
    if (-not $SkipProfiles) {
        Write-Host ''
        Write-Host '  Auditing saved wireless profiles ...' -ForegroundColor Cyan
        $profiles = @(Get-SavedWifiProfiles -IncludeKeys:$ShowKeys)

        Write-Host ''
        Write-Host '  ==================== SAVED PROFILES ====================' -ForegroundColor Cyan
        if ($profiles.Count -eq 0) {
            Write-Host '  No saved profiles found.' -ForegroundColor Gray
        }
        else {
            $order = @{ High = 0; Medium = 1; Low = 2; Good = 3 }
            foreach ($p in ($profiles | Sort-Object { $order[$_.Severity] }, Name)) {
                $color = switch ($p.Severity) { 'High' { 'Red' } 'Medium' { 'Yellow' } 'Good' { 'Green' } default { 'Gray' } }
                $keyStr = if ($ShowKeys -and $p.Key) { "  key='$($p.Key)'" } else { '' }
                Write-Host ("  [{0,-6}] {1,-24} {2,-18} {3}{4}" -f `
                    $p.Severity, $p.Name, ($p.Authentication ?? '?'), ($p.Cipher ?? '?'), $keyStr) -ForegroundColor $color
                if ($p.Severity -in 'High', 'Medium') {
                    Write-Host ("           -> {0}" -f $p.Note) -ForegroundColor DarkGray
                }
            }
        }
    }

    # --- Summary --------------------------------------------------------------
    $allSev = @($networks.Severity) + @($profiles.Severity)
    $high = @($allSev | Where-Object { $_ -eq 'High' }).Count
    $med  = @($allSev | Where-Object { $_ -eq 'Medium' }).Count
    Write-Host ''
    Write-Host ("  Summary: {0} High, {1} Medium across {2} network(s) and {3} saved profile(s)." -f `
        $high, $med, $networks.Count, $profiles.Count) -ForegroundColor Cyan
    Write-Host ''

    # --- Output ---------------------------------------------------------------
    $audit = [pscustomobject]@{
        GeneratedAt = (Get-Date).ToString('s')
        Networks    = $networks
        Profiles    = $profiles
    }

    if ($OutFile) {
        $html = ConvertTo-WifiHtml -Audit $audit -ShowKeys:$ShowKeys
        Set-Content -Path $OutFile -Value $html -Encoding UTF8
        Write-Host ("  HTML report written to: {0}" -f (Resolve-Path -LiteralPath $OutFile)) -ForegroundColor Green
        if ($Json) {
            $jsonPath = [System.IO.Path]::ChangeExtension($OutFile, 'json')
            $audit | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonPath -Encoding UTF8
            Write-Host ("  JSON report written to: {0}" -f (Resolve-Path -LiteralPath $jsonPath)) -ForegroundColor Green
        }
    }
    elseif ($Json) {
        $audit | ConvertTo-Json -Depth 6
    }

    return $audit
}

#endregion

# ------------------------------- Entry point ---------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    Get-WifiAudit -OutFile $OutFile -Json:$Json -ShowKeys:$ShowKeys -SkipProfiles:$SkipProfiles
}
