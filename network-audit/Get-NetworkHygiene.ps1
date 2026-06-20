<#
.SYNOPSIS
    Local Windows host security-hygiene check (PowerShell 7+ / 5.1-safe).

.DESCRIPTION
    Get-NetworkHygiene audits the security posture of THIS laptop - the machine
    you scan your home network from. It checks:

      1. Windows Firewall status per profile (Get-NetFirewallProfile).
      2. Listening TCP ports with owning process (Get-NetTCPConnection -Listen).
      3. SMBv1 status (Get-SmbServerConfiguration / Get-WindowsOptionalFeature).
      4. Microsoft Defender status (Get-MpComputerStatus): AV enabled, real-time
         protection, signature age.
      5. Network shares and anonymous/everyone access (Get-SmbShare / access).
      6. Risky / remote-access services (RemoteRegistry, TermService, Telnet...).
      7. A note on pending Windows updates (best-effort, non-authoritative).

    Each issue becomes a finding with a Severity and a Remediation hint. Output
    is a colored console summary plus optional -OutFile HTML and -Json.

.PARAMETER OutFile
    Path to write a self-contained styled HTML report. A sibling .json is also
    written when -Json is supplied.

.PARAMETER Json
    Also emit JSON (alongside the HTML report, or to stdout if no -OutFile).

.EXAMPLE
    .\Get-NetworkHygiene.ps1
    Run a full local hygiene check, console output.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-NetworkHygiene.ps1 -OutFile .\hygiene.html -Json

.NOTES
    ============================ AUTHORIZED USE ONLY ============================
    Run this only on a machine you own or administer. It inspects local security
    configuration of THIS device to help you harden it.
    ============================================================================

    Privileges: Most checks work as a standard user, but several are richer when
    run as Administrator (full firewall detail, process owners for all listeners,
    Defender status, SMB server config). Run elevated for complete results. The
    script degrades gracefully and notes when data is unavailable.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutFile,

    [Parameter()]
    [switch]$Json
)

#region ---------------------------- Helpers ---------------------------------

function Test-IsAdmin {
    [CmdletBinding()] param()
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

function New-Finding {
    <# Factory for a consistent finding record. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('High','Medium','Low','Info','Good')][string]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Issue,
        [string]$Detail,
        [string]$Remediation
    )
    [pscustomobject]@{
        Severity    = $Severity
        Category    = $Category
        Issue       = $Issue
        Detail      = $Detail
        Remediation = $Remediation
    }
}

function Get-FirewallFindings {
    [CmdletBinding()] param()
    $findings = New-Object System.Collections.Generic.List[object]
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($p in $profiles) {
            if (-not $p.Enabled) {
                $findings.Add((New-Finding -Severity 'High' -Category 'Firewall' `
                    -Issue ("Firewall disabled on '{0}' profile" -f $p.Name) `
                    -Detail ("Profile {0} Enabled={1}" -f $p.Name, $p.Enabled) `
                    -Remediation "Set-NetFirewallProfile -Profile $($p.Name) -Enabled True"))
            }
            else {
                $findings.Add((New-Finding -Severity 'Good' -Category 'Firewall' `
                    -Issue ("Firewall enabled on '{0}' profile" -f $p.Name) `
                    -Detail ("DefaultInbound={0}" -f $p.DefaultInboundAction)))
            }
            if ("$($p.DefaultInboundAction)" -eq 'Allow') {
                $findings.Add((New-Finding -Severity 'High' -Category 'Firewall' `
                    -Issue ("Default inbound = Allow on '{0}'" -f $p.Name) `
                    -Remediation "Set-NetFirewallProfile -Profile $($p.Name) -DefaultInboundAction Block"))
            }
        }
    }
    catch {
        $findings.Add((New-Finding -Severity 'Info' -Category 'Firewall' `
            -Issue 'Could not read firewall profiles' -Detail $_.Exception.Message))
    }
    return $findings
}

function Get-ListeningPortFindings {
    <#
        Lists listening TCP endpoints with the owning process. Flags well-known
        risky listeners that are reachable from the network (non-loopback bind).
    #>
    [CmdletBinding()] param()
    $findings = New-Object System.Collections.Generic.List[object]
    $risky = @{
        23   = @{ Severity='High';   Name='Telnet' }
        21   = @{ Severity='High';   Name='FTP' }
        3389 = @{ Severity='Medium'; Name='RDP' }
        445  = @{ Severity='Medium'; Name='SMB' }
        139  = @{ Severity='Medium'; Name='NetBIOS' }
        135  = @{ Severity='Low';    Name='MSRPC' }
        5985 = @{ Severity='Low';    Name='WinRM-HTTP' }
        5900 = @{ Severity='High';   Name='VNC' }
        1433 = @{ Severity='High';   Name='MSSQL' }
        3306 = @{ Severity='High';   Name='MySQL' }
    }
    try {
        $listen = Get-NetTCPConnection -State Listen -ErrorAction Stop
        $procCache = @{}
        foreach ($conn in $listen) {
            $localAddr = $conn.LocalAddress
            # Network-reachable if bound to a non-loopback address (0.0.0.0, ::, or a real IP).
            $networkReachable = $localAddr -notin @('127.0.0.1', '::1')
            # NOTE: $pid is a read-only automatic variable in PowerShell - use $ownerPid.
            $ownerPid = $conn.OwningProcess
            if (-not $procCache.ContainsKey($ownerPid)) {
                $procCache[$ownerPid] = try { (Get-Process -Id $ownerPid -ErrorAction Stop).ProcessName } catch { "PID $ownerPid" }
            }
            $procName = $procCache[$ownerPid]

            if ($risky.ContainsKey([int]$conn.LocalPort) -and $networkReachable) {
                $r = $risky[[int]$conn.LocalPort]
                $findings.Add((New-Finding -Severity $r.Severity -Category 'Listening Port' `
                    -Issue ("{0} listening on {1}:{2}" -f $r.Name, $localAddr, $conn.LocalPort) `
                    -Detail ("Process: {0} (PID {1})" -f $procName, $ownerPid) `
                    -Remediation "Confirm this service is intended; restrict via firewall or disable if unused."))
            }
        }
        # Informational rollup of all network-reachable listeners.
        $reachableCount = @($listen | Where-Object { $_.LocalAddress -notin @('127.0.0.1','::1') }).Count
        $findings.Add((New-Finding -Severity 'Info' -Category 'Listening Port' `
            -Issue ("{0} network-reachable TCP listener(s) total" -f $reachableCount) `
            -Detail 'See full report/JSON for the complete list.'))
    }
    catch {
        $findings.Add((New-Finding -Severity 'Info' -Category 'Listening Port' `
            -Issue 'Could not enumerate listening ports' -Detail $_.Exception.Message))
    }
    return $findings
}

function Get-Smb1Findings {
    [CmdletBinding()] param()
    $findings = New-Object System.Collections.Generic.List[object]
    $detected = $false
    try {
        $cfg = Get-SmbServerConfiguration -ErrorAction Stop
        $detected = $true
        if ($cfg.EnableSMB1Protocol) {
            $findings.Add((New-Finding -Severity 'High' -Category 'SMBv1' `
                -Issue 'SMBv1 server protocol is ENABLED' `
                -Detail 'SMBv1 is obsolete and the EternalBlue/WannaCry vector.' `
                -Remediation "Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force"))
        }
        else {
            $findings.Add((New-Finding -Severity 'Good' -Category 'SMBv1' `
                -Issue 'SMBv1 server protocol is disabled'))
        }
    }
    catch { Write-Verbose "Get-SmbServerConfiguration failed: $($_.Exception.Message)" }

    # Cross-check the optional feature too (covers client component).
    try {
        $feat = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        if ($feat -and $feat.State -eq 'Enabled') {
            $findings.Add((New-Finding -Severity 'High' -Category 'SMBv1' `
                -Issue 'SMB1Protocol Windows feature is Enabled' `
                -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"))
        }
        elseif (-not $detected) {
            $findings.Add((New-Finding -Severity 'Good' -Category 'SMBv1' `
                -Issue 'SMB1Protocol feature not enabled'))
        }
    }
    catch { Write-Verbose "Get-WindowsOptionalFeature SMB1 failed: $($_.Exception.Message)" }

    if ($findings.Count -eq 0) {
        $findings.Add((New-Finding -Severity 'Info' -Category 'SMBv1' `
            -Issue 'Could not determine SMBv1 status' -Detail 'Cmdlets unavailable or insufficient rights.'))
    }
    return $findings
}

function Get-DefenderFindings {
    [CmdletBinding()] param()
    $findings = New-Object System.Collections.Generic.List[object]
    try {
        $s = Get-MpComputerStatus -ErrorAction Stop
        if (-not $s.AntivirusEnabled) {
            $findings.Add((New-Finding -Severity 'High' -Category 'Defender' `
                -Issue 'Antivirus is NOT enabled' `
                -Remediation 'Enable Microsoft Defender or confirm a third-party AV is active.'))
        }
        else {
            $findings.Add((New-Finding -Severity 'Good' -Category 'Defender' -Issue 'Antivirus enabled'))
        }
        if (-not $s.RealTimeProtectionEnabled) {
            $findings.Add((New-Finding -Severity 'High' -Category 'Defender' `
                -Issue 'Real-time protection is OFF' `
                -Remediation 'Set-MpPreference -DisableRealtimeMonitoring $false'))
        }
        else {
            $findings.Add((New-Finding -Severity 'Good' -Category 'Defender' -Issue 'Real-time protection on'))
        }
        $age = $s.AntivirusSignatureAge
        if ($null -ne $age -and $age -gt 7) {
            $findings.Add((New-Finding -Severity 'Medium' -Category 'Defender' `
                -Issue ("AV signatures are {0} day(s) old" -f $age) `
                -Remediation 'Update-MpSignature'))
        }
    }
    catch {
        $findings.Add((New-Finding -Severity 'Info' -Category 'Defender' `
            -Issue 'Could not read Defender status' `
            -Detail 'Get-MpComputerStatus unavailable (3rd-party AV or insufficient rights).'))
    }
    return $findings
}

function Get-ShareFindings {
    [CmdletBinding()] param()
    $findings = New-Object System.Collections.Generic.List[object]
    try {
        $shares = Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -notmatch '^\w+\$$' }  # skip admin$, c$, IPC$
        foreach ($sh in $shares) {
            $findings.Add((New-Finding -Severity 'Info' -Category 'Share' `
                -Issue ("Share '{0}' -> {1}" -f $sh.Name, $sh.Path)))
            try {
                $access = Get-SmbShareAccess -Name $sh.Name -ErrorAction Stop
                $loose = $access | Where-Object {
                    $_.AccountName -match 'Everyone|ANONYMOUS LOGON|Guest|Authenticated Users' -and
                    $_.AccessControlType -eq 'Allow'
                }
                foreach ($a in $loose) {
                    $sev = if ($a.AccountName -match 'Everyone|ANONYMOUS|Guest') { 'High' } else { 'Medium' }
                    $findings.Add((New-Finding -Severity $sev -Category 'Share' `
                        -Issue ("Share '{0}' grants {1} to '{2}'" -f $sh.Name, $a.AccessRight, $a.AccountName) `
                        -Remediation "Revoke-SmbShareAccess -Name '$($sh.Name)' -AccountName '$($a.AccountName)' -Force"))
                }
            }
            catch { Write-Verbose "Get-SmbShareAccess failed for $($sh.Name): $($_.Exception.Message)" }
        }
    }
    catch {
        $findings.Add((New-Finding -Severity 'Info' -Category 'Share' `
            -Issue 'Could not enumerate shares' -Detail $_.Exception.Message))
    }
    return $findings
}

function Get-ServiceFindings {
    [CmdletBinding()] param()
    $findings = New-Object System.Collections.Generic.List[object]
    # service name -> @{ Severity; Why }
    $risky = [ordered]@{
        'TlntSvr'        = @{ Severity='High';   Why='Telnet server (cleartext remote shell).' }
        'RemoteRegistry' = @{ Severity='Medium'; Why='Remote registry access; common recon vector.' }
        'TermService'    = @{ Severity='Low';    Why='Remote Desktop service; ensure NLA + strong creds.' }
        'SSDPSRV'        = @{ Severity='Low';    Why='SSDP discovery; reduces attack surface if off.' }
        'upnphost'       = @{ Severity='Low';    Why='UPnP host; can auto-expose services.' }
        'WinRM'          = @{ Severity='Low';    Why='Windows Remote Management; restrict if unused.' }
        'SharedAccess'   = @{ Severity='Low';    Why='Internet Connection Sharing.' }
    }
    foreach ($name in $risky.Keys) {
        try {
            $svc = Get-Service -Name $name -ErrorAction Stop
            if ($svc.Status -eq 'Running' -or $svc.StartType -in 'Automatic') {
                $r = $risky[$name]
                $findings.Add((New-Finding -Severity $r.Severity -Category 'Service' `
                    -Issue ("Service '{0}' is {1} (StartType {2})" -f $svc.DisplayName, $svc.Status, $svc.StartType) `
                    -Detail $r.Why `
                    -Remediation "Disable if unused: Stop-Service '$name'; Set-Service '$name' -StartupType Disabled"))
            }
        }
        catch { }   # service not installed -> fine
    }
    return $findings
}

function Get-UpdateFindings {
    <# Best-effort pending-update note via the Windows Update COM API. #>
    [CmdletBinding()] param()
    $findings = New-Object System.Collections.Generic.List[object]
    try {
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $result   = $searcher.Search("IsInstalled=0 and IsHidden=0")
        $count    = $result.Updates.Count
        if ($count -gt 0) {
            $sev = if ($count -ge 5) { 'Medium' } else { 'Low' }
            $findings.Add((New-Finding -Severity $sev -Category 'Updates' `
                -Issue ("{0} pending Windows update(s)" -f $count) `
                -Remediation 'Install pending updates via Settings > Windows Update.'))
        }
        else {
            $findings.Add((New-Finding -Severity 'Good' -Category 'Updates' -Issue 'No pending updates detected'))
        }
    }
    catch {
        $findings.Add((New-Finding -Severity 'Info' -Category 'Updates' `
            -Issue 'Pending-update check unavailable' `
            -Detail 'Windows Update COM API not accessible (managed/restricted environment).'))
    }
    return $findings
}

function ConvertTo-HygieneHtml {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Audit)
    $esc = { param($s) ([string]$s) -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1"><title>Host Hygiene</title><style>')
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
.sev-Low{color:#9fb3c8}.sev-Info{color:#7fa8c8}.sev-Good{color:#5bd99a;font-weight:bold}
.mono{font-family:Consolas,monospace}footer{margin:32px;font-size:11px;color:#5a6b7a}
'@)
    [void]$sb.AppendLine('</style></head><body>')
    [void]$sb.AppendLine('<header><h1>Local Host Security Hygiene</h1></header>')
    [void]$sb.AppendLine('<div class="warn"><b>AUTHORIZED USE ONLY.</b> Local posture review of this device.</div>')
    [void]$sb.AppendLine(("<section><p>Generated: {0} &nbsp; | &nbsp; Elevated: {1} &nbsp; | &nbsp; Host: {2}</p></section>" -f `
        (& $esc $Audit.GeneratedAt), $Audit.IsAdmin, (& $esc $Audit.ComputerName)))

    $order = @{ High=0; Medium=1; Low=2; Info=3; Good=4 }
    [void]$sb.AppendLine('<section><h2>Findings</h2>')
    [void]$sb.AppendLine('<table><tr><th>Severity</th><th>Category</th><th>Issue</th><th>Detail</th><th>Remediation</th></tr>')
    foreach ($f in ($Audit.Findings | Sort-Object { $order[$_.Severity] }, Category)) {
        [void]$sb.AppendLine(("<tr><td class='sev-{0}'>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td class='mono'>{4}</td></tr>" -f `
            (& $esc $f.Severity), (& $esc $f.Category), (& $esc $f.Issue), (& $esc $f.Detail), (& $esc $f.Remediation)))
    }
    [void]$sb.AppendLine('</table></section>')
    [void]$sb.AppendLine('<footer>Generated by Get-NetworkHygiene.ps1 - local defensive tool. Authorized use only.</footer>')
    [void]$sb.AppendLine('</body></html>')
    return $sb.ToString()
}

#endregion

#region ----------------------------- Main -----------------------------------

function Get-NetworkHygiene {
    [CmdletBinding()]
    param([string]$OutFile, [switch]$Json)

    Write-Host ''
    Write-Host '  ============================================================' -ForegroundColor Cyan
    Write-Host '   Get-NetworkHygiene  -  Local Host Security Hygiene' -ForegroundColor Cyan
    Write-Host '   AUTHORIZED USE ONLY. Reviews THIS device''s posture.' -ForegroundColor Yellow
    Write-Host '  ============================================================' -ForegroundColor Cyan
    Write-Host ''

    $isAdmin = Test-IsAdmin
    if (-not $isAdmin) {
        Write-Host '  Note: not running as Administrator - some checks may be limited.' -ForegroundColor Yellow
        Write-Host ''
    }

    $findings = New-Object System.Collections.Generic.List[object]
    Write-Host '  Checking firewall ...'          -ForegroundColor Cyan; $findings.AddRange(@(Get-FirewallFindings))
    Write-Host '  Checking listening ports ...'   -ForegroundColor Cyan; $findings.AddRange(@(Get-ListeningPortFindings))
    Write-Host '  Checking SMBv1 ...'             -ForegroundColor Cyan; $findings.AddRange(@(Get-Smb1Findings))
    Write-Host '  Checking Defender ...'          -ForegroundColor Cyan; $findings.AddRange(@(Get-DefenderFindings))
    Write-Host '  Checking shares ...'            -ForegroundColor Cyan; $findings.AddRange(@(Get-ShareFindings))
    Write-Host '  Checking risky services ...'    -ForegroundColor Cyan; $findings.AddRange(@(Get-ServiceFindings))
    Write-Host '  Checking pending updates ...'   -ForegroundColor Cyan; $findings.AddRange(@(Get-UpdateFindings))

    # --- Console output -------------------------------------------------------
    Write-Host ''
    Write-Host '  ======================= FINDINGS =======================' -ForegroundColor Cyan
    $order = @{ High=0; Medium=1; Low=2; Info=3; Good=4 }
    foreach ($f in ($findings | Sort-Object { $order[$_.Severity] }, Category)) {
        $color = switch ($f.Severity) {
            'High'   { 'Red' }   'Medium' { 'Yellow' } 'Low' { 'Gray' }
            'Good'   { 'Green' }  default  { 'DarkCyan' }
        }
        Write-Host ("  [{0,-6}] {1,-15} {2}" -f $f.Severity, $f.Category, $f.Issue) -ForegroundColor $color
        if ($f.Remediation -and $f.Severity -in 'High','Medium') {
            Write-Host ("           fix: {0}" -f $f.Remediation) -ForegroundColor DarkGray
        }
    }

    $high = @($findings | Where-Object Severity -eq 'High').Count
    $med  = @($findings | Where-Object Severity -eq 'Medium').Count
    $low  = @($findings | Where-Object Severity -eq 'Low').Count
    Write-Host ''
    Write-Host ("  Summary: {0} High, {1} Medium, {2} Low." -f $high, $med, $low) -ForegroundColor Cyan
    Write-Host ''

    # --- Output ---------------------------------------------------------------
    $audit = [pscustomobject]@{
        GeneratedAt  = (Get-Date).ToString('s')
        ComputerName = $env:COMPUTERNAME
        IsAdmin      = $isAdmin
        Findings     = $findings
    }

    if ($OutFile) {
        $html = ConvertTo-HygieneHtml -Audit $audit
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
    Get-NetworkHygiene -OutFile $OutFile -Json:$Json
}
