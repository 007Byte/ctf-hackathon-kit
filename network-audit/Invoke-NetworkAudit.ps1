<#
.SYNOPSIS
    Native Windows home-network security auditor (PowerShell 7+ / 5.1-safe).

.DESCRIPTION
    Invoke-NetworkAudit performs a defensive audit of the local IPv4 subnet from a
    Windows 11 laptop with NO Python or third-party tooling required. It:

      1. Auto-detects the active local subnet and default gateway
         (Get-NetIPConfiguration / Get-NetRoute).
      2. Discovers live hosts by combining the ARP/neighbor cache
         (Get-NetNeighbor) with a fast, parallel ICMP + TCP ping sweep.
      3. Resolves hostnames (Resolve-DnsName / DNS reverse lookup).
      4. For each live host, performs TCP connect checks against a common-ports
         list (raw TcpClient with a hard timeout, runspace/parallel accelerated).
      5. Flags risky exposed services (Telnet, SMB, RDP, FTP, plaintext HTTP
         admin, open database ports, etc.) as findings with a severity rating.
      6. Emits a colored console summary table and, with -OutFile, a self-contained
         styled HTML report and optional JSON.

    The TCP sweep uses PowerShell 7's ForEach-Object -Parallel when available and
    transparently falls back to a runspace pool on Windows PowerShell 5.1.

.PARAMETER Subnet
    CIDR subnet to scan (e.g. 192.168.1.0/24). If omitted it is auto-detected
    from the active network adapter. Only /16 through /30 IPv4 ranges are scanned
    to keep the host count reasonable.

.PARAMETER Ports
    Array of TCP ports to probe on each live host. Defaults to a curated common
    /risky-service port list. Ignored values must be 1-65535.

.PARAMETER Quick
    Quick mode: pings only and probes a much smaller "top risky ports" list,
    and skips reverse DNS for speed.

.PARAMETER TimeoutMs
    Per-port TCP connect timeout in milliseconds (default 400).

.PARAMETER ThrottleLimit
    Maximum concurrent worker threads for the sweep (default 64).

.PARAMETER OutFile
    Path to write a self-contained HTML report. A sibling .json file is also
    written when -Json is supplied.

.PARAMETER Json
    Also emit a JSON file alongside the HTML report (or to OutFile.json).

.EXAMPLE
    .\Invoke-NetworkAudit.ps1
    Auto-detect the subnet and run a full audit, console output only.

.EXAMPLE
    .\Invoke-NetworkAudit.ps1 -Subnet 192.168.1.0/24 -OutFile .\report.html -Json
    Scan a specific subnet and write HTML + JSON reports.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Invoke-NetworkAudit.ps1 -Quick
    Fast scan from Windows PowerShell 5.1 with execution policy bypass.

.NOTES
    ============================ AUTHORIZED USE ONLY ============================
    Run this ONLY against networks you own or are explicitly authorized to test.
    Active host discovery and port scanning of networks without permission may be
    illegal and is against the terms of service of most providers. This tool is
    intended for a defender auditing their OWN home network.
    ============================================================================

    Privileges: Get-NetNeighbor and the ping sweep run without elevation. No
    administrator rights are required for the network audit itself.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$Subnet,

    [Parameter()]
    [ValidateRange(1, 65535)]
    [int[]]$Ports,

    [Parameter()]
    [switch]$Quick,

    [Parameter()]
    [ValidateRange(50, 10000)]
    [int]$TimeoutMs = 400,

    [Parameter()]
    [ValidateRange(1, 512)]
    [int]$ThrottleLimit = 64,

    [Parameter()]
    [string]$OutFile,

    [Parameter()]
    [switch]$Json
)

#region ----------------------------- Data -----------------------------------

# Map of common ports -> human label. Used both for probing and reporting.
# Plain hashtable (not [ordered]) so integer indexing like $PortCatalog[443]
# is a KEY lookup, not a positional index.
$Script:PortCatalog = @{
    21    = 'FTP'
    22    = 'SSH'
    23    = 'Telnet'
    25    = 'SMTP'
    53    = 'DNS'
    80    = 'HTTP'
    110   = 'POP3'
    135   = 'MSRPC'
    139   = 'NetBIOS-SSN'
    143   = 'IMAP'
    443   = 'HTTPS'
    445   = 'SMB'
    465   = 'SMTPS'
    587   = 'SMTP-Sub'
    993   = 'IMAPS'
    995   = 'POP3S'
    1433  = 'MSSQL'
    1521  = 'Oracle'
    3306  = 'MySQL'
    3389  = 'RDP'
    5432  = 'PostgreSQL'
    5900  = 'VNC'
    5985  = 'WinRM-HTTP'
    6379  = 'Redis'
    8080  = 'HTTP-Alt'
    8443  = 'HTTPS-Alt'
    9200  = 'Elasticsearch'
    27017 = 'MongoDB'
}

# Reduced port set used in -Quick mode (highest-signal risky services).
$Script:QuickPorts = @(21, 22, 23, 80, 139, 443, 445, 3389, 8080)

# Risk rules: port -> @{ Severity; Reason }. Anything not listed is informational.
$Script:RiskRules = @{
    23    = @{ Severity = 'High';   Reason = 'Telnet transmits credentials in cleartext.' }
    21    = @{ Severity = 'High';   Reason = 'FTP control channel is typically plaintext.' }
    445   = @{ Severity = 'High';   Reason = 'SMB file sharing exposed; common ransomware/worm vector.' }
    139   = @{ Severity = 'High';   Reason = 'NetBIOS/SMB legacy file sharing exposed.' }
    3389  = @{ Severity = 'High';   Reason = 'RDP exposed; frequent brute-force / exploit target.' }
    5900  = @{ Severity = 'High';   Reason = 'VNC remote desktop, often weak/no authentication.' }
    1433  = @{ Severity = 'High';   Reason = 'Microsoft SQL Server database port exposed.' }
    3306  = @{ Severity = 'High';   Reason = 'MySQL database port exposed.' }
    5432  = @{ Severity = 'High';   Reason = 'PostgreSQL database port exposed.' }
    6379  = @{ Severity = 'High';   Reason = 'Redis exposed; default config is unauthenticated.' }
    27017 = @{ Severity = 'High';   Reason = 'MongoDB exposed; historically unauthenticated by default.' }
    9200  = @{ Severity = 'High';   Reason = 'Elasticsearch exposed; often unauthenticated.' }
    1521  = @{ Severity = 'High';   Reason = 'Oracle database listener exposed.' }
    80    = @{ Severity = 'Medium'; Reason = 'Plaintext HTTP service / admin interface possible.' }
    8080  = @{ Severity = 'Medium'; Reason = 'Plaintext HTTP-alt service / admin interface possible.' }
    135   = @{ Severity = 'Medium'; Reason = 'MSRPC endpoint mapper exposed.' }
    5985  = @{ Severity = 'Medium'; Reason = 'WinRM over HTTP (unencrypted transport) exposed.' }
    25    = @{ Severity = 'Low';    Reason = 'SMTP service exposed.' }
    110   = @{ Severity = 'Low';    Reason = 'POP3 (plaintext mail) exposed.' }
    143   = @{ Severity = 'Low';    Reason = 'IMAP (plaintext mail) exposed.' }
}

#endregion

#region ---------------------------- Helpers ---------------------------------

function Write-Banner {
    [CmdletBinding()]
    param()
    Write-Host ''
    Write-Host '  ============================================================' -ForegroundColor Cyan
    Write-Host '   Invoke-NetworkAudit  -  Home Network Security Audit' -ForegroundColor Cyan
    Write-Host '   AUTHORIZED USE ONLY. Scan only networks you own/control.' -ForegroundColor Yellow
    Write-Host '  ============================================================' -ForegroundColor Cyan
    Write-Host ''
}

function Get-LocalNetworkContext {
    <#
        Returns a PSCustomObject describing the active adapter: IPv4 address,
        prefix length, gateway, DNS servers and the derived CIDR subnet.
        Falls back gracefully if Get-NetIPConfiguration is unavailable.
    #>
    [CmdletBinding()]
    param()

    $ctx = [pscustomobject]@{
        IPAddress    = $null
        PrefixLength = $null
        Gateway      = $null
        DnsServers   = @()
        Cidr         = $null
        Interface    = $null
    }

    try {
        # Prefer an adapter that has a default gateway (the "real" uplink).
        $cfg = Get-NetIPConfiguration -ErrorAction Stop |
            Where-Object { $_.IPv4DefaultGateway -and $_.IPv4Address } |
            Select-Object -First 1

        if ($cfg) {
            $ctx.IPAddress    = $cfg.IPv4Address.IPAddress
            $ctx.PrefixLength = $cfg.IPv4Address.PrefixLength
            $ctx.Gateway      = $cfg.IPv4DefaultGateway.NextHop
            $ctx.DnsServers   = @($cfg.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses } )
            $ctx.Interface    = $cfg.InterfaceAlias
            $ctx.Cidr         = (Get-CidrFromAddress -IPAddress $ctx.IPAddress -PrefixLength $ctx.PrefixLength)
        }
    }
    catch {
        Write-Verbose "Get-NetIPConfiguration failed: $($_.Exception.Message)"
    }

    return $ctx
}

function Get-CidrFromAddress {
    <# Computes the network CIDR (e.g. 192.168.1.0/24) from an IP + prefix. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$IPAddress,
        [Parameter(Mandatory)][int]$PrefixLength
    )
    $ipBytes = ([System.Net.IPAddress]::Parse($IPAddress)).GetAddressBytes()
    # Build the 32-bit mask without a left-shift. PowerShell's -shl operates on
    # Int32 and "0xFFFFFFFF -shl n" yields -1 there, so derive the mask
    # arithmetically: mask = 0xFFFFFFFF - (2^hostBits - 1).
    [uint32]$maskInt = 0
    if ($PrefixLength -gt 0) {
        # NOTE: the literal 0xFFFFFFFF parses as Int32 (-1) in PowerShell, so use
        # the decimal 4294967295 to get a positive 32-bit all-ones value.
        [uint64]$hostCount = [uint64][math]::Pow(2, (32 - $PrefixLength))
        $maskInt = [uint32]([uint64]4294967295 - ($hostCount - 1))
    }
    $maskBytes = [BitConverter]::GetBytes($maskInt)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($maskBytes) }
    $netBytes = for ($i = 0; $i -lt 4; $i++) { [byte]($ipBytes[$i] -band $maskBytes[$i]) }
    return ('{0}/{1}' -f ([System.Net.IPAddress]::new([byte[]]$netBytes)).ToString(), $PrefixLength)
}

function Expand-Subnet {
    <#
        Expands a CIDR (e.g. 192.168.1.0/24) into the list of usable host IPs.
        Restricts to /16../30 to keep the scan bounded. Excludes network and
        broadcast addresses.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Cidr)

    if ($Cidr -notmatch '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') {
        throw "Invalid CIDR '$Cidr'. Expected form like 192.168.1.0/24."
    }
    $baseIp = $Matches[1]
    $prefix = [int]$Matches[2]
    if ($prefix -lt 16 -or $prefix -gt 30) {
        throw "Prefix /$prefix out of supported range (/16 - /30)."
    }

    $ipBytes = ([System.Net.IPAddress]::Parse($baseIp)).GetAddressBytes()
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($ipBytes) }
    # Work in uint64 throughout so shifts/additions never overflow or go signed.
    [uint64]$baseInt = [BitConverter]::ToUInt32($ipBytes, 0)

    $hostBits = 32 - $prefix
    [uint64]$size = [uint64][math]::Pow(2, $hostBits)
    # mask = 0xFFFFFFFF - (size - 1). Use decimal 4294967295 because the hex
    # literal 0xFFFFFFFF parses as Int32 -1 in PowerShell.
    [uint64]$mask = [uint64]4294967295 - ($size - 1)
    [uint64]$network = $baseInt -band $mask

    $first = $network + 1
    $last  = $network + $size - 2          # exclude broadcast
    if ($prefix -ge 31) { $first = $network; $last = $network + $size - 1 }

    $list = New-Object System.Collections.Generic.List[string]
    for ([uint64]$i = $first; $i -le $last; $i++) {
        $b = [BitConverter]::GetBytes([uint32]$i)
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($b) }
        $list.Add(([System.Net.IPAddress]::new([byte[]]$b)).ToString())
    }
    return $list
}

function Get-NeighborMap {
    <#
        Returns a hashtable of IP -> MAC from the ARP/neighbor cache. Filters
        out incomplete/unreachable and multicast/broadcast junk entries.
    #>
    [CmdletBinding()]
    param()
    $map = @{}
    try {
        Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object {
                $_.State -in @('Reachable', 'Stale', 'Delay', 'Probe', 'Permanent') -and
                $_.LinkLayerAddress -and
                $_.LinkLayerAddress -notmatch '^(00-00-00-00-00-00|FF-FF-FF-FF-FF-FF)$' -and
                $_.IPAddress -notmatch '^(224\.|239\.|255\.|0\.)'
            } |
            ForEach-Object { $map[$_.IPAddress] = $_.LinkLayerAddress }
    }
    catch {
        Write-Verbose "Get-NetNeighbor unavailable; falling back to 'arp -a'."
        try {
            (& arp.exe -a) 2>$null | ForEach-Object {
                if ($_ -match '^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F-]{17})\s') {
                    $map[$Matches[1]] = $Matches[2].ToUpper()
                }
            }
        }
        catch { Write-Verbose "arp -a fallback failed: $($_.Exception.Message)" }
    }
    return $map
}

function Resolve-HostName {
    <# Best-effort reverse DNS lookup; returns $null if it cannot resolve. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$IPAddress)
    try {
        $r = Resolve-DnsName -Name $IPAddress -Type PTR -DnsOnly -ErrorAction Stop -QuickTimeout 2>$null
        $name = ($r | Where-Object { $_.NameHost } | Select-Object -First 1).NameHost
        if ($name) { return $name }
    }
    catch { }
    try {
        return [System.Net.Dns]::GetHostEntry($IPAddress).HostName
    }
    catch { return $null }
}

function Invoke-ParallelWork {
    <#
        Runs a script block against a collection of input items concurrently.
        Uses ForEach-Object -Parallel on PowerShell 7+, and a runspace pool on
        Windows PowerShell 5.1. The script block receives one item via $args[0]
        (PS5.1 path) or the pipeline variable $_ (PS7 path) - both are bound to
        the same parameter name we standardize on: the block must accept the
        item as its single positional/pipeline value.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$InputObject,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [int]$ThrottleLimit = 64
    )

    if ($PSVersionTable.PSVersion.Major -ge 7) {
        # PS7: native parallel pipeline. The provided block uses $_ for the item.
        return $InputObject | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel $ScriptBlock
    }

    # PS 5.1: hand-rolled runspace pool.
    $pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
    $pool.Open()
    $handles = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($item in $InputObject) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript($ScriptBlock).AddArgument($item)
            $handles.Add([pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke() })
        }
        $results = New-Object System.Collections.Generic.List[object]
        foreach ($h in $handles) {
            try { $results.AddRange(@($h.PS.EndInvoke($h.Handle))) } catch { }
            $h.PS.Dispose()
        }
        return $results
    }
    finally {
        $pool.Close(); $pool.Dispose()
    }
}

function Test-TcpPort {
    <#
        Lightweight TCP connect test with a hard timeout. Returns $true if the
        port accepts a connection. Self-contained so it can run inside a
        runspace with no external dependencies.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutMs = 400
    )
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $client.Connected) {
            $client.EndConnect($iar)
            return $true
        }
        return $false
    }
    catch { return $false }
    finally { $client.Close() }
}

#endregion

#region ----------------------------- Main -----------------------------------

function Invoke-NetworkAudit {
    [CmdletBinding()]
    param(
        [string]$Subnet,
        [int[]]$Ports,
        [switch]$Quick,
        [int]$TimeoutMs,
        [int]$ThrottleLimit,
        [string]$OutFile,
        [switch]$Json
    )

    Write-Banner

    # --- 1. Determine subnet / context ----------------------------------------
    $ctx = Get-LocalNetworkContext
    if (-not $Subnet) {
        if (-not $ctx.Cidr) {
            throw 'Could not auto-detect a subnet. Specify one with -Subnet (e.g. 192.168.1.0/24).'
        }
        $Subnet = $ctx.Cidr
    }

    Write-Host ("  Local adapter : {0}" -f ($ctx.Interface ?? 'n/a')) -ForegroundColor Gray
    Write-Host ("  Local IP      : {0}/{1}" -f ($ctx.IPAddress ?? 'n/a'), ($ctx.PrefixLength ?? '?')) -ForegroundColor Gray
    Write-Host ("  Gateway       : {0}" -f ($ctx.Gateway ?? 'n/a')) -ForegroundColor Gray
    Write-Host ("  DNS servers   : {0}" -f (($ctx.DnsServers -join ', ') -replace '^$', 'n/a')) -ForegroundColor Gray
    Write-Host ("  Target subnet : {0}" -f $Subnet) -ForegroundColor Green

    # Resolve effective port list.
    if (-not $Ports -or $Ports.Count -eq 0) {
        $Ports = if ($Quick) { $Script:QuickPorts } else { @($Script:PortCatalog.Keys) }
    }
    Write-Host ("  Ports/host    : {0}" -f $Ports.Count) -ForegroundColor Gray
    Write-Host ''

    # --- 2. Expand subnet & seed with neighbor cache --------------------------
    $allHosts = Expand-Subnet -Cidr $Subnet
    Write-Host ("  Sweeping {0} candidate hosts ..." -f $allHosts.Count) -ForegroundColor Cyan
    $neighborMap = Get-NeighborMap

    # --- 3. Live-host discovery (parallel ICMP + TCP fallback) ----------------
    $pingBlock = {
        param($ip)
        # In PS7 -Parallel, $_ is the item; in PS5.1 runspace it arrives as $ip.
        $target = if ($ip) { $ip } else { $_ }
        $alive = $false
        try {
            $alive = Test-Connection -ComputerName $target -Count 1 -Quiet -ErrorAction SilentlyContinue
        } catch { }
        if (-not $alive) {
            # TCP fallback: many hosts (esp. Windows) drop ICMP but answer TCP.
            foreach ($p in 445, 80, 443, 22, 139) {
                $c = [System.Net.Sockets.TcpClient]::new()
                try {
                    $iar = $c.BeginConnect($target, $p, $null, $null)
                    if ($iar.AsyncWaitHandle.WaitOne(300, $false) -and $c.Connected) { $alive = $true }
                } catch { } finally { $c.Close() }
                if ($alive) { break }
            }
        }
        if ($alive) { $target }
    }

    $liveHosts = @(Invoke-ParallelWork -InputObject $allHosts -ScriptBlock $pingBlock -ThrottleLimit $ThrottleLimit |
        Sort-Object { [version]($_ -replace '(^|\.)(\d+)', '$1$2') } -ErrorAction SilentlyContinue) |
        Where-Object { $_ }

    # Always include any host present in the ARP cache that lies in-scope.
    $scopeSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$allHosts)
    foreach ($arpIp in $neighborMap.Keys) {
        if ($scopeSet.Contains($arpIp) -and $liveHosts -notcontains $arpIp) {
            $liveHosts += $arpIp
        }
    }
    $liveHosts = @($liveHosts | Sort-Object -Unique { try { [System.Net.IPAddress]::Parse($_).GetAddressBytes() -join '.' } catch { $_ } })

    Write-Host ("  Found {0} live host(s)." -f $liveHosts.Count) -ForegroundColor Green
    Write-Host ''

    if ($liveHosts.Count -eq 0) {
        Write-Host '  No live hosts discovered. (On guest/isolated networks this can be normal.)' -ForegroundColor Yellow
        return
    }

    # --- 4. Per-host port scan (parallel) -------------------------------------
    Write-Host '  Scanning ports on live hosts ...' -ForegroundColor Cyan
    $scanBlock = {
        param($ip)
        $target  = if ($ip) { $ip } else { $_ }
        $ports   = $using:Ports
        $timeout = $using:TimeoutMs
        # Inline TCP test (runspace-safe; cannot rely on outer functions).
        $openList = New-Object System.Collections.Generic.List[int]
        foreach ($port in $ports) {
            $client = [System.Net.Sockets.TcpClient]::new()
            try {
                $iar = $client.BeginConnect($target, $port, $null, $null)
                if ($iar.AsyncWaitHandle.WaitOne($timeout, $false) -and $client.Connected) {
                    $client.EndConnect($iar); $openList.Add($port)
                }
            } catch { } finally { $client.Close() }
        }
        [pscustomobject]@{ IP = $target; OpenPorts = $openList.ToArray() }
    }

    # PS5.1 fallback path cannot use $using:, so build a closure-friendly block.
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        $portsLocal = $Ports; $timeoutLocal = $TimeoutMs
        $scanBlock = [scriptblock]::Create(@"
param(`$ip)
`$target = `$ip
`$ports = @($($portsLocal -join ','))
`$timeout = $timeoutLocal
`$openList = New-Object System.Collections.Generic.List[int]
foreach (`$port in `$ports) {
    `$client = [System.Net.Sockets.TcpClient]::new()
    try {
        `$iar = `$client.BeginConnect(`$target, `$port, `$null, `$null)
        if (`$iar.AsyncWaitHandle.WaitOne(`$timeout, `$false) -and `$client.Connected) {
            `$client.EndConnect(`$iar); `$openList.Add(`$port)
        }
    } catch { } finally { `$client.Close() }
}
[pscustomobject]@{ IP = `$target; OpenPorts = `$openList.ToArray() }
"@)
    }

    $scanResults = Invoke-ParallelWork -InputObject $liveHosts -ScriptBlock $scanBlock -ThrottleLimit ([math]::Min($ThrottleLimit, 32))

    # --- 5. Build host records + findings -------------------------------------
    $hostRecords = New-Object System.Collections.Generic.List[object]
    $findings    = New-Object System.Collections.Generic.List[object]

    foreach ($res in ($scanResults | Sort-Object { try { [int](($_.IP -split '\.')[-1]) } catch { 999 } })) {
        $ip       = $res.IP
        $mac      = $neighborMap[$ip]
        $hostName = $null
        if (-not $Quick) { $hostName = Resolve-HostName -IPAddress $ip }

        $openDetailed = foreach ($p in ($res.OpenPorts | Sort-Object)) {
            [pscustomobject]@{ Port = $p; Service = ($Script:PortCatalog[$p] ?? 'unknown') }
        }

        $hostRecords.Add([pscustomobject]@{
            IPAddress = $ip
            HostName  = $hostName
            MAC       = $mac
            OpenPorts = @($openDetailed)
            IsGateway = ($ip -eq $ctx.Gateway)
        })

        foreach ($od in $openDetailed) {
            if ($Script:RiskRules.ContainsKey($od.Port)) {
                $rule = $Script:RiskRules[$od.Port]
                $findings.Add([pscustomobject]@{
                    Severity = $rule.Severity
                    IP       = $ip
                    HostName = $hostName
                    Port     = $od.Port
                    Service  = $od.Service
                    Reason   = $rule.Reason
                })
            }
        }
    }

    # --- 6. Console output ----------------------------------------------------
    Write-Host ''
    Write-Host '  ===================== LIVE HOSTS =====================' -ForegroundColor Cyan
    foreach ($h in $hostRecords) {
        $tag = if ($h.IsGateway) { ' [GATEWAY]' } else { '' }
        $portStr = if ($h.OpenPorts.Count) {
            ($h.OpenPorts | ForEach-Object { '{0}/{1}' -f $_.Port, $_.Service }) -join ', '
        } else { '(no common ports open)' }
        Write-Host ("  {0,-15} {1,-22} {2}" -f $h.IPAddress, ($h.HostName ?? $h.MAC ?? ''), $tag) -ForegroundColor White
        Write-Host ("      ports: {0}" -f $portStr) -ForegroundColor DarkGray
    }

    Write-Host ''
    Write-Host '  ====================== FINDINGS ======================' -ForegroundColor Cyan
    if ($findings.Count -eq 0) {
        Write-Host '  No risky exposed services detected. Nice.' -ForegroundColor Green
    }
    else {
        $order = @{ High = 0; Medium = 1; Low = 2 }
        foreach ($f in ($findings | Sort-Object { $order[$_.Severity] }, IP)) {
            $color = switch ($f.Severity) { 'High' { 'Red' } 'Medium' { 'Yellow' } default { 'Gray' } }
            Write-Host ("  [{0,-6}] {1,-15} {2}/{3,-14} {4}" -f `
                $f.Severity, $f.IP, $f.Port, $f.Service, $f.Reason) -ForegroundColor $color
        }
        Write-Host ''
        $high = @($findings | Where-Object Severity -eq 'High').Count
        $med  = @($findings | Where-Object Severity -eq 'Medium').Count
        $low  = @($findings | Where-Object Severity -eq 'Low').Count
        Write-Host ("  Summary: {0} High, {1} Medium, {2} Low across {3} host(s)." -f `
            $high, $med, $low, $hostRecords.Count) -ForegroundColor Cyan
    }
    Write-Host ''

    # --- 7. Reports -----------------------------------------------------------
    $auditObject = [pscustomobject]@{
        GeneratedAt = (Get-Date).ToString('s')
        Subnet      = $Subnet
        Context     = $ctx
        Hosts       = $hostRecords
        Findings    = $findings
    }

    if ($OutFile) {
        $html = ConvertTo-AuditHtml -Audit $auditObject
        Set-Content -Path $OutFile -Value $html -Encoding UTF8
        Write-Host ("  HTML report written to: {0}" -f (Resolve-Path -LiteralPath $OutFile)) -ForegroundColor Green

        if ($Json) {
            $jsonPath = [System.IO.Path]::ChangeExtension($OutFile, 'json')
            $auditObject | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonPath -Encoding UTF8
            Write-Host ("  JSON report written to: {0}" -f (Resolve-Path -LiteralPath $jsonPath)) -ForegroundColor Green
        }
    }
    elseif ($Json) {
        $auditObject | ConvertTo-Json -Depth 6
    }

    return $auditObject
}

function ConvertTo-AuditHtml {
    <# Produces a self-contained, styled HTML report from an audit object. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Audit)

    $enc = { param($s) [System.Web.HttpUtility]::HtmlEncode([string]$s) }
    # HttpUtility may be unavailable in some hosts; provide a minimal fallback.
    try { Add-Type -AssemblyName System.Web -ErrorAction Stop } catch { }
    $esc = {
        param($s)
        $t = [string]$s
        $t = $t -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;'
        return $t
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine('<title>Network Audit Report</title><style>')
    [void]$sb.AppendLine(@'
body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#0f1419;color:#e6e6e6}
header{background:#11202e;padding:24px 32px;border-bottom:3px solid #2b8a8a}
h1{margin:0;font-size:22px;color:#7fdbff}
.warn{background:#3a2a00;color:#ffd166;padding:10px 16px;border-left:4px solid #ffd166;margin:16px 32px;border-radius:4px}
.meta{margin:16px 32px;font-size:13px;color:#9fb3c8}
.meta b{color:#cfe3f3}
section{margin:24px 32px}
h2{color:#7fdbff;border-bottom:1px solid #29404f;padding-bottom:6px}
table{border-collapse:collapse;width:100%;font-size:13px;margin-top:8px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #233544}
th{background:#16242f;color:#9fb3c8;position:sticky;top:0}
tr:hover{background:#16242f}
.sev-High{color:#ff6b6b;font-weight:bold}
.sev-Medium{color:#ffd166;font-weight:bold}
.sev-Low{color:#9fb3c8}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;background:#2b8a8a;color:#001}
.gw{background:#3a2a00;color:#ffd166}
.mono{font-family:Consolas,monospace}
footer{margin:32px;font-size:11px;color:#5a6b7a}
'@)
    [void]$sb.AppendLine('</style></head><body>')
    [void]$sb.AppendLine('<header><h1>Home Network Security Audit</h1></header>')
    [void]$sb.AppendLine('<div class="warn"><b>AUTHORIZED USE ONLY.</b> This report covers only networks the operator owns or is authorized to test.</div>')

    $c = $Audit.Context
    [void]$sb.AppendLine('<div class="meta">')
    [void]$sb.AppendLine(("<div><b>Generated:</b> {0}</div>" -f (& $esc $Audit.GeneratedAt)))
    [void]$sb.AppendLine(("<div><b>Subnet:</b> {0}</div>" -f (& $esc $Audit.Subnet)))
    [void]$sb.AppendLine(("<div><b>Local IP:</b> {0} &nbsp; <b>Gateway:</b> {1} &nbsp; <b>Interface:</b> {2}</div>" -f (& $esc $c.IPAddress), (& $esc $c.Gateway), (& $esc $c.Interface)))
    [void]$sb.AppendLine(("<div><b>DNS:</b> {0}</div>" -f (& $esc ($c.DnsServers -join ', '))))
    [void]$sb.AppendLine('</div>')

    # Findings summary
    $high = @($Audit.Findings | Where-Object Severity -eq 'High').Count
    $med  = @($Audit.Findings | Where-Object Severity -eq 'Medium').Count
    $low  = @($Audit.Findings | Where-Object Severity -eq 'Low').Count
    [void]$sb.AppendLine('<section><h2>Findings</h2>')
    [void]$sb.AppendLine(("<p><span class='sev-High'>{0} High</span> &nbsp; <span class='sev-Medium'>{1} Medium</span> &nbsp; <span class='sev-Low'>{2} Low</span></p>" -f $high, $med, $low))
    if (@($Audit.Findings).Count -eq 0) {
        [void]$sb.AppendLine('<p>No risky exposed services detected.</p>')
    } else {
        [void]$sb.AppendLine('<table><tr><th>Severity</th><th>Host</th><th>Port</th><th>Service</th><th>Reason</th></tr>')
        $order = @{ High = 0; Medium = 1; Low = 2 }
        foreach ($f in ($Audit.Findings | Sort-Object { $order[$_.Severity] }, IP)) {
            $hostLabel = if ($f.HostName) { "$($f.IP) ($($f.HostName))" } else { $f.IP }
            [void]$sb.AppendLine(("<tr><td class='sev-{0}'>{0}</td><td class='mono'>{1}</td><td class='mono'>{2}</td><td>{3}</td><td>{4}</td></tr>" -f `
                (& $esc $f.Severity), (& $esc $hostLabel), $f.Port, (& $esc $f.Service), (& $esc $f.Reason)))
        }
        [void]$sb.AppendLine('</table>')
    }
    [void]$sb.AppendLine('</section>')

    # Hosts table
    [void]$sb.AppendLine('<section><h2>Live Hosts</h2>')
    [void]$sb.AppendLine('<table><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Open Ports</th></tr>')
    foreach ($h in $Audit.Hosts) {
        $ports = if (@($h.OpenPorts).Count) { (@($h.OpenPorts) | ForEach-Object { '{0}/{1}' -f $_.Port, $_.Service }) -join ', ' } else { '-' }
        $gw = if ($h.IsGateway) { " <span class='badge gw'>GATEWAY</span>" } else { '' }
        [void]$sb.AppendLine(("<tr><td class='mono'>{0}{1}</td><td>{2}</td><td class='mono'>{3}</td><td class='mono'>{4}</td></tr>" -f `
            (& $esc $h.IPAddress), $gw, (& $esc $h.HostName), (& $esc $h.MAC), (& $esc $ports)))
    }
    [void]$sb.AppendLine('</table></section>')
    [void]$sb.AppendLine('<footer>Generated by Invoke-NetworkAudit.ps1 - defensive auditing tool. Authorized use only.</footer>')
    [void]$sb.AppendLine('</body></html>')
    return $sb.ToString()
}

#endregion

# ------------------------------- Entry point ---------------------------------
# Only auto-run when executed as a script (not dot-sourced for testing).
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-NetworkAudit -Subnet $Subnet -Ports $Ports -Quick:$Quick `
        -TimeoutMs $TimeoutMs -ThrottleLimit $ThrottleLimit -OutFile $OutFile -Json:$Json
}
