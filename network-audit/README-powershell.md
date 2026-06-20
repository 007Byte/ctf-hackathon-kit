# Home Network Security Audit Suite (Native Windows / PowerShell)

A pure-PowerShell, no-Python defensive auditing toolkit for a defender to run on
their **own** Windows 11 laptop. Three scripts cover the network, the airwaves,
and the local host:

| Script | Purpose | Needs Admin? |
|---|---|---|
| `Invoke-NetworkAudit.ps1` | Discover live hosts on your LAN, scan their TCP ports, flag risky exposed services. | No |
| `Get-WifiAudit.ps1` | Passively list nearby Wi-Fi networks and audit saved profiles; flag weak crypto. | No (admin can help) |
| `Get-NetworkHygiene.ps1` | Audit the security posture of the laptop itself (firewall, SMBv1, Defender, ports, shares, services, updates). | Recommended |

Works on **PowerShell 7+** (uses `ForEach-Object -Parallel` for speed) and
degrades gracefully to **Windows PowerShell 5.1** (runspace-pool fallback).

---

## AUTHORIZED USE ONLY

> **Run these tools only against networks and devices you own or are explicitly
> authorized to test.** Active host discovery and port scanning of networks you
> do not control may be illegal and violate provider terms of service. These
> scripts are built for a defender auditing their **own** home network. The
> author/operator is solely responsible for ensuring authorization.

**Privacy note (Wi-Fi):** `Get-WifiAudit.ps1 -ShowKeys` reveals the stored
passwords for *your own* saved Wi-Fi networks (via `netsh wlan show profile
key=clear`). Any HTML/JSON report containing this data is sensitive — do not
share it. Keys are hidden by default.

---

## Running the scripts

If script execution is blocked by policy, bypass it for a single run without
changing system settings:

```powershell
powershell -ExecutionPolicy Bypass -File .\Invoke-NetworkAudit.ps1
```

In PowerShell 7 the executable is `pwsh`:

```powershell
pwsh -ExecutionPolicy Bypass -File .\Invoke-NetworkAudit.ps1
```

To launch elevated (for the hygiene check), start an **Administrator** PowerShell
and run the script from there, or:

```powershell
Start-Process pwsh -Verb RunAs -ArgumentList '-ExecutionPolicy','Bypass','-File','.\Get-NetworkHygiene.ps1'
```

View the built-in help for any script:

```powershell
Get-Help .\Invoke-NetworkAudit.ps1 -Full
```

---

## 1. `Invoke-NetworkAudit.ps1` — LAN auditor

Auto-detects your subnet and gateway, finds live hosts (ARP/neighbor cache +
parallel ICMP/TCP ping sweep), resolves hostnames, scans common TCP ports, and
flags risky exposed services.

**Parameters**

- `-Subnet <CIDR>` — e.g. `192.168.1.0/24`. Auto-detected if omitted. Supported range `/16`–`/30`.
- `-Ports <int[]>` — override the port list (defaults to a curated common/risky set).
- `-Quick` — ping + small top-risk port list, skips reverse DNS (fastest).
- `-TimeoutMs <int>` — per-port TCP connect timeout (default 400 ms).
- `-ThrottleLimit <int>` — max concurrent threads (default 64).
- `-OutFile <path>` — write a self-contained styled HTML report.
- `-Json` — also write JSON (sibling `.json`, or to stdout if no `-OutFile`).

**Examples**

```powershell
# Auto-detect and audit, console only
.\Invoke-NetworkAudit.ps1

# Specific subnet, full HTML + JSON report
.\Invoke-NetworkAudit.ps1 -Subnet 192.168.1.0/24 -OutFile .\report.html -Json

# Fast pass
.\Invoke-NetworkAudit.ps1 -Quick

# Custom ports
.\Invoke-NetworkAudit.ps1 -Ports 22,80,443,8443
```

**Privileges:** none required. `Get-NetNeighbor` and the ping/TCP sweep run as a
standard user.

---

## 2. `Get-WifiAudit.ps1` — passive Wi-Fi auditor

Uses built-in `netsh wlan` commands only. **No cracking, no deauth, no attacks.**

- Lists nearby networks (`netsh wlan show networks mode=bssid`) — SSID, BSSID,
  signal, radio type, channel, authentication, encryption.
- Audits saved profiles (`netsh wlan show profiles` + `show profile name=<x>
  key=clear`) — flags saved Open/weak networks; can surface stored keys.

**Parameters**

- `-ShowKeys` — include stored Wi-Fi passwords for saved profiles (off by default; see privacy note).
- `-SkipProfiles` — only scan nearby networks.
- `-OutFile <path>` / `-Json` — HTML and/or JSON report.

**Examples**

```powershell
.\Get-WifiAudit.ps1
.\Get-WifiAudit.ps1 -OutFile .\wifi.html -Json
.\Get-WifiAudit.ps1 -ShowKeys          # reveals your own stored keys
```

**Privileges:** standard user can list networks and profiles. Note that
`netsh wlan` requires a wireless adapter and the **WLAN AutoConfig** service
running; the script reports clearly if no Wi-Fi interface is present.

---

## 3. `Get-NetworkHygiene.ps1` — local host hygiene

Hardens the very laptop you scan from. Checks:

- **Firewall** per profile (`Get-NetFirewallProfile`) — disabled profile or
  default-inbound-Allow is flagged High.
- **Listening ports** (`Get-NetTCPConnection -Listen`) with owning process —
  network-reachable risky listeners (Telnet/FTP/RDP/SMB/VNC/DB) flagged.
- **SMBv1** (`Get-SmbServerConfiguration` + `Get-WindowsOptionalFeature`).
- **Defender** (`Get-MpComputerStatus`) — AV enabled, real-time protection,
  signature age.
- **Shares** (`Get-SmbShare` / `Get-SmbShareAccess`) — Everyone/Anonymous/Guest
  access flagged.
- **Risky services** (Telnet server, RemoteRegistry, UPnP, WinRM, etc.).
- **Pending updates** (best-effort via Windows Update COM API).

Each issue is a finding with **Severity** + **Remediation** command.

**Examples**

```powershell
# Best run elevated for full detail
.\Get-NetworkHygiene.ps1
.\Get-NetworkHygiene.ps1 -OutFile .\hygiene.html -Json
```

**Privileges:** runs as standard user but is **more complete as Administrator**
(full firewall detail, all process owners, Defender + SMB server config). The
script notes when data is unavailable.

---

## Understanding findings / severities

| Severity | Meaning |
|---|---|
| **High** | Likely exploitable or cleartext-credential exposure (Telnet, FTP, exposed DB, open/WEP Wi-Fi, firewall off, SMBv1 on, AV off). Act promptly. |
| **Medium** | Weak or legacy configuration (WPA/TKIP, plaintext HTTP admin, RemoteRegistry, exposed RDP/SMB on host). Review and harden. |
| **Low** | Minor / context-dependent (WPA2-Personal note, common services that may be intended). Confirm it is intended. |
| **Info** | Neutral inventory data (counts, shares, items that could not be determined). |
| **Good** | A check passed (firewall on, SMBv1 off, AV + real-time protection on, WPA3). |

**Common LAN findings and what to do**

- *Telnet (23) / FTP (21) open* — disable and use SSH/SFTP/HTTPS instead.
- *SMB (445/139) exposed* — restrict to trusted hosts; never expose to the internet.
- *RDP (3389) open* — require NLA, strong passwords/MFA, restrict source IPs.
- *Open database port (MySQL/MSSQL/PostgreSQL/Redis/MongoDB/Elasticsearch)* —
  bind to localhost, enable auth, firewall it off the LAN.
- *Plaintext HTTP admin (80/8080)* — move admin UIs to HTTPS.

**Common Wi-Fi findings**

- *Open / WEP* — High: replace with WPA2/WPA3 (AES) immediately.
- *WPA (v1) / TKIP* — Medium: upgrade to WPA2/WPA3 with AES (CCMP).
- *WPA2-Personal* — acceptable; prefer WPA3 where supported.

---

## Output files

- HTML reports are **self-contained** (inline CSS, no external assets) — open in
  any browser, easy to archive or attach.
- JSON output (`-Json`) is machine-readable for diffing scans over time or
  feeding into other tooling.

## Safety / footprint

- All scanning is **read-only / connect-only**. No exploits, payloads, or
  configuration changes are made by these scripts (remediation commands are
  *printed* for you to run, never executed).
- The LAN sweep uses short connect timeouts and bounded concurrency to stay
  light on the network.
