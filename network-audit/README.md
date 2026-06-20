# 🛡️ Home-Network Security Audit Suite

Custom tools to audit **your own** home/lab network for exposed services, weak/default credentials, backdoor indicators, router misconfigurations, and risky UPnP exposure — then roll it all into one HTML report. Runs on a **Windows 11 laptop** (Python *or* native PowerShell) and on Linux.

> ## ⚠️ AUTHORIZED NETWORKS ONLY
> Run these tools **only against networks you own or have explicit written permission to test.** Port scanning, credential testing, and service probing of networks you do not control may be **illegal**. The credential tester actively attempts logins — it is **off by default**. Findings are *heuristic indicators to investigate*, not proof of compromise.

---

## 🚀 Quick start — one command, full report

```bash
# Python (cross-platform). From this folder:
python audit.py                 # auto-detect your subnet, scan, write HTML report
python audit.py --quick         # faster (top-20 ports)
python audit.py 192.168.1.0/24  # explicit subnet
python audit.py --check-creds   # ALSO test default credentials (intrusive)
```
Open the result: **`audit-results/report.html`** (also `report.txt` + `combined.json`).

```powershell
# Native Windows — no Python needed (run PowerShell as Administrator for full data):
powershell -ExecutionPolicy Bypass -File .\Invoke-NetworkAudit.ps1 -OutFile report.html
powershell -ExecutionPolicy Bypass -File .\Get-WifiAudit.ps1
powershell -ExecutionPolicy Bypass -File .\Get-NetworkHygiene.ps1
```

---

## 🧰 What's inside

### `audit.py` — Orchestrator
Runs the Python tools in a pipeline (discovery → port scan → backdoor scan → optional creds → router → UPnP), aggregates every tool's JSON, and writes a styled **HTML + text + combined-JSON** report. Flags: `--quick`, `--check-creds`, `-o <dir>`, `--skip-router/--skip-upnp/--skip-backdoor/--skip-discovery`.

### Python tools (cross-platform, stdlib-first)
| Tool | What it finds |
|------|---------------|
| `host-discovery.py` | Live devices on the subnet — IP, MAC, vendor (OUI), hostname. Auto-detects your subnet. |
| `port-service-scan.py` | Open ports + service/banner ID; flags risky exposed services (Telnet, SMB, RDP, DBs, Docker API…). |
| `backdoor-scan.py` | Known RAT/backdoor ports (Back Orifice, NetBus, Metasploit 4444, ADB 5555…), banner/port mismatches, unauth VNC. |
| `weak-creds-check.py` | Default/weak credentials on HTTP/SSH/FTP/Telnet/MySQL — **rate-limited, capped, opt-in, `--dry-run`**. |
| `router-audit.py` | Gateway: plaintext admin, missing security headers, exposed Telnet/SSH, TLS basics, DNS check. |
| `upnp-scan.py` | UPnP/SSDP devices; flags exposed IGD port-mapping (a classic home-network risk). |
| `default-creds.json` | ~80 default credential pairs (generic + per-vendor) used by the creds checker. |

### Native PowerShell tools (no Python required)
| Script | What it does | Admin? |
|--------|--------------|--------|
| `Invoke-NetworkAudit.ps1` | LAN discovery + port scan + findings → console + HTML/JSON | Recommended |
| `Get-WifiAudit.ps1` | **Passive** Wi-Fi audit: flags Open/WEP/TKIP/WPS nearby + saved networks | No |
| `Get-NetworkHygiene.ps1` | Audits *this laptop*: firewall, listening ports, SMBv1, Defender, shares | Yes (full data) |

---

## 📦 Dependencies
- **Python tools:** work with **standard library only** (no admin needed — uses TCP-connect scans). Optional, for more features:
  ```bash
  pip install requests scapy paramiko pymysql      # (or add --break-system-packages on Kali)
  ```
  - `requests` → nicer HTTP (urllib fallback built in) · `scapy` → faster ARP discovery · `paramiko`/`pymysql` → SSH/MySQL credential checks.
- **PowerShell tools:** PowerShell 7+ preferred (5.1 supported); some checks need Administrator. Wi-Fi scan needs Location services enabled for the terminal.

> 🪟 **Windows line endings:** these were authored on Windows, so they're ready to run on Windows. If you move them to **Kali/Linux**, run `sed -i 's/\r$//' *.py` first.

---

## 🔁 Recommended workflow
1. **Secure your own laptop first:** `Get-NetworkHygiene.ps1` (firewall on? SMBv1 off? unexpected listeners?).
2. **Map the network:** `python audit.py --quick` → review `report.html`.
3. **Investigate findings:** anything High/Critical (Telnet, default creds, exposed DB, UPnP IGD) → fix at the device/router.
4. **Check Wi-Fi:** `Get-WifiAudit.ps1` → ensure WPA2/WPA3, no WEP/Open, WPS off.
5. **Re-run after changes** to confirm the findings are gone.

## 🎯 What "good" looks like at home
- Router admin over **HTTPS** only, **strong non-default** password, remote admin **off**, **UPnP off** (or trusted only), **WPA2/WPA3** Wi-Fi, **no Telnet**, firmware **up to date**, IoT devices on a **guest/VLAN**, and your laptop's **firewall on** with **SMBv1 disabled**.

See the topic READMEs for per-tool detail: `README-scanning.md`, `README-creds-backdoor.md`, `README-router-upnp.md`, `README-powershell.md`.
