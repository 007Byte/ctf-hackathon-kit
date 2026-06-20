# Home-Network Security Audit Suite — Router & UPnP Tools

Two cross-platform (Windows 11 + Linux) Python 3 tools for a **defender** to
audit their **own** home network:

- `router-audit.py` — audits the home router/gateway.
- `upnp-scan.py` — discovers and audits UPnP/SSDP devices on the LAN.

---

## ⚠️ Authorization Warning

**AUTHORIZED USE ONLY.** Run these tools **only** against a router, device, or
network that **you own or are explicitly authorized to assess**. Scanning or
probing networks/devices you do not control may be **illegal**. These are
**defensive** tools intended for home-network self-assessment. The same notice
appears in the header of each tool.

Neither tool performs brute force, exploitation, or any modification of device
state. They read configuration and advertised metadata only.

---

## Dependencies

- **Python 3.6+** (tested with the standard library).
- No third-party packages are **required**.
  - If [`requests`](https://pypi.org/project/requests/) is installed it is used
    for HTTP(S) fetches; otherwise the tools fall back to `urllib` from the
    standard library automatically.
- UPnP discovery uses raw UDP sockets (standard library `socket`).

> On some systems, sending multicast or binding to a specific interface may
> require appropriate network permissions. No administrator/root privileges are
> normally needed for the default behavior.

---

## Tool 1 — `router-audit.py`

Audits the default gateway (your router).

### What it checks

| Check | Description |
|-------|-------------|
| Gateway auto-detection | Parses `ipconfig /all` / `route print` (Windows) or `ip route` / `route -n` / `netstat -rn` (Linux). Override with `--gateway`. |
| Reachability | TCP-connect test on common admin/service ports. |
| Admin port scan | 80, 443, 8080, 8443 (web), 23 (Telnet), 22 (SSH). |
| Admin page fetch | HTTP and HTTPS; captures `Server` header and page title. |
| Plaintext HTTP admin | Flags admin served over unencrypted HTTP. |
| Security headers | Reports missing HSTS, X-Frame-Options, CSP, X-Content-Type-Options. |
| TLS certificate basics | If HTTPS: version, cipher, subject/issuer, validity, self-signed detection. |
| Telnet/SSH exposure | Flags exposed remote-admin services. |
| Login form detection | Heuristic check for an HTML login form. |
| Default-credential advisory | Notes the risk and points to a weak-creds checker. **Does not brute force.** |
| DNS check | Reports configured DNS server(s); flags non-private, non-well-known public resolvers (possible DNS hijack). |

### Fingerprinting

Looks for vendor markers (Netgear, TP-Link, ASUS, Linksys, D-Link, OpenWrt,
etc.) in the `Server` header and page body to identify the router model.

### Usage

```bash
# Auto-detect the gateway and DNS, print a summary
python router-audit.py

# Audit a specific gateway and write JSON
python router-audit.py --gateway 192.168.1.1 --json router.json

# Override the DNS servers to report, tune timeouts
python router-audit.py --dns 192.168.1.1 8.8.8.8 --port-timeout 1.0 --http-timeout 8
```

### Key options

- `-g/--gateway <ip>` — gateway IP (default: auto-detect)
- `--dns <ip ...>` — DNS server(s) to report (default: auto-detect)
- `--json <file>` — write results in the shared schema
- `--port-timeout <s>` / `--http-timeout <s>` — connection timeouts

---

## Tool 2 — `upnp-scan.py`

Discovers UPnP devices via SSDP and enumerates their services.

### What it does

1. Sends SSDP **M-SEARCH** multicast to `239.255.255.250:1900` over UDP for
   several search targets (`ssdp:all`, `upnp:rootdevice`, and IGD device/service
   types).
2. Collects responses and extracts each device's `LOCATION`, `SERVER`, `ST`,
   `USN`.
3. Fetches and parses each device-description XML:
   `friendlyName`, `manufacturer`, `modelName`, `deviceType`.
4. **Enumerates all exposed UPnP services** (`serviceType` list).
5. **Flags IGD port-mapping**: `WANIPConnection` / `WANPPPConnection` (and
   `Layer3Forwarding`), the classic home-network risk where any LAN program can
   open firewall ports to the Internet without user awareness.

UPnP is UDP and best-effort. No replies may mean UPnP is **disabled** (good) or
that responses were blocked/slow. The tool handles timeouts gracefully.

### Usage

```bash
# Default 5s discovery, print a summary
python upnp-scan.py

# Longer discovery window, write JSON
python upnp-scan.py --timeout 8 --mx 3 --json upnp.json

# Send from a specific local interface
python upnp-scan.py --bind 192.168.1.50
```

### Key options

- `--timeout <s>` — how long to listen for SSDP replies (default 5)
- `--mx <n>` — SSDP `MX` max response-delay seconds (default 2)
- `--bind <ip>` — local interface IP to send from
- `--http-timeout <s>` — device-XML fetch timeout
- `--json <file>` — write results in the shared schema

---

## Finding Severities & What They Mean

### `router-audit.py`

| Finding | Severity | Meaning |
|---------|----------|---------|
| Telnet administration exposed (port 23) | **high** | Cleartext admin protocol; prime botnet target. Disable it. |
| Router admin over plaintext HTTP | **medium** | Credentials/cookies sniffable on the LAN. Use HTTPS. |
| Unrecognized public DNS server | **medium** | Non-private DNS not in the well-known list — possible DNS hijack. Verify it. |
| SSH administration exposed (port 22) | **low** | Encrypted but extra attack surface; ensure not WAN-exposed and uses strong/key auth. |
| Missing HTTP security headers | **low** | Admin UI lacks HSTS/XFO/CSP/X-Content-Type-Options. |
| Self-signed TLS cert | **low** | Normal for routers, but trains users to ignore TLS warnings. |
| Login form detected | **info** | Confirms an admin login exists; set strong credentials. |
| Default-credentials advisory | **info** | Reminder to run a weak-creds checker (no brute force here). |
| Router fingerprint | **info** | Identified vendor/model for firmware advisory lookups. |
| Configured DNS server(s) | **info** | The resolvers in use. |

### `upnp-scan.py`

| Finding | Severity | Meaning |
|---------|----------|---------|
| UPnP IGD port-mapping service exposed | **high** | `WANIPConnection`/`WANPPPConnection` present — LAN programs can open firewall ports to the Internet. Disable UPnP unless required. |
| UPnP IGD advertised | **medium** | Device is an Internet Gateway Device; port mapping is likely available. |
| UPnP Layer3Forwarding exposed | **low** | IGD routing/connection control service present. |
| UPnP device discovered | **info** | A discovered device with its enumerated services. |
| No UPnP devices discovered | **info** | Nothing replied — often means UPnP is off (good). |

Severity levels used across the suite: `info`, `low`, `medium`, `high`,
`critical`.

---

## Shared JSON Schema

Both tools write the same structure with `--json <file>`:

```json
{
  "tool": "<tool-name>",
  "target": "<scanned>",
  "hosts": [
    {
      "ip": "",
      "mac": "",
      "vendor": "",
      "hostname": "",
      "state": "up"
    }
  ],
  "findings": [
    {
      "host": "",
      "port": 0,
      "service": "",
      "severity": "info|low|medium|high|critical",
      "title": "",
      "detail": "",
      "recommendation": ""
    }
  ]
}
```

> Output files also include a non-schema `_generated` ISO-8601 timestamp for
> convenience; consumers should ignore unknown top-level keys.

Both tools also print a human-readable summary to stdout, with findings sorted
by severity.

---

## Quick Start

```bash
cd network-audit

# Audit your router
python router-audit.py --json router.json

# Inventory UPnP devices
python upnp-scan.py --json upnp.json
```

Review the printed summaries and the JSON output, then act on `high` and
`medium` findings first.
