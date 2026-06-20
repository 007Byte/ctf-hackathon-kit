# Home-Network Security Audit — Scanning Tools

Two cross-platform (Windows + Linux), Python 3 command-line tools for auditing
**your own** home network:

1. **`host-discovery.py`** — find live hosts on a subnet (IP, MAC, vendor, hostname).
2. **`port-service-scan.py`** — TCP port + service scan with risk findings.

---

## ⚠️ AUTHORIZED USE ONLY

These tools are for defenders auditing networks they **own or are explicitly
authorized to test**. Unauthorized scanning of networks or hosts may be illegal
in your jurisdiction. You are solely responsible for how you use them. Each
script repeats this warning in its file header and at runtime.

---

## Requirements

- **Python 3.7+** (uses only the standard library by default).
- **No admin/root required** for the default path — it uses TCP-connect scans,
  the OS `ping` command, and reads the existing ARP table.
- **Optional:** [`scapy`](https://scapy.net/) for a faster, more reliable
  layer-2 ARP scan in `host-discovery.py`. This is the *only* feature that
  needs admin/root (raw sockets). Without it, the tools degrade gracefully.

```bash
# Optional enhancement only:
pip install scapy
```

If scapy is missing (or you lack privileges), the tool prints an install hint
and falls back to the stdlib methods automatically.

---

## 1. `host-discovery.py`

Discovers live hosts and enriches each with MAC, vendor, and hostname.

**Methods:** TCP-connect "ping" to common ports + ICMP via the OS `ping`
command for liveness; reads the ARP table (`arp -a` / `ip neigh`) for MACs;
optional scapy ARP scan.

**Vendor lookup:** a small built-in OUI prefix map (~30 common vendors: Apple,
Samsung, Cisco, TP-Link, Netgear, Amazon, Google, Raspberry Pi, Intel,
Espressif, Ubiquiti, etc.). Drop in a full IEEE OUI file with `--oui-file
oui.txt` to expand coverage (format: `PREFIX  Vendor` per line; prefix may be
`AABBCC`, `AA:BB:CC`, or `AA-BB-CC`).

### Usage

```bash
# Auto-detect the local subnet and scan it
python host-discovery.py

# Scan an explicit subnet
python host-discovery.py 192.168.1.0/24

# Faster, more thorough (needs admin/root + scapy)
sudo python host-discovery.py 192.168.1.0/24 --scapy      # Linux
python host-discovery.py 192.168.1.0/24 --scapy           # Windows (Run as Admin)

# Tune performance / write JSON for the orchestrator
python host-discovery.py 192.168.1.0/24 --threads 150 --timeout 0.4 --json hosts.json

# Skip ICMP (TCP-connect probes only)
python host-discovery.py 192.168.1.0/24 --no-icmp

# Use a full OUI file
python host-discovery.py --oui-file oui.txt
```

### Key options

| Option | Description |
| --- | --- |
| `target` | CIDR/range to scan (optional; auto-detected if omitted). |
| `--threads N` | Concurrent probe threads (default 100). |
| `--timeout S` | Per-probe timeout in seconds (default 0.5). |
| `--no-icmp` | Skip ICMP; TCP-connect probes only. |
| `--scapy` | Use scapy ARP scan if available (needs admin/root). |
| `--oui-file PATH` | Merge a full OUI file with the built-in map. |
| `--json FILE` | Write shared-schema JSON output. |

---

## 2. `port-service-scan.py`

Threaded TCP-connect scanner. Grabs banners, identifies services, and flags
risky exposed services as **findings** with severities.

**Targets:** single IP, comma-separated list, CIDR, or hosts loaded from a
`host-discovery.py` JSON file via `--from-json`.

**Default ports:** ~100 common TCP ports. Override with `--ports`, `--top N`,
or `--full` (all 65535).

### Example findings

| Service / Port | Severity | Why |
| --- | --- | --- |
| Telnet / 23 | high | Cleartext admin protocol |
| FTP / 21 | medium | Often cleartext / anonymous |
| SMB / 139, 445 | medium + SMBv1 check (high) | File sharing, wormable history |
| Databases (MySQL 3306, MSSQL 1433, PostgreSQL 5432, MongoDB 27017, Redis 6379, Elasticsearch 9200) | high | Should not be LAN-reachable |
| Docker API / 2375 | critical | Unauthenticated host takeover |
| RDP / 3389 | medium | Brute-force / exploit target |
| VNC / 5900 | high | Often weak/unencrypted |
| SNMP / 161 | medium | Default community strings |
| UPnP/SSDP / 1900 | low | Auto port-forwarding, info leak |
| Unencrypted HTTP admin (80/8080/…) | low | Cleartext credentials |

### Usage

```bash
# Scan one host with the default port set
python port-service-scan.py 192.168.1.10

# Scan a list or a CIDR
python port-service-scan.py 192.168.1.10,192.168.1.20
python port-service-scan.py 192.168.1.0/24

# Scan hosts discovered earlier, write JSON
python port-service-scan.py --from-json hosts.json --json scan.json

# Custom ports / top-N / full
python port-service-scan.py 192.168.1.10 --ports 22,80,443,8000-8100
python port-service-scan.py 192.168.1.10 --top 50
python port-service-scan.py 192.168.1.10 --full        # slow

# Tune speed
python port-service-scan.py 192.168.1.10 --threads 300 --timeout 0.5
```

### Key options

| Option | Description |
| --- | --- |
| `target` | IP, comma-list, or CIDR. |
| `--from-json FILE` | Load hosts from a host-discovery JSON file. |
| `--ports LIST` | Explicit ports/ranges, e.g. `22,80,8000-8100`. |
| `--top N` | Scan the top N common ports. |
| `--full` | Scan all 65535 TCP ports. |
| `--timeout S` | Per-port connect timeout (default 0.7s). |
| `--threads N` | Concurrent threads per host (default 200). |
| `--json FILE` | Write shared-schema JSON output. |

---

## Typical workflow

```bash
# 1) Discover hosts on your subnet
python host-discovery.py --json hosts.json

# 2) Scan everything that was found
python port-service-scan.py --from-json hosts.json --json scan.json

# 3) Feed hosts.json / scan.json into your aggregator/orchestrator
```

---

## Shared JSON schema

Both tools write the **same** top-level JSON object so an orchestrator can
aggregate results. Arrays that don't apply to a tool are left empty.

```json
{
  "tool": "<tool-name>",
  "target": "<what was scanned>",
  "hosts": [
    { "ip": "", "mac": "", "vendor": "", "hostname": "", "state": "up" }
  ],
  "findings": [
    {
      "host": "", "port": 0, "service": "",
      "severity": "info|low|medium|high|critical",
      "title": "", "detail": "", "recommendation": ""
    }
  ]
}
```

- `host-discovery.py` populates `hosts` (and leaves `findings` empty).
- `port-service-scan.py` populates `findings` (and `hosts` with `ip`/`state`).

---

## Windows vs Linux notes

| Concern | Windows | Linux / macOS |
| --- | --- | --- |
| Subnet auto-detect | Parses `ipconfig` (IPv4 + Subnet Mask). | Parses `ip addr` (`inet x/NN`). |
| ICMP ping flags | `ping -n 1 -w <ms>`. | `ping -c 1 -W <sec>`. |
| ARP table | `arp -a` (MACs use `-` separators). | `ip neigh` / `arp -a` / `arp -n` (`:` separators). |
| MAC normalization | Handled — both `-` and `:` separators parsed. | Same. |
| scapy ARP scan | Run terminal **as Administrator**. | Use `sudo`. Needs Npcap on Windows. |
| Admin/root | Only for `--scapy`. Everything else runs as a normal user. | Same. |

**Reverse DNS / hostnames** are best-effort (`socket.gethostbyaddr`). Many home
IoT devices have no PTR record and will show a blank hostname — that is normal.

**Firewalls:** A host that drops both ICMP and all probed TCP ports may not be
detected by the stdlib path. The ARP table and `--scapy` help catch these on the
local segment.
