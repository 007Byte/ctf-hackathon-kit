# Nmap CTF/Hackathon Toolkit

A small, self-contained set of Nmap automation and parsing tools for CTF and
hackathon recon. Built to run on Kali/Linux; authored on Windows 11.

> **AUTHORIZED TARGETS ONLY.** Every tool here is for systems you have explicit,
> written permission to test. Unauthorized scanning is illegal and can get you
> banned, fined, or prosecuted. You are responsible for how you use these.

## Contents

| File | What it does |
|------|--------------|
| `nmap-parser.py` | Parse Nmap XML (`-oX`) into table / markdown / CSV / JSON, plus `--grep` and `--targets` pipe modes. Pure stdlib. **Flagship tool.** |
| `smart-scan.sh` | Staged scan orchestrator: fast all-port discovery → focused `-sCV -A` → optional UDP, then auto-parse + next-step suggestions. |
| `nse-vuln-scan.sh` | Maps services → useful NSE scripts and runs them (http, smb, ftp, ssl, dns, fallback `vuln`). |

## Prerequisites

- **nmap** (`sudo apt install nmap`) — the scan scripts call it directly.
- **python3** — for `nmap-parser.py` (standard library only; no `pip install`).
- **bash** + coreutils (`grep`, `sort`, `paste`, `sed`) — present on Kali by default.
- Run with **sudo** when possible: SYN scans, OS detection, and UDP scans need
  raw-socket privileges.

### First-time setup (on Kali/Linux)

If you copied these from Windows, strip CRLF line endings and make them
executable:

```bash
cd tools/nmap
sed -i 's/\r$//' *.sh *.py        # remove Windows carriage returns
chmod +x smart-scan.sh nse-vuln-scan.sh nmap-parser.py
```

## Recommended workflow

```
   smart-scan.sh            nmap-parser.py            nse-vuln-scan.sh
  ┌──────────────┐         ┌──────────────┐          ┌────────────────┐
  │ discover all │  XML →  │ summarize /  │  ports → │ run targeted   │
  │ ports, -sCV  │ ──────► │ pick targets │ ───────► │ NSE vuln checks│
  └──────────────┘         └──────────────┘          └────────────────┘
```

1. **Scan** — full staged recon against a target:
   ```bash
   sudo ./smart-scan.sh 10.10.10.5 ./loot --udp
   ```
   Produces `phase1.xml`, `phase2.xml/.txt`, optional `phase3-udp.*`,
   a parsed `summary.txt`, and prints suggested next steps.

2. **Parse / pivot** — turn the XML into exactly the view you need:
   ```bash
   ./nmap-parser.py ./loot/phase2.xml --format markdown   # paste into notes
   ./nmap-parser.py ./loot/phase2.xml --targets http      # hosts with http
   ```

3. **Vuln-check** — run service-specific NSE scripts on the open ports:
   ```bash
   sudo ./nse-vuln-scan.sh 10.10.10.5 80,443,445 ./loot
   ```

## Tool reference

### `nmap-parser.py`

```
./nmap-parser.py <XML> [XML ...] [--format table|markdown|csv|json]
                                 [--grep] [--targets SERVICE]
```

| Option | Purpose |
|--------|---------|
| (default) | Per-host summary + open-ports table (`--format table`). |
| `--format markdown` | Markdown tables for CTF notes. |
| `--format csv` | One row per open port (spreadsheet / awk friendly). |
| `--format json` | Structured output incl. NSE script results. |
| `--grep` | `ip:port service` lines, one per open port. |
| `--targets SERVICE` | Print hosts (IPs) with SERVICE open; add `--grep` for `ip:port` lines. Understands aliases (`smb` → microsoft-ds/netbios-ssn, `http` → https/http-alt, etc.). |

Accepts multiple XML files at once and is robust to partial/missing fields.

**Examples**
```bash
./nmap-parser.py scan.xml                       # readable table
./nmap-parser.py *.xml --format json > out.json # merge many scans
./nmap-parser.py scan.xml --grep                # ip:port service
./nmap-parser.py scan.xml --targets smb         # feed into enum4linux
./nmap-parser.py scan.xml --targets http --grep # http endpoints to fuzz
```

### `smart-scan.sh`

```
./smart-scan.sh <target> [output_dir] [--udp]
```

- **Phase 1** — `nmap -p- --min-rate 2000 -T4 -Pn -n --open -oX phase1.xml`
- **Phase 2** — `nmap -sCV -A -Pn -n -p <discovered> -oX phase2.xml -oN phase2.txt`
- **Phase 3** — (with `--udp`) `nmap -sU --top-ports 100 ...`
- Auto-parses with `nmap-parser.py` if present (grep fallback otherwise) and
  prints next-step suggestions (e.g. `445 → enum4linux`, `80 → web enum`,
  `21 → anon FTP`).

### `nse-vuln-scan.sh`

```
./nse-vuln-scan.sh <target> [ports] [output_dir]
```

- If `ports` is omitted, runs a quick `-sV` scan to auto-detect open ports.
- Classifies each port by service and runs the matching scripts:

  | Service | NSE scripts |
  |---------|-------------|
  | http/https | `http-enum, http-title, http-headers, http-shellshock, http-vuln*` |
  | ssl/tls | `ssl-enum-ciphers, ssl-heartbleed` |
  | smb | `smb-os-discovery, smb-enum-shares, smb-enum-users, smb-vuln-ms17-010, smb-vuln*` |
  | ftp | `ftp-anon, ftp-vsftpd-backdoor, ftp-syst` |
  | dns | `dns-zone-transfer, dns-nsid` |
  | other | `--script vuln` |

- Saves `nse-<category>.txt/.xml` per category. Jump to findings with:
  ```bash
  grep -ri 'VULNERABLE' ./loot
  ```

## Notes & tuning

- `--min-rate 2000` is aggressive; lower it on fragile or rate-limited targets.
- `-Pn` is used throughout because CTF hosts commonly drop ICMP. Drop it if you
  want real host discovery.
- `-n` disables DNS resolution for speed; remove it if reverse DNS matters.
