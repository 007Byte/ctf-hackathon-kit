# 🛠️ Custom Tools

Purpose-built CTF tools, organized by domain. These are heavier, more capable than the quick helpers in `../scripts/recon/` — use them when you want depth. **Authorized CTF / lab targets only.**

> **First-time setup (on Kali/Linux):** these were authored on Windows, so strip CRLF and make executable before running:
> ```bash
> cd tools
> find . -name '*.sh' -exec sed -i 's/\r$//' {} \;
> find . -name '*.py' -exec sed -i 's/\r$//' {} \;
> chmod +x */*.sh
> pip install r2pipe requests scapy --break-system-packages   # or in a venv
> ```

---

## 📡 `pcap/` — Wireshark / packet analysis
| Tool | What it does |
|------|--------------|
| `pcap-analyzer.py` | All-in-one triage: `summary`, `dns`, `http`, `creds`, `streams`, `flags` (scapy) |
| `extract-files.py` | Carve files from HTTP transfers + magic-byte carver (JPG/PNG/PDF/ZIP/ELF…) |
| `tshark-helper.sh` | CLI wrapper for common tshark filters: `proto http dns creds objects follow ips strings` |

```bash
python3 pcap/pcap-analyzer.py creds capture.pcap
python3 pcap/pcap-analyzer.py flags capture.pcap --regex 'FLAG\{.*?\}'
python3 pcap/extract-files.py capture.pcap -o loot/
./pcap/tshark-helper.sh capture.pcap objects ./http_objects
```

## 🛰️ `nmap/` — Scanning & parsing
| Tool | What it does |
|------|--------------|
| `smart-scan.sh` | Staged scan: fast all-ports → `-sCV -A` on open → optional UDP → next-step suggestions |
| `nmap-parser.py` | Parse nmap XML → table / markdown / csv / json / `--grep` / `--targets <service>` |
| `nse-vuln-scan.sh` | Service-aware NSE vuln scripts (http/smb/ftp/ssl/dns → mapped scripts) |

```bash
./nmap/smart-scan.sh 10.10.10.5 ./results
python3 nmap/nmap-parser.py results/phase2.xml --format markdown
python3 nmap/nmap-parser.py results/phase2.xml --targets http --grep | ./nmap/nse-vuln-scan.sh -
```

## 🧩 `reversing/` — Reverse engineering
| Tool | What it does |
|------|--------------|
| `bin-triage.sh` | One-shot static triage: file/checksec/libs/symbols/strings/packer + next steps |
| `r2-auto.py` | r2pipe automation: functions, imports, dangerous-call scan, win-func detect, decompile main |
| `ghidra-decompile.sh` | Headless Ghidra → decompiled C for all functions (no GUI) |
| `DecompileToC.java` | Ghidra post-script used by the wrapper above |

```bash
./reversing/bin-triage.sh ./challenge
python3 reversing/r2-auto.py ./challenge
./reversing/ghidra-decompile.sh ./challenge ./out   # needs GHIDRA_HOME
```

## 🖥️ `recon/` — Deep server enumeration
*(Complements `../scripts/recon/` — those are the fast first pass; these go deep.)*
| Tool | What it does |
|------|--------------|
| `server-enum.sh` | Deep per-service enum (FTP/SSH/SMTP/DNS/HTTP/SMB/SNMP/LDAP/NFS/DB/RDP…) |
| `smb-enum.sh` | Focused SMB: shares, users, RID cycling, policy, MS17-010 |
| `http-recon.py` | HTTP analysis: headers, tech fingerprint, forms, interesting files, cookies, flags |
| `service-brute.sh` | Guarded hydra wrapper (ssh/ftp/smb/rdp/mysql/http-post-form) |

```bash
./recon/server-enum.sh 10.10.10.5 ./results
./recon/smb-enum.sh -t 10.10.10.5 -u guest -p ''
python3 recon/http-recon.py http://10.10.10.5 --json
```

---

## 🔗 Recommended chains
- **Box / server:** `nmap/smart-scan.sh` → `nmap/nmap-parser.py` → `tools/recon/server-enum.sh` → `tools/recon/smb-enum.sh` / `http-recon.py` → privesc checklist
- **PCAP challenge:** `pcap/pcap-analyzer.py summary` → `creds` / `http` / `dns` → `extract-files.py` → analyze carved files
- **RE/pwn challenge:** `reversing/bin-triage.sh` → `r2-auto.py` → `ghidra-decompile.sh` → gdb/pwndbg + `../templates/pwn-template.py`

See each subfolder's `README.md` for full per-tool docs and prereqs.
