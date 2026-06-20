# 🚩 CTF / Hackathon Starter Pack

A complete, offline-ready toolkit for cyber CTFs and hackathons (Hack The Box / picoCTF / TryHackMe style). Everything here is for **authorized, educational, and competition use only.**

> **First time? Read in this order:** `roadmap/learning-roadmap.md` → run the setup (`checklists/kali-setup-checklist.md`) → skim every cheatsheet → practice on picoCTF/HTB → the night before, run `checklists/pre-competition-checklist.md`.

---

## 📁 What's in here

### `checklists/` — Don't-forget-anything lists
| File | Use it for |
|------|-----------|
| `kali-setup-checklist.md` | Building & verifying your Kali box from scratch |
| `pre-competition-checklist.md` | Night-before & day-of readiness |
| `privesc-linux-checklist.md` | Linux privilege escalation, step by step |
| `privesc-windows-checklist.md` | Windows privilege escalation, step by step |
| `web-enumeration-checklist.md` | Ordered web-app attack flow |

### `cheatsheets/` — Copy-paste under pressure
| File | Use it for |
|------|-----------|
| `ctf-master-cheatsheet.md` | The big one — every category, copy-pasteable commands |
| `reverse-shells.md` | Every reverse/bind shell + TTY stabilization |
| `common-payloads.md` | XSS / SQLi / SSTI / LFI / XXE / SSRF / JWT payloads |
| `nmap-cheatsheet.md` | Focused nmap reference + CTF scan workflow |
| `linux-fluency.md` | grep/sed/awk, file transfer, tmux, SSH tunneling |

### `tools/` — Custom purpose-built tools (go deep)
| File | Use it for |
|------|-----------|
| `pcap/pcap-analyzer.py` | All-in-one PCAP triage (creds, http, dns, streams, flags) |
| `pcap/extract-files.py` | Carve files out of captured traffic |
| `pcap/tshark-helper.sh` | tshark filter wrapper (objects, follow, creds…) |
| `nmap/smart-scan.sh` | Staged nmap scan + next-step suggestions |
| `nmap/nmap-parser.py` | nmap XML → table/markdown/csv/json/targets |
| `nmap/nse-vuln-scan.sh` | Service-aware NSE vuln scripts |
| `reversing/bin-triage.sh` | One-shot binary triage (checksec/strings/symbols) |
| `reversing/r2-auto.py` | radare2 automation + dangerous-call/win-func detection |
| `reversing/ghidra-decompile.sh` | Headless Ghidra → decompiled C |
| `recon/server-enum.sh` | Deep per-service enumeration orchestrator |
| `recon/smb-enum.sh` | Focused SMB enumeration |
| `recon/http-recon.py` | HTTP fingerprint / forms / files / flags |
| `recon/service-brute.sh` | Guarded hydra credential-testing wrapper |

See `tools/README.md` for the full index and recommended chains.

### `network-audit/` — Home-network security audit (defensive)
Scan a network **you own/are authorized to test** for exposed services, weak/default creds, backdoor indicators, router misconfig, and UPnP exposure → one HTML report. Cross-platform Python **and** native PowerShell.
| File | Use it for |
|------|-----------|
| `audit.py` | One-command orchestrator → `report.html` (runs all Python tools) |
| `host-discovery.py` / `port-service-scan.py` | Find devices, open ports, risky services |
| `backdoor-scan.py` | Known RAT/backdoor ports + banner mismatches |
| `weak-creds-check.py` | Default-credential test (rate-limited, opt-in) |
| `router-audit.py` / `upnp-scan.py` | Gateway hardening + UPnP IGD exposure |
| `Invoke-NetworkAudit.ps1` / `Get-WifiAudit.ps1` / `Get-NetworkHygiene.ps1` | Native Windows: LAN audit, Wi-Fi weakness, laptop hardening |

Run: `python network-audit/audit.py --quick`  →  open `audit-results/report.html`. See `network-audit/README.md`.

### `scripts/` — Automation
| File | Use it for |
|------|-----------|
| `install/install-tools.sh` | One-shot Kali/Debian toolkit installer |
| `install/install-python-libs.sh` | pwntools, pycryptodome, scapy, etc. (PEP 668-aware) |
| `install/windows-host-setup.md` | Setting up the Windows 11 host (WSL2, VMs, tools) |
| `recon/auto-recon.sh` | Full single-target recon orchestrator |
| `recon/web-enum.sh` | Web fingerprint + directory/vhost fuzzing |
| `recon/port-scan.py` | Pure-Python threaded port scanner (nmap fallback) |
| `recon/subdomain-enum.py` | DNS brute + crt.sh subdomain enumeration |
| `recon/flag-finder.sh` | Recursively hunt `flag{...}` patterns post-exploit |

### `templates/` — Copy at the start of a challenge
| File | Use it for |
|------|-----------|
| `pwn-template.py` | pwntools binary-exploitation scaffold (LOCAL/REMOTE/GDB) |
| `web-exploit-template.py` | requests session + Burp proxy + CSRF handling |
| `crypto-template.py` | RSA / XOR / encoding helpers |
| `scapy-network-template.py` | Sniff / parse pcap / craft packets |
| `forensics-helpers.py` | Magic detection, entropy, strings, carving, EXIF |

### `roadmap/` — Learn the craft
| File | Use it for |
|------|-----------|
| `learning-roadmap.md` | Category-by-category study plan + phased schedule |
| `resources-and-platforms.md` | Curated practice sites, references, OSINT, YouTube |
| `note-taking-and-workflow.md` | Note templates, team roles, personal workflow |

### `vulns/` — Pattern recognition
| File | Use it for |
|------|-----------|
| `common-vulnerabilities.md` | 18 top vulns: detect / exploit / how they show up in CTFs |

### `cheatsheet.html` — Printable
Open in a browser → **Ctrl+P → Save as PDF** for an offline one-file reference.

---

## ⚡ Quick start (on Kali)

```bash
# 1. Get the pack onto Kali (clone, scp, or shared folder), then:
cd CY5770/Hackathon

# 2. Fix Windows line endings (these files were authored on Windows)
sudo apt install -y dos2unix
find . -name '*.sh' -exec dos2unix {} \;

# 3. Install everything
chmod +x scripts/install/*.sh scripts/recon/*.sh
sudo ./scripts/install/install-tools.sh
./scripts/install/install-python-libs.sh          # choose venv mode

# 4. Load the aliases (every shell)
echo 'source ~/CY5770/Hackathon/aliases/ctf-aliases.sh' >> ~/.bashrc
source ~/.bashrc && ctfhelp

# 5. New challenge? Scaffold a folder:
mkctf web-login-bypass
```

> ⚠️ **Line endings:** all `.sh`/`.py` files were written on Windows (CRLF). Run `dos2unix` (step 2) before executing on Linux or you'll get `bad interpreter` / `\r` errors.

---

## 🏁 The 4 things that win CTFs (more than tools)
1. **Notes** — document every command, payload, and trick (`roadmap/note-taking-and-workflow.md`).
2. **Speed** — fast enumeration + Linux fluency. Practice now, not during the event.
3. **Pattern recognition** — most challenges reuse the same vulns (`vulns/common-vulnerabilities.md`).
4. **Team coordination** — split by category (Web / Crypto / RE-Pwn / Forensics / OSINT).

## ⚖️ Legal & ethical
Only use these tools and techniques against systems you own or are **explicitly authorized** to test (CTF targets, lab VMs, HTB/THM machines, scoped engagements). Unauthorized access is illegal.

---
*Built as a starter pack. Customize it — the best toolkit is the one you've made your own.*
