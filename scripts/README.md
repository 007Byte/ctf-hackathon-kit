# CTF / Hackathon Recon Scripts

Original helper scripts for speeding up enumeration during CTFs, hackathons, and
lab exercises (Hack The Box / picoCTF / TryHackMe style).

> **AUTHORIZED USE ONLY.** Every script here is for machines you own or are
> explicitly permitted to test (CTF boxes, lab VMs, sanctioned engagements).
> Scanning, fuzzing, or flag-hunting systems without authorization may be
> illegal. You are responsible for staying in scope.

---

## Layout

```
scripts/
├── install/        # environment setup (tooling, Python libs, host setup)
│   ├── install-tools.sh
│   ├── install-python-libs.sh
│   └── windows-host-setup.md
├── recon/          # the enumeration helpers documented below
│   ├── auto-recon.sh
│   ├── web-enum.sh
│   ├── port-scan.py
│   ├── subdomain-enum.py
│   └── flag-finder.sh
└── README.md       # this file
```

### `install/` (created/maintained separately)

The `install/` directory contains setup helpers you typically run **once** to
prepare a fresh attacker box:

- **`install-tools.sh`** — installs the core recon CLI tools (nmap, ffuf,
  gobuster/feroxbuster, whatweb, rustscan, etc.).
- **`install-python-libs.sh`** — installs Python dependencies (e.g. `requests`)
  used by the Python helpers in `recon/`.
- **`windows-host-setup.md`** — notes for setting up the toolchain / WSL on a
  Windows host.

Run these first if your environment is missing tools. The `recon/` scripts all
degrade gracefully when a tool is absent, but they are far more useful with the
full toolchain installed.

---

## Prerequisites

| Script | Needs | Optional / fallback |
| --- | --- | --- |
| `auto-recon.sh` | `bash`, `nmap` | `whatweb`, `ffuf`/`gobuster`, `web-enum.sh` |
| `web-enum.sh` | `bash`, `curl` | `whatweb`, `ffuf`/`gobuster`, SecLists |
| `port-scan.py` | `python3` (stdlib only) | — (zero external deps) |
| `subdomain-enum.py` | `python3` | `requests` (falls back to `urllib`) |
| `flag-finder.sh` | `bash`, `grep`/`find` | `rg` (ripgrep, faster), `base64` |

Make the shell scripts executable once after checkout:

```bash
chmod +x recon/*.sh
```

Many web scripts default to **SecLists** wordlists. Install SecLists or point
the scripts at your own list via the `-w` flag or the `SECLISTS_WORDLIST`
environment variable.

---

## Recon Scripts

### 1. `auto-recon.sh` — single-target recon orchestrator

Layered workflow against one host: quick top-ports nmap → full TCP sweep →
targeted `-sCV` on the open ports → clear port summary → conditional web
enumeration if 80/443/8080/8443 are open. All artifacts saved to a per-target
results folder. Missing tools are warned about and skipped.

```bash
# Basic run (auto-creates ./recon-<target>-<timestamp>/)
./recon/auto-recon.sh 10.10.10.5

# Custom output directory
./recon/auto-recon.sh target.htb ./box1-results

# Override the directory-fuzzing wordlist used by the inline web step
SECLISTS_WORDLIST=/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  ./recon/auto-recon.sh 192.168.56.101
```

**Output:** `01_quick.nmap`, `02_allports.nmap`, `03_services.nmap`, plus a
`web_*/` subfolder per discovered web service.

> No nmap? Use the Python fallback: `python3 recon/port-scan.py <target> --common`.

---

### 2. `web-enum.sh` — web application enumeration helper

Fingerprints a URL (whatweb), grabs headers, pulls `robots.txt`/`sitemap.xml`,
runs directory fuzzing (ffuf preferred, gobuster fallback) against a SecLists
wordlist, and optionally fuzzes virtual hosts / subdomains.

```bash
# Default content-discovery wordlist
./recon/web-enum.sh http://10.10.10.5

# Custom output dir + wordlist
./recon/web-enum.sh https://target.htb ./web-results \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# Add virtual-host / subdomain fuzzing for a known domain
./recon/web-enum.sh http://target.htb -d target.htb
```

**Env overrides:** `SECLISTS_WORDLIST` (content list), `VHOST_WORDLIST`
(vhost/subdomain list).

**Output:** `whatweb.txt`, `headers.txt`, `robots.txt`, `sitemap.xml`,
`ffuf.csv`/`gobuster.txt`, and `vhosts.*` when `-d` is used.

---

### 3. `port-scan.py` — dependency-free TCP port scanner

Pure-Python (standard library only) threaded TCP connect scanner. Use it as an
nmap fallback. Supports port ranges or a built-in common-ports list, adjustable
timeout/concurrency, banner grabbing, and JSON output.

```bash
# Common/CTF ports
python3 recon/port-scan.py 10.10.10.5 --common

# Full range, 500 workers, 0.5s timeout
python3 recon/port-scan.py target.htb -p 1-65535 -w 500 -t 0.5

# Specific ports with banner grab, JSON to file
python3 recon/port-scan.py 192.168.56.101 -p 22,80,443,8080 --banner -o results.json

# Pipe JSON into jq
python3 recon/port-scan.py 10.10.10.5 --common --json | jq .
```

---

### 4. `subdomain-enum.py` — subdomain enumeration (brute force + crt.sh)

Combines active DNS brute force (`<word>.<domain>`, concurrent) with passive
Certificate Transparency lookups via the crt.sh JSON API. Merges, de-duplicates,
and filters to live names. Uses `requests` when available, else `urllib`.

```bash
# Brute force + crt.sh, print live subdomains
python3 recon/subdomain-enum.py example.com -w subdomains.txt

# crt.sh only, keep unresolved names, JSON output
python3 recon/subdomain-enum.py example.com --no-bruteforce --keep-unresolved --json

# Tune concurrency / timeout, write list to a file
python3 recon/subdomain-enum.py example.com -w big.txt -c 100 --timeout 3 -o subs.txt
```

---

### 5. `flag-finder.sh` — recursive CTF flag hunter

Post-exploitation helper that recursively searches a path for likely flag
patterns (`flag{...}`, `picoCTF{...}`, `CTF{...}`, `HTB{...}`, `THM{...}`,
`key{...}`, plus your own regex). Searches **file contents and file names**, with
an optional base64-decode pass. Uses ripgrep when available, else grep.

```bash
# Search current directory
./recon/flag-finder.sh

# Search the whole filesystem
./recon/flag-finder.sh -p /

# Include a base64-decode pass over readable files
./recon/flag-finder.sh -p /home -b

# Custom regex, case-insensitive
./recon/flag-finder.sh -p /var/www -r 'secret\{[^}]+\}' -i
```

| Flag | Meaning |
| --- | --- |
| `-p <path>` | Directory to search (default `.`) |
| `-r <regex>` | Additional custom flag regex (ERE) |
| `-b` | Enable base64-decode pass |
| `-i` | Case-insensitive matching |
| `-h` | Help |

---

## Typical workflow

```bash
# 0. One-time: set up tooling
./install/install-tools.sh
./install/install-python-libs.sh

# 1. Enumerate a target end-to-end
./recon/auto-recon.sh 10.10.10.5

# 2. Drill into a web service the orchestrator found
./recon/web-enum.sh http://10.10.10.5 -d target.htb

# 3. (If a domain is in scope) enumerate subdomains
python3 recon/subdomain-enum.py target.htb -w subdomains.txt

# 4. After getting a foothold, hunt for flags
./recon/flag-finder.sh -p / -b
```

---

## Notes & tips

- All shell scripts use `set -euo pipefail` and print a usage header with
  `-h`/`--help`.
- The Python scripts use `argparse`; run with `-h` for full options.
- Scripts are intentionally tolerant of missing tools — they warn and skip
  rather than crash, so they keep working on minimal target shells.
- Tune nmap timing (`-T4`/`--min-rate`) in `auto-recon.sh` if you trip IDS or
  hit unstable hosts.
