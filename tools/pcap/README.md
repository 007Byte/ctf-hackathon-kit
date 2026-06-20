# PCAP / Wireshark CTF Toolkit

A small set of packet-capture analysis tools for CTF challenges and authorised
lab work. Designed to run on Kali/Linux, but the Python tools are cross-platform
and run on Windows too.

> **Authorised use only.** These tools are for CTF challenges, your own lab
> traffic, or captures you have explicit permission to analyse. Do not use them
> against traffic you are not authorised to inspect.

## Contents

| Tool | Language | Purpose |
|------|----------|---------|
| `pcap-analyzer.py` | Python (scapy) | All-round triage: summary, DNS, HTTP, creds, TCP streams, flag hunting |
| `extract-files.py` | Python (scapy) | Carve files out of HTTP transfers and raw payloads (magic-byte carver) |
| `tshark-helper.sh` | Bash (tshark) | Friendly wrappers over common tshark one-liners |

---

## Prerequisites

### Python tools (`pcap-analyzer.py`, `extract-files.py`)

```bash
pip install scapy
# Kali usually ships it; otherwise:
sudo apt install python3-scapy
```

Python 3.7+ recommended. No other third-party dependencies (stdlib only beyond scapy).

### tshark helper (`tshark-helper.sh`)

```bash
# Debian / Kali
sudo apt install tshark
# Fedora
sudo dnf install wireshark-cli
# macOS
brew install wireshark
```

`tshark-helper.sh` also uses `xxd` and `strings` (from binutils) for the
`strings` subcommand — both are standard on Kali.

Make the shell script executable:

```bash
chmod +x tshark-helper.sh
```

> **Windows note:** The `.sh` helper expects a Bash environment (WSL, Git Bash).
> The two Python tools run natively on Windows once scapy is installed
> (`pip install scapy`); on Windows you may also need
> [Npcap](https://npcap.com/) for live capture, but **reading existing pcap
> files needs no extra driver**.

---

## `pcap-analyzer.py`

Comprehensive triage tool built on scapy's `rdpcap`. Subcommand-based.

```bash
# Protocol/port breakdown, capture timespan, top talkers
python3 pcap-analyzer.py summary capture.pcap

# Every DNS query and response (with record types)
python3 pcap-analyzer.py dns capture.pcap

# HTTP requests (method/host/uri/user-agent) and responses
python3 pcap-analyzer.py http capture.pcap

# Cleartext credential hunt: HTTP Basic, FTP, Telnet, POST forms, mail AUTH
python3 pcap-analyzer.py creds capture.pcap

# List all TCP streams (index, endpoints, payload size)
python3 pcap-analyzer.py streams capture.pcap --list

# Dump a specific stream as ASCII (colour-coded by direction)
python3 pcap-analyzer.py streams capture.pcap --index 3

# Dump a stream by endpoint substring, as a hexdump
python3 pcap-analyzer.py streams capture.pcap --filter 10.0.0.5:21 --hexdump

# Hunt for flags (flag{}, picoCTF{}, CTF{}, HTB{}) + a base64-decode pass
python3 pcap-analyzer.py flags capture.pcap

# Add your own flag format
python3 pcap-analyzer.py flags capture.pcap --regex 'MYCTF\{[^}]+\}'
```

Output is colour-coded on a TTY and degrades to plain text when piped.

---

## `extract-files.py`

Carve files out of a capture two ways:

1. **HTTP-aware** — reassembles TCP streams, parses HTTP responses, handles
   chunked transfer-encoding and gzip/deflate, and names files from the request
   URI or content-type.
2. **Magic-byte carver** — scans raw payloads for file signatures
   (JPG, PNG, GIF, PDF, ZIP, GZIP, ELF) and carves them out.

```bash
# Both passes, output to ./loot
python3 extract-files.py capture.pcap -o loot/

# Only the HTTP reassembly pass
python3 extract-files.py capture.pcap -o loot/ --http-only

# Only the generic carver
python3 extract-files.py capture.pcap -o loot/ --carve-only
```

Each saved file is reported with its size and a short SHA-256 prefix.

---

## `tshark-helper.sh`

The pcap is always the **first** argument, the subcommand is **second**.

```bash
# Protocol hierarchy — best first look
./tshark-helper.sh capture.pcap proto

# HTTP requests + responses
./tshark-helper.sh capture.pcap http

# DNS queries + answers
./tshark-helper.sh capture.pcap dns

# Credential grep across HTTP/FTP/Telnet/mail/POST
./tshark-helper.sh capture.pcap creds

# Export HTTP objects (files) to ./loot
./tshark-helper.sh capture.pcap objects ./loot http

# Follow TCP stream number 3 as ASCII (or hex / raw)
./tshark-helper.sh capture.pcap follow 3 ascii

# Endpoint + conversation stats
./tshark-helper.sh capture.pcap ips

# Printable strings (min length 6) from payloads
./tshark-helper.sh capture.pcap strings 6
```

Run with no subcommand (or `-h`) to print the usage header.

---

## Typical PCAP challenge workflow

1. **Get the lay of the land.**
   ```bash
   python3 pcap-analyzer.py summary capture.pcap
   ./tshark-helper.sh capture.pcap proto
   ```
   Note the protocols present, busiest ports, and the top talkers. This tells
   you whether you're dealing with web, DNS, file transfer, mail, etc.

2. **Chase the obvious protocols.**
   - Web challenge? `pcap-analyzer.py http` and `pcap-analyzer.py creds`.
   - DNS exfil? `pcap-analyzer.py dns` (look for long/odd subdomains or TXT data).
   - File transfer (FTP/HTTP/TFTP/SMB)? jump to step 4.

3. **Look for low-hanging fruit.**
   ```bash
   python3 pcap-analyzer.py creds capture.pcap     # cleartext logins
   python3 pcap-analyzer.py flags capture.pcap     # flags incl. base64 pass
   ./tshark-helper.sh capture.pcap strings 6        # raw printable strings
   ```

4. **Pull out transferred files.**
   ```bash
   python3 extract-files.py capture.pcap -o loot/
   # or, via tshark's built-in exporter:
   ./tshark-helper.sh capture.pcap objects ./loot http
   ```
   Then inspect the carved files (`file loot/*`, `exiftool`, `binwalk`,
   `strings`, `unzip`, image steg tools, etc.).

5. **Manually read suspicious conversations.**
   ```bash
   python3 pcap-analyzer.py streams capture.pcap --list
   python3 pcap-analyzer.py streams capture.pcap --index <n>
   # or with tshark:
   ./tshark-helper.sh capture.pcap follow <n> ascii
   ```
   Reassembling the right TCP stream often reveals the flag directly, a
   command-and-control channel, or another file to carve.

6. **Iterate.** Carved files frequently contain *another* layer (a zip inside a
   PDF, base64 inside an HTTP body, a flag inside an image). Re-run the carver /
   flag hunter on extracted artefacts.

### Handy companion commands

```bash
file loot/*                 # identify carved files
binwalk -e loot/foo.bin     # recursively extract embedded data
exiftool loot/*.jpg         # image metadata (flags hide here a lot)
strings -n 8 loot/foo.bin   # quick string sweep
zsteg / steghide / stegseek # image/audio steganography
```
