# CTF / Hackathon Starter Templates

Reusable starting points for common challenge categories (Hack The Box /
picoCTF style). Copy the relevant template at the start of a challenge, rename
it, and fill in the marked sections. Each file is self-contained and commented.

## Templates at a glance

| File | Category | When to use it |
|------|----------|----------------|
| `pwn-template.py` | Binary exploitation (pwn) | Buffer overflows, ROP, ret2libc, format strings. Handles LOCAL/REMOTE/GDB modes. |
| `web-exploit-template.py` | Web | HTTP challenges: login flows, CSRF, SQLi, SSTI, fuzzing. Burp proxy toggle built in. |
| `crypto-template.py` | Cryptography | RSA attacks, XOR, encodings, modular math. |
| `scapy-network-template.py` | Network / traffic | Live sniffing, pcap analysis, packet crafting, custom protocols. |
| `forensics-helpers.py` | Forensics / stego | File triage: magic detection, entropy, strings, hexdump, carving, EXIF. |

---

## `pwn-template.py`
pwntools exploit scaffold. Copy to `exploit.py`.

- **Run modes** (chosen by command-line args):
  - `./exploit.py` — local process against the binary
  - `./exploit.py GDB` — local + auto-attach GDB (edit `GDBSCRIPT` for breakpoints)
  - `./exploit.py REMOTE host port` — connect to the remote service
- Sets `context.binary`, loads the ELF (and optional libc/ld), and gives you
  short I/O wrappers (`sla`, `sl`, `ru`, `rl`, `leak_u64`, …).
- Includes commented scaffolding for offsets (`cyclic`), the pwntools `ROP()`
  object, ret2libc, and a `flat()` payload.
- **Reminder:** run `checksec ./binary` first (RELRO / Canary / NX / PIE) — the
  protections decide your strategy.
- Edit `context.terminal` to match how you want GDB windows to open
  (tmux on Linux/WSL, Windows Terminal, etc.).

## `web-exploit-template.py`
`requests` + BeautifulSoup web scaffold.

- One `Session` carries cookies across requests.
- **Burp toggle:** set `USE_BURP = True` (or run with `BURP=1`) to route through
  `127.0.0.1:8080` with TLS verification off.
- Helpers: `get`/`post`/`soup`, CSRF token extraction (`get_csrf`), and a
  CSRF-aware `login()`.
- Attack loops included: `fuzz_paths`, `test_sqli`, `test_ssti`,
  `bruteforce_field`. Wire up your flow in `main()`.

## `crypto-template.py`
pycryptodome / sympy / gmpy2 crypto toolkit.

- **RSA:** decrypt with `p,q` or `d`, small-`e` exact root, common-modulus
  attack, Fermat factoring, local factoring (sympy), factordb lookup, and a
  Wiener pointer.
- **XOR:** single/multi-byte, single-byte brute force, known-plaintext key
  recovery.
- **Encodings & math:** base64/hex/int/bytes conversions, `modinv`, integer
  `iroot`.
- Uses `gmpy2` when present but degrades gracefully to pure Python / sympy.
- Paste your `n, e, c` (or ciphertext) into `main()` and run.

## `scapy-network-template.py`
Scapy networking scaffold. CLI with three modes:

- `sudo python scapy-network-template.py sniff [iface] [bpf-filter]` — live capture
- `python scapy-network-template.py pcap capture.pcap` — offline analysis
- `sudo python scapy-network-template.py send` — craft/send examples

Parsers pull out **DNS** queries/answers, **HTTP** requests/responses, and
plaintext **credentials/flags**. There is a stub for decoding custom protocols.
Live sniffing and raw send need root/admin (and Npcap on Windows); reading a
pcap does not.

## `forensics-helpers.py`
Standalone forensics CLI (argparse subcommands):

- `magic FILE` — identify by magic bytes
- `entropy FILE` — Shannon entropy (spot encryption/packing)
- `strings FILE [-n MIN]` — ASCII + UTF-16LE strings
- `hexdump FILE [-o OFF] [-l N]` — hex view
- `carve FILE [-d OUTDIR]` — extract embedded files by signature
- `exif FILE` — image metadata (needs Pillow)

The core features need no external tools; for deep work pair it with `binwalk`,
`exiftool`, and `foremost`.

---

## Installation

```bash
# everything (Python 3.8+)
pip install pwntools requests beautifulsoup4 pycryptodome sympy scapy pillow

# optional speedups for crypto
pip install gmpy2          # fast big-int roots/inverses
pip install owiener        # tested Wiener's-attack implementation
```

Per-template minimums:

| Template | Required pip packages |
|----------|----------------------|
| `pwn-template.py` | `pwntools` (plus GDB + a pwndbg/GEF setup recommended) |
| `web-exploit-template.py` | `requests`, `beautifulsoup4` |
| `crypto-template.py` | `pycryptodome`, `sympy` (optional: `gmpy2`, `requests`) |
| `scapy-network-template.py` | `scapy` (Npcap on Windows for live capture) |
| `forensics-helpers.py` | none for core; `pillow` for `exif` |

## Handy companion tools (not Python)
`checksec`, `gdb` + `pwndbg`/`GEF`, `one_gadget`, `ROPgadget` (pwn) ·
`ffuf`, `gobuster`, `sqlmap`, Burp Suite (web) ·
`RsaCtfTool`, SageMath (crypto) ·
Wireshark, `tshark` (network) ·
`binwalk`, `exiftool`, `foremost`, `steghide`, `zsteg` (forensics).
