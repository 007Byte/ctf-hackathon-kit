# Credential & Backdoor Audit Tools

Part of the **Home-Network Security Audit** suite. These tools help a defender
audit **their own** Windows 11 / Linux home network for two things:

1. **Default / weak credentials** still accepted by local services
   (`weak-creds-check.py`).
2. **Backdoor / RAT / suspicious-service indicators** on local hosts
   (`backdoor-scan.py`).

They are cross-platform Python 3 (tested on Python 3.14, no third-party
libraries required for the core features).

---

## ⚠️ AUTHORIZATION & LEGAL WARNING

> **AUTHORIZED NETWORKS ONLY.** Testing default credentials against devices you
> do not own — or scanning hosts you do not own — **may be illegal** under
> computer-misuse / unauthorized-access laws. Use these tools **only** on
> equipment you own or are **explicitly authorized in writing** to test. You are
> solely responsible for how you use them.

Every script prints this warning at startup and repeats it in its file header.

---

## Files

| File | Purpose |
|------|---------|
| `default-creds.json` | Curated data file of common default/weak credential pairs, by service and router vendor. |
| `weak-creds-check.py` | Safely tests default/weak creds against discovered services (HTTP, SSH, FTP, Telnet, MySQL). |
| `backdoor-scan.py` | Scans for known RAT/backdoor ports, exposed remote-admin services, and banner/port mismatches. |
| `README-creds-backdoor.md` | This document. |

---

## Rate limiting & anti-lockout guidance (important)

`weak-creds-check.py` is built **defensively** to avoid locking out your own
accounts or tripping intrusion defenses:

- `--delay <seconds>` — pause between **every** attempt (default **1.0s**).
  Increase it (e.g. `--delay 3`) for devices with aggressive lockout policies.
- `--max-attempts <n>` — **hard cap on total attempts per host** (default
  **20**). Once reached, that host is skipped.
- **Stop-on-first-success** per `(host, service)` — once a default cred works,
  the tool stops testing that service.
- `--dry-run` — list exactly what *would* be tried, **connecting to nothing**.
- Sequential by default (no aggressive parallelism against a single host).

> Tip: run `--dry-run` first to review the attempt plan, then run for real with a
> conservative `--delay` and a low `--max-attempts`.

`backdoor-scan.py` only performs lightweight TCP connect checks (and one
optional banner grab per open port). Tune `--workers` and `--timeout` to be
gentle on low-power IoT devices.

---

## Optional dependencies

The core works with the **standard library only**. Some service checks need an
optional library; if missing, the tool **skips that service with a note** (and
records an `info` finding) rather than failing.

| Feature | Library | Install |
|---------|---------|---------|
| Nicer HTTP handling | `requests` | `pip install requests` (else urllib fallback is used) |
| SSH credential check | `paramiko` | `pip install paramiko` |
| MySQL credential check | `mysql-connector-python` **or** `pymysql` | `pip install mysql-connector-python` *or* `pip install pymysql` |

FTP and Telnet use the standard library (Telnet via a minimal raw-socket
implementation, since `telnetlib` was removed in Python 3.13).

---

## Shared JSON schema

Both tools accept `--json <outfile>` and emit the suite's shared schema:

```json
{
  "tool": "<tool-name>",
  "target": "<scanned>",
  "hosts": [
    {"ip": "", "mac": "", "vendor": "", "hostname": "", "state": "up"}
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

Both tools also accept `--from-json <port-service-scan.json>` to operate on
already-discovered open services from an earlier scan in the suite, so you can
chain: *discover ports → check creds → hunt backdoors* without re-scanning.

---

## Usage examples

### weak-creds-check.py

```bash
# Test a router web UI and its Telnet, conservatively, dry-run first
python weak-creds-check.py 192.168.1.1:80 192.168.1.1:23:telnet --dry-run

# Real run with a safe delay and tight per-host cap
python weak-creds-check.py 192.168.1.1:80 --delay 3 --max-attempts 10 --json creds.json

# Operate on services discovered by an earlier port scan
python weak-creds-check.py --from-json port-service-scan.json --json creds.json

# Use your own credential list
python weak-creds-check.py 192.168.1.50:22:ssh --creds my-creds.json
```

Target syntax: `ip:port[:service]`. If `service` is omitted it is inferred from
well-known ports (21→ftp, 22→ssh, 23→telnet, 80/443/8080→http, 3306→mysql).

A successful default-credential login produces a **critical** finding with
remediation. If nothing succeeds, an `info` finding records that.

### backdoor-scan.py

```bash
# Scan one host over the curated suspicious-port list, with banner grabbing
python backdoor-scan.py 192.168.1.10 --grab-banners --json backdoor.json

# Sweep a whole /24
python backdoor-scan.py 192.168.1.0/24 --json backdoor.json

# Add extra ports to the curated list
python backdoor-scan.py 192.168.1.10 --ports 8081,9000

# Analyze open ports already found by another scan (no re-scan unless --grab-banners)
python backdoor-scan.py --from-json port-service-scan.json --grab-banners --json backdoor.json
```

#### What backdoor-scan looks for

- **Known RAT/backdoor/trojan ports**, e.g.:
  - `31337` Back Orifice (critical), `12345/12346` NetBus, `27374` SubSeven/Sub7,
    `4444/4445` Metasploit/Meterpreter default handler, `1337` "leet" backdoor,
    `54320/54321` Back Orifice 2000, `16660` Stacheldraht, `27665` Trinoo.
- **Exposed remote-admin / cleartext services**: Telnet (23), RDP (3389),
  Radmin (4899).
- **ADB (5555)** — Android Debug Bridge, an *unauthenticated* remote shell when open.
- **VNC (5900/5901)** — flagged high; unauthenticated VNC = full GUI control.
- **IRC ports (6667–7000)** — classic botnet C2.
- **Open SOCKS (1080)**, **Tor ORPort / trojan (9001)**, **X11 (6000)**.
- **Banner vs. port mismatch** and **shell-like banners** (e.g. a `/bin/sh`,
  `Microsoft Windows`, or `meterpreter` banner = strong bind-shell indicator).

> **These are INDICATORS to investigate, not proof of compromise.** Legitimate
> software can reuse any port, and attackers can relocate services. Each finding
> includes how to identify the listening process
> (`netstat -anob` on Windows; `ss -tlnp` / `lsof -i` on Linux).

---

## Suggested workflow

1. Run your port/service discovery tool → `port-service-scan.json`.
2. `python backdoor-scan.py --from-json port-service-scan.json --grab-banners --json backdoor.json`
3. `python weak-creds-check.py --from-json port-service-scan.json --delay 2 --json creds.json`
4. Review `critical`/`high` findings; remediate (change passwords, disable
   Telnet/ADB/VNC, restrict WAN management, update firmware), then re-scan.

---

## Data sources (consulted June 2026)

- cirt.net default password database — <https://cirt.net/passwords/>
- NETGEAR default credentials KB — <https://kb.netgear.com/1148/>
- Default-password background — <https://en.wikipedia.org/wiki/Default_password>
- Back Orifice / NetBus ports — <https://en.wikipedia.org/wiki/NetBus>,
  <https://www.irchelp.org/security/netbus>
- Bifrost trojan — <https://en.wikipedia.org/wiki/Bifrost_(Trojan_horse)>
- Gary Kessler "Bad" TCP/UDP ports — <https://www.garykessler.net/library/bad_ports.html>
