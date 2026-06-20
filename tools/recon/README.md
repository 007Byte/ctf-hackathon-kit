# Server Recon / Service Enumeration Tools

Deep, per-service enumeration tools for the hackathon toolkit. These run
on **Kali/Linux** and are designed to **complement** (not replace) the basic
recon scripts in [`../../scripts/recon/`](../../scripts/recon/):

| Basic script (existing)        | What it does (broad strokes)                |
| ------------------------------ | ------------------------------------------- |
| `auto-recon.sh`                | High-level "kick everything off" wrapper    |
| `web-enum.sh`                  | Web directory / vhost **fuzzing**           |
| `port-scan.py`                 | Quick port discovery                        |
| `subdomain-enum.py`            | Subdomain discovery                         |
| `flag-finder.sh`               | Hunt for CTF flag strings                   |

The tools in **this** directory go *deeper per service* once you know what is
open: protocol-specific banner grabbing, anonymous/null-session checks, share
spidering, fingerprinting, content analysis, and (optionally) credential
testing.

> ## AUTHORIZED TARGETS ONLY
> Every tool here is intrusive to some degree. Only run them against systems you
> **own** or have **explicit written permission** to test. Unauthorized
> scanning, enumeration, or brute forcing is illegal in most jurisdictions.

---

## Tools

### 1. `server-enum.sh` — deep multi-service orchestrator
Quick port discovery (nmap, or falls back to the existing `port-scan.py`), then
runs **deep, per-service** enumeration for each open port, one output file per
service.

**Services covered:** FTP(21), SSH(22), SMTP(25/587), DNS(53),
HTTP/S(80/443/8080), POP3/IMAP(110/143), SMB(139/445), SNMP(161), LDAP(389),
NFS(2049), MySQL(3306), PostgreSQL(5432), Redis(6379), MongoDB(27017),
RDP(3389).

Missing tools are warned about and skipped gracefully. Ends with a summary of
what was found plus suggested follow-ups.

**Prereqs (all optional, skipped if absent):** `nmap`, `dig`, `whatweb`,
`curl`, `smbclient`, `smbmap`, `enum4linux-ng`/`enum4linux`, `snmpwalk`,
`ldapsearch`, `showmount`, `mysql`, `psql`, `redis-cli`, `mongosh`/`mongo`,
`nc`.

```bash
chmod +x server-enum.sh
./server-enum.sh 10.10.10.5                 # results in ./server-enum-10.10.10.5-<ts>/
./server-enum.sh target.htb /tmp/recon-tgt  # custom output dir
```

### 2. `smb-enum.sh` — focused SMB enumeration
Null / guest / **credentialed** sessions; share listing + permission mapping;
recursive share spidering (`-s`); users / groups / password policy via
`enum4linux-ng` (preferred) or `enum4linux`; **RID cycling** fallback when
anonymous enum is blocked; and SMB **vuln checks** (MS17-010 / EternalBlue and
friends via nmap NSE).

**Prereqs:** `enum4linux-ng` or `enum4linux`, `smbclient`, `smbmap`,
`rpcclient`, `nmap`, `nmblookup`.

```bash
chmod +x smb-enum.sh
./smb-enum.sh -t 10.10.10.5                          # null session
./smb-enum.sh -t 10.10.10.5 -u guest -p ''           # guest
./smb-enum.sh -t dc01.corp.local -u jdoe -p 'P@ss' -d CORP -s   # creds + spider
./smb-enum.sh -t 10.10.10.5 -S                       # skip slow RID cycling
```

| Flag | Meaning |
| ---- | ------- |
| `-t` | target (required) |
| `-u` / `-p` | username / password (omit for null session) |
| `-d` | domain / workgroup |
| `-o` | output dir |
| `-s` | spider readable shares (recursive listing) |
| `-S` | skip RID cycling |

### 3. `http-recon.py` — deep HTTP(S) recon (Python)
Single-URL fingerprinting & content analysis (distinct from `web-enum.sh`'s
fuzzing): status + redirect chain, **all** response headers with **missing
security-header** flags, server/tech fingerprints (WordPress, Joomla, Drupal,
Laravel, Django, Tomcat, React/Angular/Vue, …), `<title>` + HTML comments,
links + forms (method/action/inputs), interesting-file probe (`robots.txt`,
`sitemap.xml`, `.git/HEAD`, `.env`, `/admin`, `/api`, backups…), cookies +
flags (HttpOnly/Secure/SameSite), and **CTF flag pattern** detection. Uses
`requests` if present, gracefully falls back to `urllib`.

**Prereqs:** Python 3. `requests` recommended (`pip install requests`) but not
required.

```bash
chmod +x http-recon.py
./http-recon.py http://10.10.10.5/
./http-recon.py https://target.htb/ -k --timeout 15 --json out.json
./http-recon.py http://10.10.10.5:8080/ --proxy http://127.0.0.1:8080   # via Burp
./http-recon.py http://10.10.10.5/ --no-probe                           # skip file probing
```

### 4. `service-brute.sh` — guarded hydra wrapper
Safer THC-Hydra wrapper for `ssh`, `ftp`, `smb`, `rdp`, `mysql`, and
`http-post-form`. Sane defaults (SecLists wordlists with rockyou fallback, low
thread count), **always prints the exact hydra command** before running, strong
authorization/lockout warnings, and a `-n` dry-run mode.

**Prereqs:** `hydra`. Optional: SecLists (`/usr/share/seclists/...`) or
`/usr/share/wordlists/rockyou.txt`.

```bash
chmod +x service-brute.sh
./service-brute.sh -s ssh   -T 10.10.10.5 -u root -W rockyou.txt -S
./service-brute.sh -s ftp   -T 10.10.10.5 -U users.txt -W pass.txt
./service-brute.sh -s smb   -T 10.10.10.5 -u admin -W pass.txt -t 1
./service-brute.sh -s mysql -T 10.10.10.5 -u root  -W pass.txt -n   # dry run
./service-brute.sh -s http-post-form -T 10.10.10.5 -U users.txt -W pass.txt \
     -f "/login:username=^USER^&password=^PASS^:F=incorrect"
```

| Flag | Meaning |
| ---- | ------- |
| `-s` | service (required) |
| `-T` | target (required) |
| `-P` | custom port |
| `-u`/`-U` | single user / userlist |
| `-p`/`-W` | single pass / passlist |
| `-f` | http-post-form spec (`path:params:F=fail-string`) |
| `-t` | threads (default 4) |
| `-S` | stop after first valid pair |
| `-n` | dry run (print command, don't execute) |

> Rate-limit note: brute forcing triggers IDS/lockouts. Keep `-t` low (1–4),
> prefer small targeted lists, and on Windows/AD targets be mindful of account
> lockout thresholds — `-S` (stop on first hit) is your friend.

---

## Server / Box Enumeration Workflow

A practical order of operations for a typical CTF/box:

1. **Discover the surface (basic scripts).**
   ```bash
   ../../scripts/recon/port-scan.py <target>        # or: nmap -Pn -p- <target>
   ../../scripts/recon/subdomain-enum.py <domain>   # if it's a named host
   ```

2. **Deep per-service sweep (this toolkit).**
   ```bash
   ./server-enum.sh <target>
   ```
   Read its **summary + suggested follow-ups** — it points you at the right
   specialized tool for each open service.

3. **Drill into the juicy services.**
   - **Web (80/443/8080):**
     ```bash
     ./http-recon.py http://<target>/            # tech, headers, forms, files
     ../../scripts/recon/web-enum.sh http://<target>/   # then dir/vhost fuzzing
     ```
   - **SMB (139/445):**
     ```bash
     ./smb-enum.sh -t <target>                   # null session first
     ./smb-enum.sh -t <target> -u <u> -p <p> -s  # once you have creds: spider
     ```
   - Other services (FTP/SNMP/LDAP/NFS/DBs): review the `server-enum.sh` output
     files and follow the per-service hints.

4. **Harvest creds & users.** Pull usernames from SMB/LDAP/SNMP/SMTP output and
   any passwords from share contents, `.env`/`.git` leaks, or comments found by
   `http-recon.py`.

5. **Credential testing (only if authorized & in scope).**
   ```bash
   ./service-brute.sh -s ssh -T <target> -U found-users.txt -W passwords.txt -S
   ```

6. **Hunt for flags.**
   ```bash
   ../../scripts/recon/flag-finder.sh <loot-dir>
   ```
   (`http-recon.py` also auto-surfaces `flag{...}`/`HTB{...}`-style strings.)

---

## Quick setup

```bash
chmod +x server-enum.sh smb-enum.sh http-recon.py service-brute.sh

# Kali usually has most tools; if not:
sudo apt install -y nmap dnsutils whatweb smbclient smbmap enum4linux \
    snmp ldap-utils nfs-common hydra netcat-traditional
pipx install enum4linux-ng        # preferred over classic enum4linux
pip install requests              # optional, for http-recon.py
```

Stay within authorized scope. Happy hunting.
