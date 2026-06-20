# Nmap Cheatsheet

> For authorized CTF / educational use only. Scan only hosts you have permission to test.

Placeholder: `$IP` = target. Many scan types need `sudo` (raw packets). Save output with `-oA`.

---

## 1. Recommended CTF Workflow (fast → full → targeted)

```bash
# STEP 1 — fast: find open TCP ports across the whole range quickly
nmap -p- --min-rate 10000 -T4 $IP -oN scans/allports.txt
# or with rustscan: rustscan -a $IP --ulimit 5000

# STEP 2 — full: deep scan only the discovered ports (versions + default scripts)
ports=$(grep -oP '^\d+(?=/tcp)' scans/allports.txt | paste -sd, -)
nmap -p$ports -sC -sV -oA scans/targeted $IP

# STEP 3 — UDP top ports (slow; do in parallel/background)
sudo nmap -sU --top-ports 100 $IP -oN scans/udp.txt

# STEP 4 — targeted scripts based on what you found (vuln / service-specific NSE)
nmap -p445 --script "smb-enum-*,smb-vuln-*" $IP
```

---

## 2. Host Discovery (find live hosts)

```bash
nmap -sn 10.10.10.0/24                  # ping sweep, no port scan
nmap -sn -PE 10.10.10.0/24              # ICMP echo
nmap -PS22,80,443 10.10.10.0/24         # TCP SYN ping to ports
nmap -PA80 10.10.10.0/24               # TCP ACK ping
nmap -PU53 10.10.10.0/24               # UDP ping
nmap -Pn $IP                            # SKIP discovery, treat as up (use when host blocks ping)
nmap -n $IP                             # no DNS resolution (faster)
nmap -sL 10.10.10.0/24                  # list targets only, no packets
```

---

## 3. Port Scanning Types

```bash
nmap -sS $IP        # SYN "stealth" scan (default w/ root; half-open)
nmap -sT $IP        # full TCP connect (default w/o root)
nmap -sU $IP        # UDP scan (slow)
nmap -sA $IP        # ACK scan (map firewall rules)
nmap -sN $IP        # NULL scan (no flags)
nmap -sF $IP        # FIN scan
nmap -sX $IP        # Xmas scan (FIN+PSH+URG)
# Port selection
nmap -p 80,443 $IP            # specific ports
nmap -p 1-1000 $IP            # range
nmap -p- $IP                  # all 65535 ports
nmap --top-ports 1000 $IP     # most common N
nmap -F $IP                   # fast (top 100)
```

---

## 4. Service / Version / OS Detection

```bash
nmap -sV $IP                       # service & version detection
nmap -sV --version-intensity 9 $IP # most aggressive probing
nmap -O $IP                         # OS detection (needs root)
nmap -A $IP                         # aggressive: -sV -O --script=default --traceroute
nmap -sC $IP                        # default NSE scripts (equiv --script=default)
nmap -sC -sV -O $IP                 # common combined enumeration
```

---

## 5. NSE Scripts

### Categories (`--script=<category>`)
`auth, broadcast, brute, default, discovery, dos, exploit, external, fuzzer, intrusive, malware, safe, version, vuln`

```bash
nmap --script vuln $IP                          # check known vulnerabilities
nmap --script "default,safe" $IP
nmap --script="not intrusive" $IP
nmap --script-help "smb-*"                       # read what a script does
ls /usr/share/nmap/scripts/ | grep <service>     # find scripts
nmap --script-updatedb
```

### Useful service-specific scripts
```bash
# SMB
nmap -p445 --script "smb-enum-shares,smb-enum-users,smb-os-discovery" $IP
nmap -p445 --script "smb-vuln-ms17-010,smb-vuln-ms08-067" $IP    # EternalBlue etc.
# HTTP
nmap -p80,443 --script "http-enum,http-title,http-headers,http-methods" $IP
nmap -p80 --script "http-shellshock" $IP
nmap -p80 --script "http-wordpress-enum" $IP
# FTP
nmap -p21 --script "ftp-anon,ftp-vsftpd-backdoor,ftp-syst" $IP
# SSH
nmap -p22 --script "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods" $IP
# DNS / SMTP / SNMP / MySQL
nmap -p53 --script "dns-zone-transfer" --script-args dns-zone-transfer.domain=$DOMAIN $IP
nmap -p25 --script "smtp-enum-users,smtp-commands" $IP
nmap -sU -p161 --script "snmp-info,snmp-brute" $IP
nmap -p3306 --script "mysql-info,mysql-empty-password,mysql-enum" $IP
# Pass args
nmap --script <name> --script-args key=val,key2=val2 $IP
```

---

## 6. Timing & Performance

```bash
nmap -T0 ... # paranoid (IDS evasion)   -T1 sneaky   -T2 polite
nmap -T3 ... # normal (default)
nmap -T4 ... # aggressive (good for CTF labs)
nmap -T5 ... # insane (fast, may miss/flood)
nmap --min-rate 5000 $IP        # at least N packets/sec
nmap --max-rate 100 $IP         # cap rate
nmap --min-parallelism 100 $IP  # parallel probes
nmap --host-timeout 5m $IP
nmap --max-retries 1 $IP        # fewer retransmits = faster (may miss ports)
```

---

## 7. Output Formats

```bash
nmap -oN out.txt $IP       # normal human-readable
nmap -oG out.gnmap $IP     # greppable
nmap -oX out.xml $IP       # XML
nmap -oA scans/base $IP    # ALL three at once (base.nmap/.gnmap/.xml)
nmap -v $IP                # verbose (-vv more)
nmap --reason $IP          # why a port is in its state
nmap --open $IP            # show only open ports
nmap -d $IP                # debug
# Convert XML to HTML report:
xsltproc out.xml -o report.html
```

---

## 8. Firewall / IDS Evasion (basics)

```bash
nmap -f $IP                       # fragment packets
nmap --mtu 16 $IP                 # custom fragment size (multiple of 8)
nmap -D RND:10 $IP                # decoy scan (10 random decoys)
nmap -D 10.0.0.1,10.0.0.2,ME $IP  # specific decoys
nmap -S <spoofed_ip> $IP          # spoof source IP (needs -e + careful)
nmap --source-port 53 $IP         # scan from a trusted port (DNS)
nmap --data-length 50 $IP         # append random data to packets
nmap --spoof-mac 0 $IP            # random MAC
nmap -sI <zombie>:port $IP        # idle/zombie scan (very stealthy)
nmap --scan-delay 1s $IP          # slow down to avoid rate-based IDS
```

---

## 9. Handy Combos / Cheat Lines

```bash
# Full TCP enumeration in one go (after you know ports are open)
sudo nmap -p- -sS -sV -sC -O -T4 -oA scans/full $IP
# Vuln sweep on web + smb
nmap -p80,443,445 --script "vuln" $IP
# Scan a list of hosts from a file
nmap -iL hosts.txt -oA scans/multi
# Resume an interrupted scan
nmap --resume scans/full.gnmap
# Quick "what's this box" first contact
nmap -Pn -sCV -p- --min-rate 5000 $IP -oA scans/initial
```

See also: `ctf-master-cheatsheet.md` (section 1-2 for follow-up service enumeration).
