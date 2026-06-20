# Resources & Platforms — Curated Toolbox

> Bookmark these. The grouping mirrors how you'll actually use them:
> **practice → reference/payloads → decode/crack → OSINT → wordlists → learning/video.**
> For authorized/educational use only.

---

## 1. Practice Platforms

| Platform | URL | What it's for |
|---|---|---|
| picoCTF | https://picoctf.org | **Start here.** Free, beginner-friendly CTF by CMU; great General Skills / Web / Forensics / Crypto / RE tracks and a persistent practice gym. |
| Hack The Box (HTB) | https://www.hackthebox.com | Realistic pentesting machines + a Challenges section by category. Free tier + VIP. |
| HTB Academy | https://academy.hackthebox.com | Structured, guided modules and skill paths (web, AD, etc.); some free, most via cubes/subscription. |
| TryHackMe | https://tryhackme.com | Beginner-friendly guided rooms and learning paths, in-browser (no VPN/VM needed). |
| OverTheWire | https://overthewire.org/wargames/ | **Bandit** = the best free Linux/SSH/CLI fundamentals; then Natas (web), Leviathan, Krypton. |
| CryptoHack | https://cryptohack.org | The best gamified way to learn CTF cryptography, beginner → advanced. |
| pwn.college | https://pwn.college | Free, university-grade structured curriculum for binary exploitation, RE, and more. |
| VulnHub | https://www.vulnhub.com | Downloadable vulnerable VMs to attack offline in your own lab. |
| PortSwigger Web Security Academy | https://portswigger.net/web-security | Free, authoritative web-vuln labs from the makers of Burp Suite. Do the apprentice labs. |
| CTFtime | https://ctftime.org | Calendar of live CTF events, team rankings, and links to write-ups. |
| Root-Me | https://www.root-me.org | Huge catalog of challenges across every category; good for breadth. |
| pwnable.kr / pwnable.tw | https://pwnable.kr / https://pwnable.tw | Classic standalone pwn challenge ladders. |
| Crackmes.one | https://crackmes.one | Endless reverse-engineering puzzles, filterable by difficulty. |
| flAWS / CloudGoat | http://flaws.cloud / https://github.com/RhinoSecurityLabs/cloudgoat | Hands-on AWS misconfiguration / cloud-attack practice. |

---

## 2. Reference Sites & Payload Cheatsheets

| Resource | URL | What it's for |
|---|---|---|
| HackTricks | https://book.hacktricks.wiki | The pentest/CTF encyclopedia — methodology and techniques for nearly every service & vuln. |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings | Copy-paste payloads and bypasses for every web attack class. |
| GTFOBins | https://gtfobins.github.io | Abuse legit **Unix/Linux** binaries for shell/privesc/file-read. |
| LOLBAS | https://lolbas-project.github.io | The **Windows** equivalent — Living-Off-the-Land binaries/scripts. |
| OWASP | https://owasp.org | Top 10, testing guide, and cheat-sheet series — the web-security reference. |
| OWASP Cheat Sheet Series | https://cheatsheetseries.owasp.org | Focused, practical cheat sheets per topic. |
| revshells.com | https://www.revshells.com | Generate reverse shells in any language/format with the right IP/port. |
| HackTricks Cloud | https://cloud.hacktricks.wiki | Cloud + AD attack methodology companion to HackTricks. |
| PEASS / linPEAS-winPEAS | https://github.com/peass-ng/PEASS-ng | Automated Linux/Windows privilege-escalation enumeration scripts. |

---

## 3. Decode / Crack / Compute Tools

| Tool | URL | What it's for |
|---|---|---|
| CyberChef | https://gchq.github.io/CyberChef/ | "Cyber Swiss-army knife" — chain encode/decode/crypto/data operations. |
| CrackStation | https://crackstation.net | Free lookup of common unsalted hashes (MD5/SHA1/etc.). |
| dcode.fr | https://www.dcode.fr/en | Identifies and solves dozens of classical ciphers and puzzles. |
| factordb | http://factordb.com | Look up factorizations of (weak) RSA moduli `n`. |
| hashcat | https://hashcat.net/hashcat/ | GPU password/hash cracking (offline). |
| John the Ripper | https://www.openwall.com/john/ | Versatile hash cracker; `*2john` helpers for zip/pdf/etc. |
| jwt.io / jwt_tool | https://jwt.io / https://github.com/ticarpi/jwt_tool | Decode and attack JSON Web Tokens. |
| RsaCtfTool | https://github.com/RsaCtfTool/RsaCtfTool | Automated attacks against weak RSA keys. |
| aperisolve | https://www.aperisolve.com | Runs multiple steganography tools on an uploaded image at once. |

---

## 4. OSINT Tools & Sites

| Tool | URL | What it's for |
|---|---|---|
| Shodan | https://www.shodan.io | "Search engine for internet-connected devices" — exposed services/hosts. |
| crt.sh | https://crt.sh | Certificate Transparency search → discover subdomains. |
| VirusTotal | https://www.virustotal.com | File/URL/hash reputation and multi-engine analysis. |
| HaveIBeenPwned | https://haveibeenpwned.com | Check emails/passwords against known breaches. |
| Wayback Machine | https://web.archive.org | Historical snapshots of web pages (find removed content). |
| theHarvester | https://github.com/laramies/theHarvester | CLI collection of emails, subdomains, hosts from public sources (built into Kali). |
| Maltego | https://www.maltego.com | Visual link-analysis / entity-pivoting for investigations. |
| SpiderFoot | https://github.com/smicallef/spiderfoot | Automated OSINT reconnaissance framework. |
| Sherlock | https://github.com/sherlock-project/sherlock | Hunt a username across hundreds of social platforms. |
| Google Dorks (GHDB) | https://www.exploit-db.com/google-hacking-database | Advanced search-operator queries for exposed data. |
| DNSDumpster | https://dnsdumpster.com | DNS recon and subdomain mapping. |

---

## 5. Wordlists & Fuzzing

| Resource | URL | What it's for |
|---|---|---|
| SecLists | https://github.com/danielmiessler/SecLists | The collection — usernames, passwords, web dirs, fuzzing payloads, subdomains. (Ships with Kali at `/usr/share/seclists`.) |
| rockyou.txt | (in SecLists / Kali `/usr/share/wordlists`) | The classic password-cracking wordlist. |
| ffuf | https://github.com/ffuf/ffuf | Fast web fuzzer (dirs, params, vhosts). |
| gobuster / dirsearch | https://github.com/OJ/gobuster / https://github.com/maurosoria/dirsearch | Directory & file brute-forcing. |

---

## 6. Core Offensive Tools (have these installed)

- **Kali Linux** — https://www.kali.org (distro with most tools preinstalled).
- **Burp Suite Community** — https://portswigger.net/burp/communitydownload (web proxy).
- **Wireshark** — https://www.wireshark.org (packet analysis).
- **Ghidra** — https://ghidra-sre.org (free decompiler/RE).
- **nmap** — https://nmap.org (port/service scanning).
- **pwntools** — https://docs.pwntools.com (Python exploit-dev framework).
- **gdb + pwndbg/GEF** — https://github.com/pwndbg/pwndbg (debugging).
- **binwalk / exiftool / steghide / zsteg** — forensics & stego staples.

---

## 7. Learning — YouTube & Courses

| Channel / Resource | URL | Best for |
|---|---|---|
| IppSec | https://www.youtube.com/c/ippsec | Detailed HTB machine walkthroughs; learn methodology by watching. |
| John Hammond | https://www.youtube.com/c/JohnHammond010 | CTF write-ups, malware analysis, practical hacking, beginner-friendly. |
| LiveOverflow | https://www.youtube.com/c/LiveOverflow | Deep, concept-first explanations (binary exploitation, web, RE). |
| PwnFunction | https://www.youtube.com/c/PwnFunction | Crisp animated explainers for web-security concepts (XSS, prototype pollution). |
| Nightmare (binary exploitation) | https://guyinatuxedo.github.io | Free guided pwn/RE course with worked CTF examples. |
| CTF write-ups (CTFtime) | https://ctftime.org/writeups | Read how others solved challenges — the fastest way to improve. |

---

## 8. Suggested "first session" bookmarks bar

picoCTF · CyberChef · HackTricks · PayloadsAllTheThings · GTFOBins · revshells.com ·
CrackStation · dcode.fr · CTFtime · PortSwigger Academy

> See also: `learning-roadmap.md` (what to learn and when),
> `../vulns/common-vulnerabilities.md` (vuln quick-reference),
> `note-taking-and-workflow.md` (how to organize your work).
