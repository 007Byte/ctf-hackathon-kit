# CTF Learning Roadmap — Category by Category

> A beginner-friendly roadmap for your first CTF / hackathon (Hack The Box / picoCTF style).
> Work through categories in roughly the order listed. Pick ONE category to go deep on first
> (Web is the most beginner-friendly and the most common in hackathons), then broaden.

---

## How to use this document

1. Read the **phased study plan** at the bottom first — it tells you *when* to learn each category.
2. For each category below you get: **What it is → Concepts (in order) → Tools → Practice → Patterns.**
3. Do the practice rooms/challenges. Reading without solving does not work for CTFs.
4. Keep notes (see `note-taking-and-workflow.md`) from day one.

---

## 1. Web Exploitation

**What it is:** Attacking web applications — HTTP, browsers, servers, databases, and the code that
glues them together. The single most common and beginner-friendly CTF category.

**Core concepts (in order):**
1. HTTP request/response model, methods (GET/POST/PUT), status codes, headers, cookies.
2. Browser dev tools (Network tab, Storage, Console) and viewing page source.
3. URL structure, query parameters, form submission, redirects.
4. Client vs. server: why hiding things in JS/HTML never works.
5. Sessions, cookies, and authentication (then JWTs).
6. Core vulnerability classes: SQL Injection, XSS, SSTI, LFI/RFI, command injection, SSRF, IDOR, file upload (see `../vulns/common-vulnerabilities.md`).

**Key tools:**
- **Burp Suite (Community)** — intercepting proxy; the #1 web tool. Repeater + Intruder.
- **curl** — scripted requests; essential for non-browser endpoints.
- **ffuf / gobuster / dirsearch** — directory and parameter fuzzing.
- **Browser DevTools** — built into Chrome/Firefox.
- **sqlmap** — automated SQLi (use only when manual fails / when allowed).

**Practice resources:**
- [picoCTF](https://picoctf.org) — "Web Exploitation" track (start here).
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — free, the gold standard for web; do the apprentice-level labs.
- [TryHackMe](https://tryhackme.com) — rooms: *OWASP Top 10*, *Web Fundamentals*, *Junior Penetration Tester* path.
- [HTB Academy](https://academy.hackthebox.com) — *Web Requests*, *Introduction to Web Applications*.
- [Root-Me](https://www.root-me.org) — Web-Client / Web-Server challenges.

**Common challenge patterns:**
- Flag hidden in HTML comment, JS file, `robots.txt`, or `/sitemap.xml`.
- Cookie/parameter tampering (`admin=false` → `admin=true`).
- SQLi login bypass (`' OR '1'='1`) or UNION-based data extraction.
- SSTI in a "name"/template field leading to RCE.
- LFI reading `/etc/passwd` or `flag.txt`; LFI → log poisoning → RCE.
- IDOR: change `?id=1` to `?id=2` to read another user's data.

---

## 2. Reverse Engineering (RE / rev)

**What it is:** Figuring out what a compiled program does without source code, usually to recover
a hidden password/flag or understand a check routine.

**Core concepts (in order):**
1. Compilation pipeline: source → assembly → machine code.
2. x86/x64 assembly basics: registers, stack, calling conventions, common instructions.
3. Static analysis (reading disassembly/decompilation) vs. dynamic analysis (running + debugging).
4. Identifying strings, comparisons, loops, and the "win" branch.
5. Common obfuscation: XOR loops, base64, simple encryption of the flag.
6. Patching binaries and bypassing checks.

**Key tools:**
- **Ghidra** — free NSA decompiler; reads C-like pseudocode. Best starting point.
- **IDA Free / Binary Ninja (free tier)** — alternatives to Ghidra.
- **radare2 / Cutter** — open-source RE framework (Cutter = GUI).
- **gdb + GEF/pwndbg** — dynamic analysis/debugging.
- **strings, file, ltrace, strace, xxd** — quick triage on Linux.

**Practice resources:**
- [picoCTF](https://picoctf.org) — "Reverse Engineering" track (excellent ramp).
- [pwn.college](https://pwn.college) — *Reverse Engineering* module (free, structured).
- [Crackmes.one](https://crackmes.one) — endless reversing puzzles by difficulty.
- [Root-Me](https://www.root-me.org) — Cracking section.
- [Microcorruption](https://microcorruption.com) — embedded/assembly RE+pwn game.

**Common challenge patterns:**
- `strings binary` reveals the flag directly (always try first).
- Decompile, read `if (input == "secret")` and read the literal.
- Recover an XOR/transform applied to the flag and reverse it.
- Patch a `jnz`/`jz` to force the "you win" branch.
- .NET/Java apps: decompile with **dnSpy** / **jd-gui** for near-source output.

---

## 3. Cryptography

**What it is:** Breaking or exploiting cryptographic schemes — classical ciphers, weak modern
crypto, bad key/IV usage, and number-theory puzzles.

**Core concepts (in order):**
1. Encoding vs. encryption vs. hashing (base64/hex are NOT encryption).
2. Classical ciphers: Caesar/ROT, Vigenère, substitution, XOR.
3. Symmetric crypto: AES modes (ECB pitfalls, CBC bit-flipping), stream ciphers.
4. Hashing: MD5/SHA, cracking, length-extension.
5. Modular arithmetic and RSA: key generation, small-`e`, common modulus, factoring weak `n`.
6. Diffie-Hellman, ECC basics (later).

**Key tools:**
- **CyberChef** — decode/transform pipelines; the crypto Swiss-army knife.
- **dcode.fr** — identifies and solves dozens of classical ciphers.
- **CrackStation** / **hashcat** / **john** — hash cracking.
- **factordb.com** — look up factors of weak RSA moduli.
- **Python + pycryptodome / SageMath** — scripting real attacks.
- **RsaCtfTool** — automated RSA attacks.

**Practice resources:**
- [CryptoHack](https://cryptohack.org) — the best place to learn CTF crypto, gamified and progressive.
- [picoCTF](https://picoctf.org) — "Cryptography" track.
- [Cryptopals](https://cryptopals.com) — classic challenge set for hands-on crypto.
- [Root-Me](https://www.root-me.org) — Cryptanalysis section.

**Common challenge patterns:**
- "Decode this" → run through CyberChef / dcode (base64 → hex → ROT13 chains).
- ECB penguin / identical ciphertext blocks reveal structure.
- RSA with tiny `e` (e=3) and no padding → cube-root the ciphertext.
- RSA with a factorable/known `n` → factordb → compute `d`.
- XOR with a repeating key → frequency analysis / known-plaintext.

---

## 4. Forensics

**What it is:** Recovering hidden or deleted information from files, disk images, memory dumps, and
packet captures.

**Core concepts (in order):**
1. File formats and **magic bytes** (file signatures); fixing corrupted headers.
2. Metadata (EXIF, document properties).
3. File carving — extracting embedded files.
4. Disk and filesystem basics; deleted-file recovery.
5. Memory forensics (RAM dumps).
6. Network forensics — reading PCAPs (overlaps with Networking).

**Key tools:**
- **file, xxd, hexedit / 010 Editor** — identify and fix file types.
- **binwalk / foremost** — find and extract embedded files.
- **exiftool** — metadata extraction.
- **Wireshark / tshark** — PCAP analysis.
- **Volatility 3** — memory dump analysis.
- **Autopsy / Sleuth Kit** — disk image investigation.
- **strings, grep, zsteg** — quick content hunting.

**Practice resources:**
- [picoCTF](https://picoctf.org) — "Forensics" track (great beginner set).
- [TryHackMe](https://tryhackme.com) — rooms: *Forensics*, *Disk Analysis & Autopsy*, *Volatility*.
- [HTB](https://www.hackthebox.com) — Forensics challenges.

**Common challenge patterns:**
- Wrong/missing magic bytes — fix the header to open the file.
- `binwalk -e` extracts a hidden ZIP/image inside another file.
- Flag in EXIF metadata or a document's properties.
- PCAP contains an HTTP file transfer or plaintext credentials.
- Memory dump → find a process, command history, or password with Volatility.

---

## 5. OSINT (Open-Source Intelligence)

**What it is:** Finding information about a person, organization, or location using only public
sources. Often the "fun, no-VPN-needed" category.

**Core concepts (in order):**
1. Search-engine dorking (Google/Bing operators: `site:`, `filetype:`, `intitle:`).
2. Username/email enumeration across platforms.
3. Image OSINT: reverse image search + geolocation (signs, plates, sun position, architecture).
4. Domain/infrastructure recon: WHOIS, DNS, subdomains, certificates.
5. Social-media and metadata analysis.
6. Historical data: archived pages and cached content.

**Key tools/sites:**
- **Google dorks** + **Shodan** (internet-connected devices).
- **crt.sh** (certificate transparency → subdomains), **WHOIS**, **dnsdumpster**.
- **theHarvester**, **Maltego**, **SpiderFoot** (automated collection/pivoting).
- **Wayback Machine** (web.archive.org), **Google reverse image / Yandex**.
- **exiftool** (image metadata), **HaveIBeenPwned** (breach data), **Sherlock** (username search).

**Practice resources:**
- [TryHackMe](https://tryhackme.com) — rooms: *OhSINT*, *Google Dorking*, *Searchlight - IMINT*, *Sakura Room*.
- [picoCTF](https://picoctf.org) — occasional OSINT/general-skills challenges.
- [TraceLabs / OSINT CTF events](https://www.tracelabs.org) — real-world style OSINT CTFs.

**Common challenge patterns:**
- Given a username → find their accounts → flag in a bio/post.
- Given a photo → reverse-image + landmark/sign → identify the location.
- Given a domain → crt.sh/Wayback reveals a hidden subdomain or old page.
- EXIF GPS coordinates in a provided image.

---

## 6. Binary Exploitation / Pwn

**What it is:** Exploiting memory-corruption bugs in compiled programs to hijack execution and run
your own code or read the flag. The hardest "core" category — save it for after RE basics.

**Core concepts (in order):**
1. Process memory layout: stack, heap, registers, the instruction pointer.
2. The stack and function calls (return addresses).
3. **Stack buffer overflow** — overwriting the return address.
4. Modern mitigations: stack canaries, NX/DEP, ASLR, PIE — and what each blocks.
5. **ret2win**, **ret2libc**, ROP (return-oriented programming).
6. Format-string bugs; then heap exploitation (use-after-free, tcache).

**Key tools:**
- **pwntools** (Python) — the exploitation framework; learn this early.
- **gdb + pwndbg / GEF** — debugging exploits.
- **checksec** — see which mitigations are enabled.
- **ROPgadget / ropper** — find ROP gadgets.
- **Ghidra** — to understand the binary first (overlaps with RE).

**Practice resources:**
- [pwn.college](https://pwn.college) — the single best free, structured pwn curriculum.
- [picoCTF](https://picoctf.org) — "Binary Exploitation" track (gentle intro).
- [pwnable.kr](https://pwnable.kr) and [pwnable.tw](https://pwnable.tw) — classic pwn ladders.
- [Nightmare](https://guyinatuxedo.github.io) — free guided binary-exploitation course.
- [ROP Emporium](https://ropemporium.com) — learn ROP step by step.

**Common challenge patterns:**
- `gets()`/`scanf("%s")` overflow → overwrite return address to a `win()` function (ret2win).
- Leak a libc address via a format string, then ret2libc to `system("/bin/sh")`.
- Format string `%p %p %p` to leak stack/canary, `%n` to write.
- "It's just a buffer overflow with a canary" → leak canary first, then overflow.

---

## 7. Networking

**What it is:** Understanding and exploiting network protocols and traffic; reading packet captures.
Heavy overlap with Forensics (PCAP) and Web.

**Core concepts (in order):**
1. The TCP/IP model and the OSI layers.
2. Core protocols: Ethernet, IP, TCP/UDP, DNS, HTTP(S), FTP, ICMP.
3. Reading a PCAP: following streams, filtering, extracting files.
4. Scanning and enumeration (nmap).
5. Common service misconfigurations and plaintext credentials.

**Key tools:**
- **Wireshark / tshark** — packet analysis (filters like `http`, `tcp.port == 21`).
- **nmap** — port scanning and service detection.
- **netcat (nc)** — manual connections, banner grabbing, listeners.
- **tcpdump** — capture on the CLI.

**Practice resources:**
- [TryHackMe](https://tryhackme.com) — rooms: *Network Fundamentals*, *Wireshark 101*, *Nmap*.
- [picoCTF](https://picoctf.org) — networking/forensics PCAP challenges.
- [OverTheWire: Bandit](https://overthewire.org/wargames/bandit/) — SSH/networking fundamentals.

**Common challenge patterns:**
- PCAP with a "Follow TCP Stream" revealing the flag or credentials.
- File exfiltrated over HTTP/FTP inside a capture — export and open it.
- DNS-tunneled or ICMP-tunneled data to reassemble.

---

## 8. Steganography

**What it is:** Finding data hidden *inside* other files (images, audio, etc.). Common in beginner
events; almost a sub-genre of Forensics.

**Core concepts (in order):**
1. LSB (least-significant-bit) hiding in images.
2. Hidden data in file metadata / appended after EOF.
3. Audio spectrograms (visual messages in sound).
4. Color-channel and bit-plane tricks.
5. Password-protected stego (steghide).

**Key tools:**
- **zsteg** (PNG/BMP LSB), **stegsolve** (bit planes/channels).
- **steghide** (JPEG/WAV with passphrase), **exiftool** (metadata).
- **binwalk** (appended files), **Audacity / Sonic Visualiser** (spectrograms).
- **strings, xxd** (quick checks), **stegseek** (brute-force steghide passphrases).

**Practice resources:**
- [picoCTF](https://picoctf.org) — forensics/stego challenges.
- [Root-Me](https://www.root-me.org) — Steganography section.
- [aperisolve.com](https://www.aperisolve.com) — runs many stego tools at once on an upload.

**Common challenge patterns:**
- Run the image through zsteg/stegsolve to reveal LSB text.
- `steghide extract` with a password found elsewhere in the challenge.
- Audio file → open spectrogram in Audacity → read the flag.
- Data appended after the image's end-of-file marker (binwalk/strings).

---

## 9. Malware Analysis

**What it is:** Analyzing malicious software to understand behavior and extract indicators (and
sometimes a flag). Combines RE, forensics, and sandboxing. More advanced.

**Core concepts (in order):**
1. Safe lab setup: isolated VM, snapshots, no network (or controlled network).
2. Static analysis: PE/ELF structure, imports, strings, packing detection.
3. Dynamic analysis: running in a sandbox, observing files/registry/network.
4. Unpacking and deobfuscation.
5. Behavioral indicators (IOCs): C2 domains, dropped files, persistence.

**Key tools:**
- **PE-bear / PEstudio / Detect It Easy (DIE)** — static PE triage and packer detection.
- **Ghidra / x64dbg** — static + dynamic RE.
- **Cuckoo / any.run / VirusTotal** — sandboxes and reputation.
- **Wireshark, Process Monitor, Regshot** — behavioral monitoring.
- **FLOSS** — extract obfuscated strings.

**Practice resources:**
- [TryHackMe](https://tryhackme.com) — rooms: *Intro to Malware Analysis*, *MalDoc*, *Basic Malware RE*.
- [Practical Malware Analysis (book) labs](https://practicalmalwareanalysis.com) — the standard course.
- [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net) — real PCAP exercises.

**Common challenge patterns:**
- Extract a hardcoded C2 URL or key from a sample's strings/decompilation.
- Deobfuscate a script (PowerShell/JS) to reveal the payload and flag.
- Analyze a malicious document's macro to find the dropped URL.

---

## 10. Cloud / Active Directory

**What it is:** Exploiting misconfigured cloud (AWS/Azure/GCP) services and on-prem Windows Active
Directory. Increasingly common in hackathons and very relevant to real jobs.

**Core concepts (in order):**
*Cloud:*
1. IAM (users, roles, policies) and how over-permissive policies leak access.
2. Public storage buckets (S3) and exposed metadata endpoints (SSRF → cloud creds).
3. Enumerating cloud resources with leaked keys.

*Active Directory:*
1. AD fundamentals: domains, users, groups, Kerberos, NTLM.
2. Enumeration (BloodHound), Kerberoasting, AS-REP roasting.
3. Lateral movement: pass-the-hash, credential reuse.

**Key tools:**
- Cloud: **awscli**, **ScoutSuite**, **pacu**, **enumerate-iam**.
- AD: **BloodHound/SharpHound**, **impacket** suite, **CrackMapExec/NetExec**, **Rubeus**, **mimikatz**.

**Practice resources:**
- [TryHackMe](https://tryhackme.com) — paths: *Active Directory*, rooms *Attacktive Directory*, *Cloud Security*.
- [HTB Academy](https://academy.hackthebox.com) — *Active Directory Enumeration & Attacks*.
- [flAWS / flAWS2](http://flaws.cloud) — guided AWS misconfiguration challenges.
- [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) — vulnerable AWS-by-design scenarios.

**Common challenge patterns:**
- Public S3 bucket listing → download a file with the flag.
- Leaked AWS keys → `aws s3 ls` / enumerate to find the secret.
- AD: AS-REP roast a user → crack the hash → log in.
- Kerberoast a service account → crack → escalate.

---

## 11. Misc / Scripting / Programming

**What it is:** Everything that doesn't fit a box — automation puzzles, jails (sandbox escapes),
esoteric encodings, "general skills," and timing/volume problems that *require* a script.

**Core concepts (in order):**
1. Comfortable Python scripting (requests, pwntools, string handling, loops).
2. Linux command line fluency (pipes, grep, awk, find, bash).
3. Automating interaction with a remote service (sockets / pwntools `remote`).
4. Python/regex jail escapes and filter bypasses.
5. Solving math/logic puzzles fast under time pressure.

**Key tools:**
- **Python 3** + **requests**, **pwntools**, **re**.
- **bash** and core CLI tools.
- **CyberChef** for quick transforms.

**Practice resources:**
- [picoCTF](https://picoctf.org) — "General Skills" track (do ALL of these first as a beginner).
- [OverTheWire: Bandit](https://overthewire.org/wargames/bandit/) — best Linux CLI training, level by level.
- [HackerRank / Codewars](https://www.hackerrank.com) — keep scripting sharp.

**Common challenge patterns:**
- A server asks 1000 math questions in 30 seconds → script the answers with pwntools.
- Python jail: `eval` with a blocklist → bypass via `__import__`/`getattr`/encodings.
- Decode a multi-layer encoding chain (base64 → hex → ROT → ...).
- "Use the terminal" tasks that drill grep/find/cut/sort/uniq.

---

# Phased Study Plan

### Weeks 1-2 — Foundations (Beginner)
- Set up your environment: **Kali Linux** (or a Linux VM), Python 3, Burp Community, Wireshark, Ghidra.
- Do **all of picoCTF "General Skills"** and start **OverTheWire: Bandit** (levels 0-20). This builds Linux + CLI fluency, which everything else depends on.
- Do picoCTF **Web** and **Forensics** beginner challenges.
- Read `../vulns/common-vulnerabilities.md` and learn to recognize the top 5 (SQLi, XSS, LFI, IDOR, command injection).
- Start your note system today (`note-taking-and-workflow.md`).

### Weeks 3-6 — Breadth + One Depth (Intermediate)
- **Web depth:** PortSwigger Web Security Academy apprentice labs (SQLi, XSS, auth, path traversal).
- **Crypto:** CryptoHack Introduction + Encoding + XOR + intro RSA.
- **RE:** picoCTF reversing + a few Crackmes; learn Ghidra.
- **Pwn (intro):** pwn.college Memory Errors module + picoCTF binary exploitation.
- **Forensics/Stego:** TryHackMe Wireshark 101, a few aperisolve/zsteg challenges.
- Pick **one category to go deep** (Web is the safest, highest-ROI choice).
- Do at least **one real CTF** on [CTFtime](https://ctftime.org) — pick a "beginner/easy" rated event.

### Ongoing — Maintain + Specialize
- Compete in beginner-friendly CTFs roughly monthly (track via CTFtime).
- Read **write-ups** for challenges you couldn't solve — this is where most growth happens.
- Watch **IppSec** (HTB box walkthroughs) and **LiveOverflow** (concepts) regularly.
- Deepen your chosen specialty (e.g., HTB Academy Web path, pwn.college full track).
- Keep your notes/cheatsheet growing (see workflow doc).

---

# During the Competition — Strategy

**Before it starts**
- Confirm scope/rules, flag format (e.g., `picoCTF{...}`), and the scoring model.
- Have tools open and ready: Burp, terminal, Ghidra, CyberChef, your notes.
- Connect to the VPN/lab if required and verify connectivity.

**Picking challenges**
- Sort by **points ascending** (or by solve count descending) and grab the easy wins first to build momentum and confidence.
- Read EVERY challenge title/description early so your brain works on hard ones in the background.
- Match challenges to your strengths; on a team, claim categories you own (see role-splitting in the workflow doc).

**Working a challenge**
- **Recon first, always.** Look at everything provided before touching tools.
- Run the obvious quick checks (e.g., `strings`, `file`, view source, `binwalk`) before deep work.
- Time-box: if stuck ~30-45 min with no progress, note your state and switch challenges. Come back later.
- Re-read the description and title — they almost always hint at the technique.

**Flags and submission**
- Submit the flag **exactly** as given (case, braces, underscores). Trim whitespace.
- If a flag "doesn't work," check for trailing newlines or wrong wrapper format.
- Log every flag and the method in your notes immediately.

**Teamwork & finish**
- Communicate solves and dead-ends in your team channel so no one duplicates effort.
- Don't hoard a challenge you're stuck on — share findings and let fresh eyes try.
- Near the end, do one pass for "almost done" challenges; submit partial credit where allowed.
- After the event: write up what you solved AND what you didn't, then read others' write-ups.

---

## Quick links index
- picoCTF — https://picoctf.org
- Hack The Box — https://www.hackthebox.com  |  HTB Academy — https://academy.hackthebox.com
- TryHackMe — https://tryhackme.com
- OverTheWire — https://overthewire.org/wargames/
- CryptoHack — https://cryptohack.org
- pwn.college — https://pwn.college
- PortSwigger Web Security Academy — https://portswigger.net/web-security
- Root-Me — https://www.root-me.org
- CTFtime (event calendar) — https://ctftime.org

> See also: `resources-and-platforms.md` (full toolbox), `../vulns/common-vulnerabilities.md`,
> and `note-taking-and-workflow.md`.
