# Pre-Competition Checklist (Night Before & Day Of)

Use this to make sure you can focus on hacking, not fixing your setup, when the
clock starts. Two phases: **Night Before** (prep) and **Day Of** (final checks).

---

## NIGHT BEFORE

### Environment
- [ ] Kali VM fully built and tested (see `kali-setup-checklist.md`)
- [ ] System updated; no pending reboot
- [ ] **VM snapshot taken** named `ctf-ready` so you can roll back if you break something
- [ ] Enough disk space free (`df -h`) and RAM allocated to the VM

### Tools verified (each launches / prints a version)
- [ ] `nmap`, `ffuf`/`gobuster`/`feroxbuster`, `sqlmap`, `nikto`, `whatweb`
- [ ] Burp Suite opens; proxy listener on 127.0.0.1:8080
- [ ] Ghidra launches (first-run unpack already done)
- [ ] `john`, `hashcat`, `hydra` run
- [ ] `pwntools` imports; `gdb` (pwndbg/gef) works for pwn
- [ ] `vol` (volatility3) and `binwalk`/`exiftool`/`steghide` for forensics
- [ ] impacket (`impacket-secretsdump`, `impacket-psexec`) on PATH
- [ ] PrivEsc scripts staged locally: linpeas.sh, pspy64, winPEASx64.exe, PowerUp.ps1, Seatbelt.exe

### Wordlists & offline resources
- [ ] SecLists installed (`/usr/share/seclists`)
- [ ] `rockyou.txt` decompressed
- [ ] Everything downloaded so you're not dependent on internet mid-comp
- [ ] **Cheatsheets saved OFFLINE** (PDF/markdown): GTFOBins, LOLBAS, reverse-shell
      cheatsheet, nmap flags, common ports, SQLi/XSS/SSTI payloads, pwn/rev refs

### Exploit templates ready
- [ ] pwntools template (`from pwn import *`, `context`, `p = process()/remote()`)
- [ ] Reverse shell one-liners (bash, python, php, nc, powershell) in one note
- [ ] msfvenom payload snippets (msi, exe, elf, php) in a note
- [ ] Common reverse-shell listener: `rlwrap nc -lvnp 4444`

### Notes & comms
- [ ] Notes tool (CherryTree/Obsidian) open with a clean template per category
- [ ] Flag/loot tracking note ready (challenge → flag → points → who solved)
- [ ] Team comms set up: Discord/Slack channel joined, voice channel tested
- [ ] CTF platform account created; logged into CTFd / HTB and 2FA working
- [ ] Team registered; you're on the roster

### Logistics
- [ ] Laptop charged + charger packed; power outlet identified
- [ ] Stable internet confirmed; **backup connection** (phone hotspot) ready
- [ ] VPN pack (`.ovpn`) downloaded and tested connecting
- [ ] Good sleep > one more tool. Stop and rest.

---

## DAY OF

### Final verification (15 min before start)
- [ ] Boot the VM from the `ctf-ready` snapshot
- [ ] Internet up; hotspot backup on standby
- [ ] VPN connects, `tun0` up, can ping a target/gateway
- [ ] Notes tool open; team channel open; scoreboard/CTFd open

### Read the rules (do NOT skip)
- [ ] Read the **scoring & rules** page fully
- [ ] Note **allowed/forbidden** actions (no DoS, no attacking infra/scoreboard,
      no sharing flags between teams, scope/IP ranges)
- [ ] Note **start and end times** (and any freeze period)
- [ ] Confirm the **flag submission format** and where to submit
- [ ] Know the **flag format / regex** (e.g. `picoCTF{...}`, `flag{...}`, `HTB{...}`)
      so you recognize flags instantly and can `grep -r` for them

### Team roles & strategy
- [ ] Assign categories to people (web / pwn / rev / crypto / forensics / osint)
- [ ] Agree on how to claim a challenge so two people don't duplicate work
- [ ] Agree on when to ask for help / hand off a stuck challenge

### Time management
- [ ] Start with **quick wins** / low-point challenges to build momentum and points
- [ ] Time-box hard challenges (e.g. 45 min, then move on / hand off)
- [ ] Read ALL challenge titles/descriptions early; some hint at the technique
- [ ] Keep a "stuck" list; revisit with fresh eyes later
- [ ] Plan breaks (eat, water, stretch) — fatigue costs more than a short break

### Quick-win reminders
- [ ] Always check: source code / comments, robots.txt, EXIF/strings on files,
      default creds, obvious encodings (base64/hex/rot13), and the description hints
- [ ] When you find a flag: submit it immediately, then log it in the team note

---

## One-liner mindset
Enumerate thoroughly, exploit the easiest path first, take notes as you go,
submit flags the moment you find them, and rest when your brain stalls.
