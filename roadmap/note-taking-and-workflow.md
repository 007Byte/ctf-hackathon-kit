# Note-Taking & CTF Workflow

> Good notes win CTFs. They stop you repeating work, let teammates pick up where you left off,
> and become your personal cheatsheet for the next event. Set this up **before** your first
> competition, not during.

---

## 1. Pick a note-taking tool

Any of these work — choose one and stick with it:

| Tool | Why pick it | URL |
|---|---|---|
| **Obsidian** | Markdown files on disk, fast linking between notes, plugins, free, works offline. The most popular choice in the CTF/pentest community. | https://obsidian.md |
| **CherryTree** | Hierarchical tree of rich-text/code nodes in one file; preinstalled on Kali; great for structured per-machine notes. | https://www.giuspen.net/cherrytree/ |
| **Joplin** | Markdown notebooks with optional end-to-end-encrypted sync across devices; good if you want phone access. | https://joplinapp.org |

**Recommendation for a beginner:** **Obsidian**. It's plain Markdown (portable forever),
links challenges together, and you can paste screenshots directly.

### Setup tips
- One **vault/notebook per event** (e.g., `picoCTF-2026/`), plus one permanent **Cheatsheet** vault you grow over time.
- Inside the event vault, **one note per challenge**, named `Category - ChallengeName`.
- Keep a running **`_scratch`** note for commands you'll reuse.
- Save screenshots/output into an `attachments/` folder.
- **Never paste credentials/flags from authorized labs into anything synced publicly.** Keep notes local or in a private repo.

---

## 2. Per-challenge note template

Copy this for every challenge. Filling in each section forces you to actually do recon and
makes write-ups trivial afterward.

```markdown
# [Category] Challenge Name — (points)

## Meta
- Platform / Event:
- Category:
- Points / Difficulty:
- Status: [ ] not started  [ ] in progress  [ ] SOLVED  [ ] stuck/parked
- Owner (team): 
- Time started:

## Description (verbatim)
> (paste the exact challenge text — it usually hints at the technique)

## Provided files / targets
- URL / IP:Port:
- Files (name + `file` output + hash):

## Recon (what I observed)
- 

## Hypotheses (what it might be)
- 

## Attempts log (timestamped — keep even failures!)
- [HH:MM] tried X → result
- [HH:MM] tried Y → result

## Commands / payloads used
```bash
# paste exact commands so they're reproducible
```

## Key findings / leaks
- 

## Solution (the working path)
1. 
2. 

## FLAG
`picoCTF{...}`   <-- submitted exactly as shown

## Lessons / reusable trick
- (add the trick to the permanent Cheatsheet vault)
```

---

## 3. Personal CTF workflow: Recon → Identify → Exploit → Document

A repeatable loop. Run it on every challenge.

### Phase 1 — Recon (look before you touch)
- Read the description and **title** carefully; note the flag format.
- Inventory everything provided: URLs, files (`file`, `strings`, `binwalk`, `checksec`, view source).
- Note the obvious entry points (inputs, params, ports, functions) in your challenge note.
- **Do the cheap checks first** (e.g., `strings binary | grep -i flag`, `robots.txt`, EXIF).

### Phase 2 — Identify (what is this?)
- Map observations to a vulnerability/technique (use `../vulns/common-vulnerabilities.md`).
- Form 1-3 hypotheses and rank them by likelihood and effort.
- Confirm with a low-risk probe (`'`, `{{7*7}}`, `%p`, `../`, increment an ID).

### Phase 3 — Exploit (drive it home)
- Build the smallest payload that proves the bug, then escalate to the flag.
- Script anything repetitive (Python/pwntools/curl) — and paste the script into your note.
- **Time-box:** if ~30-45 min pass with no progress, record your state and park it. Switch challenges; come back with fresh eyes (or hand it to a teammate).

### Phase 4 — Document
- Record the exact working steps, the payload, and the flag in the note.
- Submit the flag **exactly** as produced (watch case, braces, trailing newlines).
- Extract the reusable trick into your permanent Cheatsheet vault.

---

## 4. Team coordination & role-splitting

Even small teams should agree on this before the clock starts.

### Shared infrastructure
- **One shared board** for challenge status (a pinned spreadsheet, a Discord/Slack channel, or a shared CTFd scoreboard). Columns: *Challenge | Category | Points | Status | Owner | Notes/Flag*.
- **One comms channel** with a thread per challenge for findings.
- A shared place for files/wordlists if needed.

### Claiming work (avoid duplicated effort)
- You **claim** a challenge by marking yourself as Owner on the board.
- Mark challenges `in progress`, `SOLVED`, or `stuck/parked` so nobody re-does solved work.
- If you park something, write your current state so the next person resumes, not restarts.

### Splitting by strength (a common 3-5 person split)
- **Web** specialist (most common category, often most points).
- **Crypto + Misc/Scripting** person.
- **RE + Pwn** person (these pair well).
- **Forensics + Stego + OSINT** person.
- A **floater/coordinator** who keeps the board updated, helps wherever stuck, and double-checks flag submissions.

### Rules of engagement
- Don't hoard a hard challenge — share findings early; fresh eyes solve stuck challenges.
- Announce every solve in the channel so the board stays accurate.
- Near the end, swarm the "almost done" challenges together.
- Stay in scope and follow the event rules (no attacking infra/other teams, no flag sharing between teams).

---

## 5. Build a permanent cheatsheet (the long game)

Keep a second, evergreen vault that survives across events. Suggested structure:

```
Cheatsheet/
  web/        (SQLi, XSS, SSTI payloads that worked, filter bypasses)
  pwn/        (pwntools template, ret2win/ret2libc skeletons)
  crypto/     (RSA scripts, CyberChef recipes)
  forensics/  (binwalk/zsteg/volatility command lists)
  recon/      (nmap, ffuf, enumeration one-liners)
  _flag-format-gotchas.md
```

Every time a trick works, drop it here. Within a few events this becomes your most valuable
asset and dramatically speeds you up.

---

## 6. Pre-event checklist

- [ ] Note vault created for this event (+ permanent Cheatsheet vault exists).
- [ ] Per-challenge template ready to copy.
- [ ] Team board + comms channel set up; roles assigned.
- [ ] Tools open/installed: Burp, terminal, Ghidra, Wireshark, CyberChef, pwntools.
- [ ] VPN/lab connectivity tested; flag format confirmed.

> See also: `learning-roadmap.md` (study plan + in-competition strategy),
> `resources-and-platforms.md` (tools), `../vulns/common-vulnerabilities.md` (vuln reference).
