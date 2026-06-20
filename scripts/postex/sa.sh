#!/usr/bin/env bash
#
# sa.sh - portable Linux situational-awareness / privesc triage
# -----------------------------------------------------------------------------
# A dependency-free, single-file enumerator to DROP ON A FOOTHOLD and run when
# you can't (or don't want to) fetch linpeas. Fast, quiet, and self-contained -
# it surfaces the things that most often lead to escalation:
#   user context & sudo rights · SUID/SGID & capabilities · cron & timers ·
#   writable paths in PATH/service files · creds in common files · network &
#   listening ports · containers/kernel · interesting recent files.
# Output is plain text; pipe to a file and exfil it.
# -----------------------------------------------------------------------------
# AUTHORIZED USE ONLY: run on hosts you are permitted to assess.
# -----------------------------------------------------------------------------
#
# USAGE:   ./sa.sh            (or:  ./sa.sh | tee /tmp/sa.txt)
# DEPENDENCIES: none beyond a POSIX shell + coreutils (works on minimal boxes).
# -----------------------------------------------------------------------------

set -u
H(){ printf '\n\033[1;36m===== %s =====\033[0m\n' "$*"; }
q(){ "$@" 2>/dev/null; }

H "HOST / KERNEL"
q uname -a; q cat /etc/os-release | grep -E 'PRETTY|VERSION='; q hostname
[ -f /.dockerenv ] && echo "[!] inside a Docker container"
q grep -qa container=lxc /proc/1/environ && echo "[!] inside an LXC container"

H "CURRENT USER"
q id; q whoami; echo "groups: $(q groups)"

H "SUDO RIGHTS  (key escalation check)"
q sudo -n -l || echo "(no passwordless sudo, or sudo needs a password)"

H "SUID / SGID BINARIES (compare against gtfobins)"
q find / -perm -4000 -type f -not -path '/proc/*' 2>/dev/null
echo "-- SGID --"; q find / -perm -2000 -type f -not -path '/proc/*' 2>/dev/null | head -40

H "FILE CAPABILITIES"
q getcap -r / 2>/dev/null | grep -v 'No such'

H "CRON / TIMERS"
q ls -la /etc/cron* 2>/dev/null; q cat /etc/crontab 2>/dev/null
q crontab -l 2>/dev/null; q systemctl list-timers --all 2>/dev/null | head -20

H "WRITABLE in \$PATH (PATH-hijack potential)"
echo "$PATH" | tr ':' '\n' | while read -r d; do [ -w "$d" ] && echo "[!] writable: $d"; done

H "WORLD-WRITABLE service/config files"
q find /etc/systemd /lib/systemd -writable -type f 2>/dev/null
q find / -path /proc -prune -o -perm -0002 -type f -name '*.service' -print 2>/dev/null | head -20

H "CREDS in common files"
q grep -rinE 'password|passwd|secret|api[_-]?key|token' /etc /var/www /opt /home 2>/dev/null \
  | grep -vE '\.(png|jpg|gz|zip|so)' | head -30
for f in ~/.bash_history ~/.ssh/id_* /var/www/html/wp-config.php /var/www/html/config.php; do
  [ -r "$f" ] && echo "[*] readable: $f"
done
q ls -la ~/.ssh 2>/dev/null

H "NETWORK"
q ip -br a 2>/dev/null || q ifconfig -a
echo "-- listening --"; q ss -tulpn 2>/dev/null || q netstat -tulpn 2>/dev/null
echo "-- arp/neighbors --"; q ip neigh 2>/dev/null | head

H "INTERESTING RECENT FILES (last 7d, in user-writable areas)"
q find /home /tmp /var/tmp /dev/shm /opt -type f -mtime -7 2>/dev/null | head -30

H "MOUNTS / NFS"
q mount 2>/dev/null | grep -iE 'nfs|cifs|nosuid|tmpfs' | head
q cat /etc/exports 2>/dev/null

printf '\n\033[1;32m[+]\033[0m sa.sh complete. Cross-ref SUID/caps/sudo with GTFOBins; check writable PATH/service files.\n'
