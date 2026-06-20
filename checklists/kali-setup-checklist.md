# Kali Setup Checklist

Prepare your Kali Linux box BEFORE the competition. Work top to bottom. Each
item has a verification command so you know it actually worked.

> Tip: Run as your normal user and `sudo` when needed. Don't do everything as root.

---

## 1. Update the system

- [ ] Update package lists and upgrade everything
  ```bash
  sudo apt update && sudo apt full-upgrade -y
  ```
- [ ] Reboot if the kernel was upgraded
  ```bash
  sudo reboot
  ```
- [ ] Verify version
  ```bash
  cat /etc/os-release        # confirm Kali rolling
  uname -a                   # confirm kernel
  ```

## 2. Install the toolkit

- [ ] Run the project install script (installs the core tools used in this pack)
  ```bash
  chmod +x ../scripts/install/install-tools.sh
  ../scripts/install/install-tools.sh
  ```
- [ ] Install/confirm the "big" extras Kali ships in metapackages
  ```bash
  sudo apt install -y kali-linux-large    # large toolset (optional, big download)
  sudo apt install -y seclists gobuster feroxbuster ffuf nmap burpsuite ghidra \
                      gdb pwntools python3-pip pipx jq tmux zsh git curl wget \
                      net-tools dnsutils whatweb nikto sqlmap hydra john hashcat \
                      crackmapexec smbclient enum4linux-ng exiftool steghide \
                      binwalk foremost
  ```
- [ ] Install pipx tools that are nicer outside apt
  ```bash
  pipx ensurepath
  pipx install impacket           # GetUserSPNs, secretsdump, psexec, etc.
  pip3 install volatility3        # memory forensics (vol3)
  ```
- [ ] Verify the headline tools launch / print versions
  ```bash
  nmap --version
  ffuf -V
  gobuster version
  feroxbuster --version
  sqlmap --version
  john --list=build-info | head
  hashcat --version
  vol --help | head            # volatility3
  python3 -c "import pwn; print(pwn.__version__)"   # pwntools
  ```

## 3. Wordlists & SecLists

- [ ] Install/extract SecLists
  ```bash
  sudo apt install -y seclists       # installs to /usr/share/seclists
  ls /usr/share/seclists
  ```
- [ ] Decompress rockyou (the default password list)
  ```bash
  sudo gzip -d /usr/share/wordlists/rockyou.txt.gz 2>/dev/null
  ls -lh /usr/share/wordlists/rockyou.txt
  ```
- [ ] Note your go-to wordlist paths (copy into your notes)
  - Dirs: `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt`
  - Files: `/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt`
  - Common: `/usr/share/seclists/Discovery/Web-Content/common.txt`
  - VHosts/subdomains: `/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt`
  - Passwords: `/usr/share/wordlists/rockyou.txt`

## 4. Shell: tmux + zsh

- [ ] Make zsh your default shell (Kali default already, confirm)
  ```bash
  echo $SHELL                 # expect /usr/bin/zsh
  chsh -s $(which zsh)        # if not
  ```
- [ ] Create a minimal tmux config for split panes + mouse
  ```bash
  cat > ~/.tmux.conf <<'EOF'
  set -g mouse on
  setw -g mode-keys vi
  set -g history-limit 100000
  bind | split-window -h
  bind - split-window -v
  EOF
  tmux kill-server 2>/dev/null; tmux        # reload; verify it starts
  ```
- [ ] Learn the 3 panes layout you'll use: one for the target shell, one for
      enumeration, one for notes.

## 5. Aliases & helpers

- [ ] Add competition aliases to `~/.zshrc`
  ```bash
  cat >> ~/.zshrc <<'EOF'

  # --- CTF aliases ---
  alias ll='ls -alh'
  alias ports='ss -tulpn'
  alias myip='ip -4 addr show tun0 2>/dev/null | grep -oP "(?<=inet )[0-9.]+"'
  alias serve='python3 -m http.server 8000'
  alias nmapq='nmap -sC -sV -oN nmap_quick.txt'
  alias nmapfull='nmap -p- --min-rate 5000 -oN nmap_full.txt'
  # quick TTY upgrade reminder: python3 -c "import pty;pty.spawn('/bin/bash')"
  EOF
  source ~/.zshrc
  myip                          # verify alias works (after VPN is up)
  ```

## 6. Notes tool

- [ ] Install a notes app (pick ONE and stick with it)
  ```bash
  sudo apt install -y cherrytree        # tree-based, offline, great for CTF
  # OR Obsidian (download AppImage from obsidian.md, chmod +x, run)
  ```
- [ ] Create a template note: Recon / Foothold / PrivEsc / Loot / Flags
- [ ] Verify it opens and saves offline (no network needed during comp).

## 7. VPN connectivity

- [ ] Place your `.ovpn` file (HTB/picoCTF/CTFd pack) in `~/`
- [ ] Connect
  ```bash
  sudo openvpn ~/lab.ovpn        # leave running in its own tmux pane
  ```
- [ ] Verify the tunnel interface and that you can reach the target network
  ```bash
  ip addr show tun0              # tun0 should have an IP
  ping -c2 10.10.10.1           # ping the gateway / a known box
  ```

## 8. Verify GUI / heavy tools launch

- [ ] Burp Suite opens and proxy listener is on 127.0.0.1:8080
  ```bash
  burpsuite &                   # then check Proxy > Options listener
  ```
- [ ] Ghidra launches (first run unpacks; do it now, not during the comp)
  ```bash
  ghidra &
  ```
- [ ] Browser proxy/FoxyProxy configured to point at Burp when needed.

## 9. Folder structure for challenges

- [ ] Create a reusable layout
  ```bash
  mkdir -p ~/ctf/{web,pwn,rev,crypto,forensics,osint,misc}
  mkdir -p ~/ctf/_templates ~/ctf/_loot ~/ctf/_notes
  # per-target helper:
  newtarget() { mkdir -p ~/ctf/$1/{scans,exploits,loot}; cd ~/ctf/$1; }
  echo 'newtarget(){ mkdir -p ~/ctf/$1/{scans,exploits,loot}; cd ~/ctf/$1; }' >> ~/.zshrc
  ```
- [ ] Verify
  ```bash
  source ~/.zshrc && newtarget testbox && ls && cd ~ && rm -rf ~/ctf/testbox
  ```

## 10. Snapshot the VM (do this LAST, when everything works)

- [ ] Power off cleanly, then take a VM snapshot named `ctf-ready-<date>`.
- [ ] Verify the snapshot appears in your hypervisor (VMware/VirtualBox) snapshot manager.
- [ ] Optional: clone the VM as a cold backup.

---

## Final go/no-go

- [ ] System updated and rebooted
- [ ] Core tools print versions without error
- [ ] SecLists + rockyou present
- [ ] VPN connects, tun0 up, target reachable
- [ ] Burp + Ghidra both launch
- [ ] Folder structure + aliases working
- [ ] Snapshot taken
