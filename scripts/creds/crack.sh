#!/usr/bin/env bash
#
# crack.sh - smart hash cracking (auto-identify -> hashcat)
# -----------------------------------------------------------------------------
# Point it at a file of hashes; it identifies the type, maps it to the right
# hashcat mode, and runs a sensible attack chain:
#   1. Identify with name-that-hash (nth) / hashid and map to a hashcat -m mode.
#   2. Straight dictionary (rockyou) first.
#   3. rockyou + OneRule rules (huge coverage bump).
#   4. Print --show to dump everything cracked.
# Auto-detect can be overridden with -m <mode> when you already know the type.
# -----------------------------------------------------------------------------
# AUTHORIZED USE ONLY: crack only hashes you are permitted to (your engagement).
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./crack.sh <hashfile> [-m <hashcat_mode>] [-w <wordlist>] [-r <rules>] [--show]
#
# EXAMPLES:
#   ./crack.sh kerb_hashes.txt                 # auto-detect (likely 13100)
#   ./crack.sh ntlm.txt -m 1000                # NTLM, explicit
#   ./crack.sh hashes.txt --show               # just show what's already cracked
#
# COMMON MODES: 1000 NTLM · 5600 NetNTLMv2 · 13100 Kerberoast · 18200 AS-REP ·
#               1800 sha512crypt · 500 md5crypt · 3200 bcrypt · 22000 WPA
#
# DEPENDENCIES: hashcat (required); name-that-hash/nth or hashid (auto-detect)
# -----------------------------------------------------------------------------

set -euo pipefail
c_info(){ printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok(){   printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_warn(){ printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_err(){  printf '\033[1;31m[-]\033[0m %s\n' "$*" >&2; }
c_step(){ printf '\n\033[1;36m===== %s =====\033[0m\n' "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

HASHFILE="" MODE="" WL="" RULE="" SHOWONLY=""
usage(){ sed -n '2,30p' "$0"; exit 1; }
[ $# -lt 1 ] && usage
HASHFILE="$1"; shift
while [ $# -gt 0 ]; do case "$1" in
  -m) MODE=$2; shift 2;; -w) WL=$2; shift 2;; -r) RULE=$2; shift 2;;
  --show) SHOWONLY=1; shift;; -h) usage;; *) c_err "unknown arg $1"; usage;;
esac; done
[ -f "$HASHFILE" ] || { c_err "no such file: $HASHFILE"; exit 1; }
have hashcat || { c_err "hashcat not installed"; exit 1; }

WL=${WL:-/opt/data/wordlists/rockyou.txt}; [ -f "$WL" ] || WL=/usr/share/wordlists/rockyou.txt
RULE=${RULE:-/opt/data/wordlists/rules/OneRuleToRuleThemStill.rule}
POT="./$(basename "$HASHFILE").potfile"

# ---- identify --------------------------------------------------------------
if [ -z "$MODE" ]; then
  c_step "Identifying hash type"
  SAMPLE=$(grep -m1 . "$HASHFILE" || true)
  case "$SAMPLE" in
    *'$krb5tgs$'*) MODE=13100;; *'$krb5asrep$'*) MODE=18200;;
    *'$krb5pa$'*) MODE=19900;;  *'$DCC2$'*|*'$cm$'*) MODE=2100;;
    *'$6$'*) MODE=1800;; *'$5$'*) MODE=7400;; *'$1$'*) MODE=500;;
    *'$2a$'*|*'$2b$'*|*'$2y$'*) MODE=3200;; *'$y$'*) MODE=1800;;
    *) ;;
  esac
  # NTLM looks like 32 hex; or user:rid:lm:nt::: (secretsdump) -> NTLM 1000
  if [ -z "$MODE" ]; then
    if printf '%s' "$SAMPLE" | grep -qiE '^[a-f0-9]{32}$'; then MODE=1000
    elif printf '%s' "$SAMPLE" | grep -qiE ':[a-f0-9]{32}:::'; then MODE=1000; c_info "secretsdump format - will extract NT hashes";
    elif printf '%s' "$SAMPLE" | grep -qiE '::.*:.*:[a-f0-9]{16}:'; then MODE=5600
    fi
  fi
  if [ -z "$MODE" ] && { have nth || have name-that-hash; }; then
    NTH=$(command -v nth || command -v name-that-hash)
    c_info "name-that-hash best guesses:"; $NTH -f "$HASHFILE" 2>/dev/null | grep -iE 'hashcat|Most likely' | head -8 | sed 's/^/   /' || true
  fi
  [ -z "$MODE" ] && { c_err "Could not auto-detect. Re-run with -m <mode> (see header for common modes)."; exit 1; }
  c_ok "Using hashcat mode -m $MODE"
fi

# secretsdump NTDS lines -> just the NT hash for mode 1000
TARGET="$HASHFILE"
if [ "$MODE" = 1000 ] && grep -qE ':[a-f0-9]{32}:::' "$HASHFILE"; then
  awk -F: 'NF>=4{print $4}' "$HASHFILE" | grep -iE '^[a-f0-9]{32}$' | sort -u > nt_only.txt
  TARGET=nt_only.txt; c_info "Extracted $(wc -l < nt_only.txt) NT hashes -> nt_only.txt"
fi

if [ -n "$SHOWONLY" ]; then
  c_step "Already-cracked (--show)"; hashcat -m "$MODE" "$TARGET" --show --potfile-path "$POT"; exit 0
fi

c_step "Attack 1: straight dictionary (rockyou)"
hashcat -m "$MODE" "$TARGET" "$WL" --potfile-path "$POT" --quiet || true
if [ -f "$RULE" ]; then
  c_step "Attack 2: rockyou + OneRule"
  hashcat -m "$MODE" "$TARGET" "$WL" -r "$RULE" --potfile-path "$POT" --quiet || true
else
  c_warn "rule file not found ($RULE) - skipped rule attack"
fi

c_step "CRACKED"
hashcat -m "$MODE" "$TARGET" --show --potfile-path "$POT" | tee cracked.txt || true
c_ok "Plaintext (if any) -> $(pwd)/cracked.txt  | potfile: $POT"
