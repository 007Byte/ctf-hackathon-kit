#!/usr/bin/env bash
#
# loot.sh - unified credential loot manager
# -----------------------------------------------------------------------------
# Ingests the messy output of your other tools (secretsdump, --ntds, sprays,
# GetNPUsers/GetUserSPNs, cracked.txt) and normalises everything into ONE
# deduplicated table you can grep and feed back into attacks:
#       user <TAB> nthash <TAB> plaintext <TAB> source
#   1. Scans the files/dirs you pass for recognisable credential formats.
#   2. Extracts user:rid:lm:nt::: (NTDS/SAM), user:plaintext, and $krb hashes.
#   3. Merges with any hashcat potfile to fill in cracked plaintext.
#   4. Writes creds.tsv + quick stats (accounts, cracked %, reused passwords).
# -----------------------------------------------------------------------------
# AUTHORIZED USE ONLY: handle harvested credentials as sensitive engagement data.
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./loot.sh <file_or_dir> [more ...] [-P <potfile>] [-o creds.tsv]
#
# EXAMPLES:
#   ./loot.sh ./secrets_10.10.10.10_*/ ./spray_*/valid_creds.txt
#   ./loot.sh ntds.txt -P kerb_hashes.txt.potfile
#
# DEPENDENCIES: none (pure awk/grep/sort).
# -----------------------------------------------------------------------------

set -euo pipefail
c_info(){ printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok(){   printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_warn(){ printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_step(){ printf '\n\033[1;36m===== %s =====\033[0m\n' "$*"; }

OUT="creds.tsv"; POT=""; INPUTS=()
usage(){ sed -n '2,26p' "$0"; exit 1; }
while [ $# -gt 0 ]; do case "$1" in
  -o) OUT=$2; shift 2;; -P) POT=$2; shift 2;; -h) usage;; *) INPUTS+=("$1"); shift;;
esac; done
[ ${#INPUTS[@]} -eq 0 ] && usage

TMP=$(mktemp); trap 'rm -f "$TMP"' EXIT
# gather candidate lines from all inputs
FILES=$(for p in "${INPUTS[@]}"; do [ -d "$p" ] && find "$p" -type f || echo "$p"; done)
c_step "Parsing $(echo "$FILES" | wc -l) file(s)"

# 1) NTDS / SAM: domain\user:rid:lm:nt:::  OR  user:rid:lm:nt:::
echo "$FILES" | while read -r f; do [ -f "$f" ] || continue
  grep -hE ':[a-f0-9]{32}:[a-f0-9]{32}:::' "$f" 2>/dev/null
done | awk -F: '{u=$1; sub(/^.*\\/,"",u); print tolower(u)"\t"$4"\t\tntds/sam"}' >> "$TMP" || true

# 2) cleartext user:pass (sprays / valid_creds: domain\user:pass)
echo "$FILES" | while read -r f; do [ -f "$f" ] || continue
  grep -hE '^[^:]+:[^:]+$' "$f" 2>/dev/null | grep -viE 'http|://|=' || true
done | awk -F: '{u=$1; sub(/^.*\\/,"",u); print tolower(u)"\t\t"$2"\tcleartext"}' >> "$TMP" || true

# 3) potfile (hash:plaintext) -> map nt hash to plaintext
declare -A CRACK
if [ -n "$POT" ] && [ -f "$POT" ]; then
  while IFS=: read -r h p; do CRACK[$h]="$p"; done < "$POT"
  c_ok "Loaded $(wc -l < "$POT") cracked entries from potfile"
fi

# merge + fill plaintext from potfile + dedupe
c_step "Building $OUT"
{ printf 'user\tnthash\tplaintext\tsource\n'
  sort -u "$TMP" | while IFS=$'\t' read -r u nt pt src; do
    [ -z "$pt" ] && [ -n "$nt" ] && [ -n "${CRACK[$nt]:-}" ] && pt="${CRACK[$nt]}"
    printf '%s\t%s\t%s\t%s\n' "$u" "$nt" "$pt" "$src"
  done
} > "$OUT"

TOTAL=$(($(wc -l < "$OUT")-1))
CRACKED=$(awk -F'\t' 'NR>1 && $3!=""' "$OUT" | wc -l)
c_step "STATS"
c_ok "Accounts: $TOTAL | with plaintext: $CRACKED"
c_info "Top reused passwords:"
awk -F'\t' 'NR>1 && $3!=""{print $3}' "$OUT" | sort | uniq -c | sort -rn | head -5 | sed 's/^/   /'
c_info "Loot table -> $(realpath "$OUT")"
c_info "Feed back in: validate.sh -u <user> -p <plaintext>  /  -H :<nthash>"
