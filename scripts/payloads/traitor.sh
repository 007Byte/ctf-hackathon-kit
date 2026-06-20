#!/usr/bin/env bash

# traitor.sh - Wrapper for Traitor privilege‑escalation tool
# -----------------------------------------------------------------------------
# This script compiles (if source is present) and runs the Traitor binary.
# Usage:
#   ./traitor.sh -t <target_ip> [-p <target_port>] [-e <payload_path>]
# Options:
#   -t  Target IP address (required)
#   -p  Target port (default: 4444)
#   -e  Path to payload to deliver (optional)
#   -h  Show this help message
# -----------------------------------------------------------------------------

set -euo pipefail

usage() {
  grep '^#' "$0" | sed -e 's/^# //'
  exit 1
}

# Default values
TARGET_IP=""
TARGET_PORT="4444"
PAYLOAD=""

while getopts ":t:p:e:h" opt; do
  case $opt in
    t) TARGET_IP="$OPTARG" ;;
    p) TARGET_PORT="$OPTARG" ;;
    e) PAYLOAD="$OPTARG" ;;
    h) usage ;;
    \?) echo "Invalid option: -$OPTARG" >&2; usage ;;
    :) echo "Option -$OPTARG requires an argument" >&2; usage ;;
  esac
done

if [[ -z "$TARGET_IP" ]]; then
  echo "Error: target IP (-t) is required" >&2
  usage
fi

SCRIPT_DIR=$(dirname "$0")
TRAITOR_DIR="$SCRIPT_DIR/traitor"
BIN_PATH="$TRAITOR_DIR/traitor.exe"

# Build if source exists and binary not present
if [[ ! -x "$BIN_PATH" ]]; then
  if [[ -f "$TRAITOR_DIR/traitor.c" ]]; then
    echo "[+] Building Traitor..."
    x86_64-w64-mingw32-gcc "$TRAITOR_DIR/traitor.c" -o "$BIN_PATH"
  else
    echo "Error: Traitor binary not found and no source to build" >&2
    exit 1
  fi
fi

CMD=("$BIN_PATH" "-t" "$TARGET_IP" "-p" "$TARGET_PORT")
if [[ -n "$PAYLOAD" ]]; then
  CMD+=("-e" "$PAYLOAD")
fi

echo "[+] Running Traitor: ${CMD[*]}"
"${CMD[@]}"
