#!/usr/bin/env bash

# ligolo-ng.sh - Wrapper for ligolo-ng proxy tool
# -----------------------------------------------------------------------------
# This script builds (if necessary) and runs the ligolo-ng binary.
# Usage:
#   ./ligolo-ng.sh -l <listen_ip> -p <listen_port>
# Options:
#   -l  IP address to listen on (default: 0.0.0.0)
#   -p  Port to listen on (default: 4444)
#   -h  Show this help message
# -----------------------------------------------------------------------------

set -euo pipefail

# Default values
LISTEN_IP="0.0.0.0"
LISTEN_PORT="4444"

usage() {
  grep '^#' "$0" | sed -e 's/^# //'
  exit 1
}

while getopts ":l:p:h" opt; do
  case $opt in
    l) LISTEN_IP="$OPTARG" ;;
    p) LISTEN_PORT="$OPTARG" ;;
    h) usage ;;
    \?) echo "Invalid option: -$OPTARG" >&2; usage ;;
    :) echo "Option -$OPTARG requires an argument" >&2; usage ;;
  esac
done

# Determine script directory
SCRIPT_DIR=$(dirname "$0")
LIGOTOOL_DIR="$SCRIPT_DIR/ligolo-ng"
BIN_PATH="$LIGOTOOL_DIR/ligolo-ng"

# Build if binary not present
if [[ ! -x "$BIN_PATH" ]]; then
  echo "[+] Building ligolo-ng..."
  pushd "$LIGOTOOL_DIR" > /dev/null
  if [[ -f go.mod ]]; then
    go build -o ligolo-ng ./cmd/ligolo-ng
  else
    echo "Error: go.mod not found in $LIGOTOOL_DIR" >&2
    exit 1
  fi
  popd > /dev/null
fi

CMD=("$BIN_PATH" "-l" "$LISTEN_IP" "-p" "$LISTEN_PORT")

echo "[+] Running ligolo-ng: ${CMD[*]}"
"${CMD[@]}"
