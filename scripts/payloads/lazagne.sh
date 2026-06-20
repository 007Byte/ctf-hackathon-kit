#!/usr/bin/env bash

# lazagne.sh - Simple wrapper for LaZagne credential extraction tool
# -----------------------------------------------------------------------------
# This script provides a thin Bash interface around the LaZagne binary (or
# Python implementation) to collect stored credentials from the local system.
# It is intended for authorized security‑research / red‑team use only.
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./lazagne.sh -i <target> [-o <output_file>] [-j]
#   -i  Path to the target executable, directory, or system to scan (required)
#   -o  Output file (default: lazagne_output.json)
#   -j  Force JSON output (adds "--json" flag if supported)
#   -h  Show this help message
#
# EXAMPLE:
#   ./lazagne.sh -i C:\\Windows\\System32 -o creds.json -j
#
# NOTE: The script assumes the LaZagne binary is either in the system PATH as
# "lazagne"/"lazagne.exe" or located in the same directory as this wrapper.
# Adjust LAZAGNE_BIN below if needed.

set -euo pipefail

# Function to display usage information
usage() {
  grep '^#' "$0" | sed -e 's/^# //'   # Extract comments as help text
  exit 1
}

# Default values
TARGET=""
OUTPUT="lazagne_output.json"
FORCE_JSON=false

# Parse command‑line arguments
while getopts ":i:o:jh" opt; do
  case $opt in
    i)
      TARGET="$OPTARG"
      ;;
    o)
      OUTPUT="$OPTARG"
      ;;
    j)
      FORCE_JSON=true
      ;;
    h)
      usage
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      usage
      ;;
    :) 
      echo "Option -$OPTARG requires an argument." >&2
      usage
      ;;
  esac
done

# Verify required input
if [[ -z "$TARGET" ]]; then
  echo "Error: target (-i) is required." >&2
  usage
fi

# Resolve LaZagne binary
if command -v lazagne >/dev/null 2>&1; then
  LAZAGNE_BIN="lazagne"
elif command -v lazagne.exe >/dev/null 2>&1; then
  LAZAGNE_BIN="lazagne.exe"
else
  # Fallback: look for a lazagne script in the same directory
  SCRIPT_DIR=$(dirname "$0")
  if [[ -x "$SCRIPT_DIR/lazagne" ]]; then
    LAZAGNE_BIN="$SCRIPT_DIR/lazagne"
  elif [[ -x "$SCRIPT_DIR/lazagne.exe" ]]; then
    LAZAGNE_BIN="$SCRIPT_DIR/lazagne.exe"
  else
    echo "Error: LaZagne binary not found in PATH or the script directory." >&2
    exit 1
  fi
fi

# Build LaZagne command
LAZ_CMD=("$LAZAGNE_BIN" "all" "-i" "$TARGET")
if $FORCE_JSON; then
  LAZ_CMD+=("--json")
fi

# Show the command for reproducibility
echo "[+] Running LaZagne command: ${LAZ_CMD[*]}"

# Execute and capture output
# If LaZagne supports direct JSON output, we simply redirect to the file.
# Otherwise, we attempt to convert plain text to JSON using a simple awk
# transformation (best‑effort).
if $FORCE_JSON; then
  "${LAZ_CMD[@]}" > "$OUTPUT"
else
  # Capture raw output first
  RAW_OUTPUT=$("${LAZ_CMD[@]}")
  # Simple conversion: each line -> {"line": "..."}
  echo "[" > "$OUTPUT"
  i=0
  while IFS= read -r line; do
    # Escape double quotes for JSON
    esc=$(printf "%s" "$line" | sed 's/"/\\"/g')
    if (( i > 0 )); then echo "," >> "$OUTPUT"; fi
    echo "  {\"line\": \"$esc\"}" >> "$OUTPUT"
    ((i++))
  done <<< "$RAW_OUTPUT"
  echo ""]" >> "$OUTPUT"
fi

echo "[+] Output written to $OUTPUT"
