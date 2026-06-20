#!/usr/bin/env bash
#
# ghidra-decompile.sh - Batch-decompile a binary to C with Ghidra headless
# ----------------------------------------------------------------------------
# AUTHORIZED / EDUCATIONAL USE ONLY.
#   For CTF challenges, hackathons, and binaries you own or are explicitly
#   authorized to analyze. Do not use against software you lack permission to
#   inspect.
# ----------------------------------------------------------------------------
#
# This is a no-GUI wrapper around Ghidra's `analyzeHeadless`. It:
#   1. Locates a Ghidra installation (env override or common paths).
#   2. Creates a temporary Ghidra project.
#   3. Imports + auto-analyzes the target binary.
#   4. Runs the companion post-script DecompileToC.java to export the
#      decompiled C for every function into a single .c file.
#   5. Prints where the output landed and cleans up the temp project.
#
# USAGE:
#   ./ghidra-decompile.sh <binary> [output-dir]
#
#   <binary>      Path to the target executable to decompile.
#   [output-dir]  Optional. Directory for the decompiled .c output.
#                 Defaults to the directory containing <binary>.
#
# ENVIRONMENT:
#   GHIDRA_HOME           Path to the Ghidra install root (contains
#                         support/analyzeHeadless). Overrides auto-detection.
#   GHIDRA_ANALYZE_TIMEOUT  Per-file analysis timeout in seconds (default 600).
#
# REQUIREMENTS:
#   * Ghidra (10.x / 11.x) with a working JDK 17+ on PATH.
#   * The companion script DecompileToC.java located next to THIS script.
#
# Target runtime: Kali / Linux. Authored on a Windows host.
# ----------------------------------------------------------------------------

set -u

# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    C_RESET="\033[0m"; C_BOLD="\033[1m"; C_RED="\033[31m"
    C_GREEN="\033[32m"; C_YELLOW="\033[33m"; C_BLUE="\033[34m"
else
    C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""
fi
say()  { printf "${C_BOLD}${C_BLUE}[*]${C_RESET} %s\n" "$1"; }
ok()   { printf "${C_GREEN}[+]${C_RESET} %s\n" "$1"; }
warn() { printf "${C_YELLOW}[-]${C_RESET} %s\n" "$1"; }
err()  { printf "${C_RED}[!]${C_RESET} %s\n" "$1" >&2; }

usage() {
    cat <<EOF
ghidra-decompile.sh - batch-decompile a binary to C with Ghidra headless

Usage:
  $0 <binary> [output-dir]

Env:
  GHIDRA_HOME=/opt/ghidra   override Ghidra install location

Example:
  GHIDRA_HOME=/opt/ghidra_11.1_PUBLIC $0 ./challenge ./decompiled

AUTHORIZED / EDUCATIONAL USE ONLY.
EOF
}

# ---------------------------------------------------------------------------
# Argument handling
# ---------------------------------------------------------------------------
if [ "$#" -lt 1 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    usage
    exit 1
fi

BIN="$1"
if [ ! -f "$BIN" ]; then
    err "Binary not found: $BIN"
    exit 1
fi

# Resolve absolute path to the binary (so it survives the cd into temp dir).
BIN_ABS="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
BIN_NAME="$(basename "$BIN")"

# Output directory (default: alongside the binary).
OUT_DIR="${2:-$(dirname "$BIN_ABS")}"
mkdir -p "$OUT_DIR" || { err "Cannot create output dir: $OUT_DIR"; exit 1; }
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
OUT_C="$OUT_DIR/${BIN_NAME}.decompiled.c"

# Directory of THIS script (to find the companion .java).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POST_SCRIPT="DecompileToC.java"
if [ ! -f "$SCRIPT_DIR/$POST_SCRIPT" ]; then
    err "Companion post-script not found: $SCRIPT_DIR/$POST_SCRIPT"
    err "It must sit next to ghidra-decompile.sh."
    exit 1
fi

# ---------------------------------------------------------------------------
# Locate analyzeHeadless
# ---------------------------------------------------------------------------
find_headless() {
    # 1. Honour GHIDRA_HOME if set.
    if [ -n "${GHIDRA_HOME:-}" ]; then
        if [ -x "$GHIDRA_HOME/support/analyzeHeadless" ]; then
            echo "$GHIDRA_HOME/support/analyzeHeadless"; return 0
        fi
        warn "GHIDRA_HOME set ($GHIDRA_HOME) but support/analyzeHeadless not found there."
    fi

    # 2. analyzeHeadless already on PATH?
    if command -v analyzeHeadless >/dev/null 2>&1; then
        command -v analyzeHeadless; return 0
    fi

    # 3. Probe common install locations / glob patterns.
    local candidates=(
        /opt/ghidra/support/analyzeHeadless
        /usr/share/ghidra/support/analyzeHeadless
        /usr/local/ghidra/support/analyzeHeadless
        "$HOME/ghidra/support/analyzeHeadless"
        "$HOME/tools/ghidra/support/analyzeHeadless"
    )
    local c
    for c in "${candidates[@]}"; do
        [ -x "$c" ] && { echo "$c"; return 0; }
    done

    # 4. Glob versioned dirs like /opt/ghidra_11.1_PUBLIC/support/analyzeHeadless
    for c in /opt/ghidra_*/support/analyzeHeadless \
             /usr/share/ghidra_*/support/analyzeHeadless \
             /usr/local/ghidra_*/support/analyzeHeadless \
             "$HOME"/ghidra_*/support/analyzeHeadless; do
        [ -x "$c" ] && { echo "$c"; return 0; }
    done

    return 1
}

HEADLESS="$(find_headless)"
if [ -z "$HEADLESS" ]; then
    err "Could not locate Ghidra's analyzeHeadless."
    err "Set GHIDRA_HOME, e.g.:  export GHIDRA_HOME=/opt/ghidra_11.1_PUBLIC"
    err "Download Ghidra: https://github.com/NationalSecurityAgency/ghidra/releases"
    exit 1
fi
ok "Using Ghidra headless: $HEADLESS"

# Sanity: a JVM must be reachable for Ghidra to run.
if ! command -v java >/dev/null 2>&1 && [ -z "${JAVA_HOME:-}" ]; then
    warn "No 'java' on PATH and JAVA_HOME unset; Ghidra needs a JDK 17+."
    warn "Install one, e.g.: sudo apt install openjdk-17-jdk"
fi

# ---------------------------------------------------------------------------
# Temp project setup
# ---------------------------------------------------------------------------
PROJ_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ghidra_proj.XXXXXX")" \
    || { err "Failed to create temp project dir."; exit 1; }
PROJ_NAME="triage_$$"
TIMEOUT="${GHIDRA_ANALYZE_TIMEOUT:-600}"

# Always clean up the temp project, even on error/interrupt.
cleanup() {
    [ -d "$PROJ_DIR" ] && rm -rf "$PROJ_DIR"
}
trap cleanup EXIT INT TERM

say "Binary       : $BIN_ABS"
say "Output C file: $OUT_C"
say "Temp project : $PROJ_DIR ($PROJ_NAME)"
say "Post-script  : $SCRIPT_DIR/$POST_SCRIPT"
say "Running analyzeHeadless (this may take a while)..."

# ---------------------------------------------------------------------------
# Run headless analysis + decompilation post-script
# ---------------------------------------------------------------------------
# analyzeHeadless usage:
#   analyzeHeadless <proj_location> <proj_name> -import <file>
#       -scriptPath <dir> -postScript <Script.java> [script args...]
#       -deleteProject -analysisTimeoutPerFile <secs> -overwrite
#
# We pass the desired output .c path as the single argument to DecompileToC.
"$HEADLESS" \
    "$PROJ_DIR" "$PROJ_NAME" \
    -import "$BIN_ABS" \
    -overwrite \
    -analysisTimeoutPerFile "$TIMEOUT" \
    -scriptPath "$SCRIPT_DIR" \
    -postScript "$POST_SCRIPT" "$OUT_C" \
    -deleteProject
HEADLESS_RC=$?

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
echo
if [ "$HEADLESS_RC" -ne 0 ]; then
    err "analyzeHeadless exited with status $HEADLESS_RC."
    err "Check the Ghidra output above for the cause."
    exit "$HEADLESS_RC"
fi

if [ -s "$OUT_C" ]; then
    LINES="$(wc -l < "$OUT_C" | tr -d ' ')"
    ok  "Decompilation complete."
    ok  "Output: $OUT_C  (${LINES} lines)"
    echo
    say "Preview (first 20 lines):"
    head -n 20 "$OUT_C" | sed 's/^/    /'
else
    warn "analyzeHeadless finished but no output file was produced at:"
    warn "  $OUT_C"
    warn "The post-script may have failed; review the Ghidra log above."
    exit 1
fi
