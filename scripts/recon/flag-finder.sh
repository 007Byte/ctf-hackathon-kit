#!/usr/bin/env bash
#
# flag-finder.sh - hunt for CTF flags across a filesystem/directory
# -----------------------------------------------------------------------------
# A post-exploitation convenience tool. It recursively searches a target path
# for likely CTF flag patterns, looking at BOTH file contents and file NAMES,
# with an optional base64-decode pass to catch encoded flags.
#
# Built-in patterns include:  flag{...}, picoCTF{...}, CTF{...}, HTB{...},
# THM{...}, FLAG{...}, and the generic "key{...}". You can add your own regex.
#
# -----------------------------------------------------------------------------
# AUTHORIZED USE ONLY: Run on CTF/lab machines you are permitted to test. This
# is meant for boxes you have legitimately compromised in a sanctioned exercise.
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./flag-finder.sh [-p path] [-r 'custom_regex'] [-b] [-i] [-h]
#
# OPTIONS:
#   -p <path>     Directory to search (default: current directory '.').
#   -r <regex>    Additional custom flag regex (extended regex / ERE).
#   -b            Also do a base64-decode pass: decode base64-looking blobs and
#                 re-search the decoded text for flag patterns.
#   -i            Case-insensitive matching.
#   -h            Show this help.
#
# EXAMPLES:
#   ./flag-finder.sh                          # search current dir
#   ./flag-finder.sh -p /                     # search whole filesystem
#   ./flag-finder.sh -p /home -b             # include base64-decode pass
#   ./flag-finder.sh -p /var/www -r 'secret\{[^}]+\}' -i
# -----------------------------------------------------------------------------

set -euo pipefail

c_reset='\033[0m'; c_blue='\033[1;34m'; c_green='\033[1;32m'
c_yellow='\033[1;33m'
info()  { echo -e "${c_blue}[*]${c_reset} $*"; }
ok()    { echo -e "${c_green}[+]${c_reset} $*"; }
warn()  { echo -e "${c_yellow}[!]${c_reset} $*" >&2; }

usage() { sed -n '2,40p' "$0"; exit "${1:-0}"; }

# --- defaults ---
SEARCH_PATH="."
CUSTOM_REGEX=""
DO_BASE64=0
CASE_FLAG=""   # becomes "-i" when -i is supplied

while getopts ":p:r:bih" opt; do
    case "$opt" in
        p) SEARCH_PATH="$OPTARG";;
        r) CUSTOM_REGEX="$OPTARG";;
        b) DO_BASE64=1;;
        i) CASE_FLAG="-i";;
        h) usage 0;;
        :) warn "Option -$OPTARG requires an argument."; usage 1;;
        \?) warn "Unknown option -$OPTARG"; usage 1;;
    esac
done

[[ -d "$SEARCH_PATH" ]] || { warn "Path not found or not a directory: $SEARCH_PATH"; exit 1; }

# Base flag pattern (ERE). Common CTF prefixes + a generic key{...}.
BASE_PATTERN='(flag|picoCTF|CTF|HTB|THM|FLAG|key|secret)\{[^}]+\}'
PATTERN="$BASE_PATTERN"
if [[ -n "$CUSTOM_REGEX" ]]; then
    PATTERN="($BASE_PATTERN)|($CUSTOM_REGEX)"
fi

info "Search path:    $SEARCH_PATH"
info "Flag pattern:   $PATTERN"
[[ -n "$CASE_FLAG" ]] && info "Case-insensitive matching enabled."
[[ "$DO_BASE64" -eq 1 ]] && info "Base64-decode pass enabled."

# Use ripgrep if available (much faster); otherwise fall back to grep.
if command -v rg >/dev/null 2>&1; then
    GREP_BIN="rg"
else
    GREP_BIN="grep"
fi

# -----------------------------------------------------------------------------
# Pass 1: search file CONTENTS
# -----------------------------------------------------------------------------
echo
ok "=== Pass 1: file contents ==="
if [[ "$GREP_BIN" == "rg" ]]; then
    # -a: treat binary as text, -n: line numbers, --no-messages: hide perm errors
    rg -a -n --no-messages $CASE_FLAG -e "$PATTERN" "$SEARCH_PATH" || warn "No content matches."
else
    # -r recursive, -a binary-as-text, -n line numbers, -E ERE; suppress errors.
    grep -rEan $CASE_FLAG -e "$PATTERN" "$SEARCH_PATH" 2>/dev/null || warn "No content matches."
fi

# -----------------------------------------------------------------------------
# Pass 2: search file NAMES / paths
# -----------------------------------------------------------------------------
echo
ok "=== Pass 2: file names / paths ==="
# -E for ERE on find's -regex via grep filtering keeps this portable.
if [[ -n "$CASE_FLAG" ]]; then
    find "$SEARCH_PATH" 2>/dev/null | grep -Ei -e "$PATTERN" || warn "No filename matches."
else
    find "$SEARCH_PATH" 2>/dev/null | grep -E -e "$PATTERN" || warn "No filename matches."
fi

# -----------------------------------------------------------------------------
# Pass 3 (optional): base64-decode pass
# -----------------------------------------------------------------------------
if [[ "$DO_BASE64" -eq 1 ]]; then
    echo
    ok "=== Pass 3: base64-decode pass ==="
    # Strategy: find base64-looking tokens (>=20 chars of the base64 alphabet),
    # decode each, and search the decoded output for flag patterns.
    # We scan regular, readable files only to stay reasonably fast.
    #
    # Note: the loops below end with `|| true` because, under `set -e`, a
    # `while read` loop whose final iteration's test is false would otherwise
    # bubble up a non-zero status and abort the script.
    #
    # Build the grep flags array so an empty CASE_FLAG never becomes a stray "".
    grep_args=(-E)
    [[ -n "$CASE_FLAG" ]] && grep_args+=("$CASE_FLAG")

    find "$SEARCH_PATH" -type f -readable 2>/dev/null | while IFS= read -r f; do
        # Extract candidate base64 blobs from the file.
        grep -aoE '[A-Za-z0-9+/]{20,}={0,2}' "$f" 2>/dev/null | while IFS= read -r blob; do
            decoded=$(printf '%s' "$blob" | base64 -d 2>/dev/null) || continue
            if printf '%s' "$decoded" | grep -q "${grep_args[@]}" -e "$PATTERN"; then
                match=$(printf '%s' "$decoded" | grep -o "${grep_args[@]}" -e "$PATTERN" | head -n1)
                ok "Decoded flag in $f"
                echo "    encoded: ${blob:0:60}..."
                echo "    decoded match: $match"
            fi
        done || true
    done || true
    info "Base64 pass complete."
fi

echo
ok "Flag hunt complete."
