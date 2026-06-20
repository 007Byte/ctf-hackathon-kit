#!/usr/bin/env bash
#
# auto-recon.sh - single-target reconnaissance orchestrator
# -----------------------------------------------------------------------------
# Runs a sensible, layered recon workflow against ONE target host/IP:
#   1. Quick nmap scan of the top ports (fast first look).
#   2. Full TCP port sweep (all 65535 ports) to find everything that is open.
#   3. Targeted service/version + default-script scan (-sCV) on the open ports.
#   4. Parses and prints the discovered open ports clearly.
#   5. If a common web port (80/443/8080/8443) is open, kicks off lightweight
#      web enumeration (whatweb + directory fuzzing via web-enum.sh if present,
#      otherwise an inline ffuf/gobuster fallback).
#
# All output is saved under a per-target results directory so you can grep it
# later. Missing tools are warned about and skipped (never fatal).
#
# -----------------------------------------------------------------------------
# AUTHORIZED USE ONLY: Run this exclusively against machines you own or are
# explicitly permitted to test (CTF boxes, lab VMs, HTB/picoCTF targets, etc.).
# Port/service scanning of systems without permission may be illegal.
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./auto-recon.sh <target> [output_dir]
#
# EXAMPLES:
#   ./auto-recon.sh 10.10.10.5
#   ./auto-recon.sh target.htb ./recon-results
#   ./auto-recon.sh 192.168.56.101 /tmp/box1
#
# DEPENDENCIES (all optional, degraded gracefully):
#   nmap            - core scanner (strongly recommended)
#   whatweb         - web fingerprinting
#   ffuf / gobuster - directory fuzzing
#   web-enum.sh     - sibling script in this directory (preferred for web step)
# -----------------------------------------------------------------------------

set -euo pipefail

# --- pretty logging helpers --------------------------------------------------
c_reset='\033[0m'; c_blue='\033[1;34m'; c_green='\033[1;32m'
c_yellow='\033[1;33m'; c_red='\033[1;31m'
info()  { echo -e "${c_blue}[*]${c_reset} $*"; }
ok()    { echo -e "${c_green}[+]${c_reset} $*"; }
warn()  { echo -e "${c_yellow}[!]${c_reset} $*" >&2; }
err()   { echo -e "${c_red}[-]${c_reset} $*" >&2; }

# Return 0 if a command exists on PATH, else warn + return 1.
have() {
    if command -v "$1" >/dev/null 2>&1; then
        return 0
    fi
    warn "Tool '$1' not found in PATH - skipping the step that needs it."
    return 1
}

# --- argument parsing --------------------------------------------------------
usage() {
    sed -n '2,40p' "$0"
    exit "${1:-0}"
}

if [[ $# -lt 1 || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage 0
fi

TARGET="$1"
# Default results dir: ./recon-<target>-<timestamp> (slashes/colons sanitized).
SAFE_TARGET="${TARGET//[^A-Za-z0-9._-]/_}"
OUTDIR="${2:-./recon-${SAFE_TARGET}-$(date +%Y%m%d-%H%M%S)}"

mkdir -p "$OUTDIR"
info "Target:       $TARGET"
info "Results dir:  $OUTDIR"

# Where we collect the open-port list for later phases.
OPEN_PORTS=""

# -----------------------------------------------------------------------------
# Phase 1 + 2 + 3: nmap-based scanning
# -----------------------------------------------------------------------------
run_nmap_phases() {
    if ! have nmap; then
        warn "nmap unavailable. Try the Python fallback scanner:"
        warn "    python3 port-scan.py $TARGET --common"
        return 1
    fi

    # --- Phase 1: quick top-ports scan ---
    info "Phase 1: quick top-1000 ports scan..."
    nmap -T4 --top-ports 1000 --open -oN "$OUTDIR/01_quick.nmap" "$TARGET" \
        2>&1 | tee "$OUTDIR/01_quick.log" || warn "Quick scan returned non-zero."

    # --- Phase 2: full TCP sweep ---
    info "Phase 2: full TCP port sweep (1-65535, this can take a while)..."
    # -p- = all ports, --min-rate speeds things up on responsive hosts.
    nmap -p- -T4 --min-rate 1000 --open -oN "$OUTDIR/02_allports.nmap" "$TARGET" \
        2>&1 | tee "$OUTDIR/02_allports.log" || warn "Full scan returned non-zero."

    # Parse open ports from the grepable-ish normal output.
    # Lines look like:  "22/tcp   open  ssh"
    OPEN_PORTS=$(grep -oE '^[0-9]+/tcp[[:space:]]+open' "$OUTDIR/02_allports.nmap" 2>/dev/null \
                 | grep -oE '^[0-9]+' | sort -un | paste -sd, -) || true

    if [[ -z "$OPEN_PORTS" ]]; then
        warn "No open TCP ports found in the full sweep."
        return 0
    fi

    ok "Open TCP ports: $OPEN_PORTS"

    # --- Phase 3: targeted -sCV on the discovered ports ---
    info "Phase 3: service/version + default scripts on open ports..."
    nmap -sCV -p "$OPEN_PORTS" -oN "$OUTDIR/03_services.nmap" "$TARGET" \
        2>&1 | tee "$OUTDIR/03_services.log" || warn "Service scan returned non-zero."
}

# -----------------------------------------------------------------------------
# Phase 4: clearly print the open ports / services
# -----------------------------------------------------------------------------
print_summary() {
    echo
    echo "============================================================"
    echo " OPEN PORT SUMMARY for $TARGET"
    echo "============================================================"
    if [[ -f "$OUTDIR/03_services.nmap" ]]; then
        grep -E '^[0-9]+/tcp[[:space:]]+open' "$OUTDIR/03_services.nmap" || echo "  (none parsed)"
    elif [[ -n "$OPEN_PORTS" ]]; then
        echo "  Ports: $OPEN_PORTS"
    else
        echo "  (no open ports detected)"
    fi
    echo "============================================================"
    echo
}

# -----------------------------------------------------------------------------
# Phase 5: conditional web enumeration
# -----------------------------------------------------------------------------
maybe_web_enum() {
    [[ -z "$OPEN_PORTS" ]] && return 0

    # Build the list of web URLs to investigate based on open ports.
    local -a urls=()
    for p in ${OPEN_PORTS//,/ }; do
        case "$p" in
            80)        urls+=("http://$TARGET");;
            8080)      urls+=("http://$TARGET:8080");;
            443)       urls+=("https://$TARGET");;
            8443)      urls+=("https://$TARGET:8443");;
        esac
    done

    if [[ ${#urls[@]} -eq 0 ]]; then
        info "No common web ports (80/443/8080/8443) open - skipping web enum."
        return 0
    fi

    local script_dir; script_dir="$(cd "$(dirname "$0")" && pwd)"

    for url in "${urls[@]}"; do
        info "Web enumeration against: $url"
        local webdir="$OUTDIR/web_${url//[^A-Za-z0-9]/_}"
        mkdir -p "$webdir"

        # Prefer the dedicated sibling helper if it exists.
        if [[ -x "$script_dir/web-enum.sh" ]]; then
            "$script_dir/web-enum.sh" "$url" "$webdir" || warn "web-enum.sh returned non-zero for $url"
            continue
        fi

        # ---- Inline fallback if web-enum.sh is absent ----
        if have whatweb; then
            info "  whatweb..."
            whatweb -a 3 "$url" 2>&1 | tee "$webdir/whatweb.txt" || true
        fi

        # Pick a wordlist (best-effort default; override with SECLISTS env var).
        local wl="${SECLISTS_WORDLIST:-/usr/share/seclists/Discovery/Web-Content/common.txt}"
        [[ -f "$wl" ]] || wl="/usr/share/wordlists/dirb/common.txt"

        if [[ -f "$wl" ]]; then
            if have ffuf; then
                info "  ffuf directory fuzzing with $wl ..."
                ffuf -w "$wl" -u "${url}/FUZZ" -mc 200,204,301,302,307,401,403 \
                    -of csv -o "$webdir/ffuf.csv" -c 2>&1 | tee "$webdir/ffuf.txt" || true
            elif have gobuster; then
                info "  gobuster directory fuzzing with $wl ..."
                gobuster dir -u "$url" -w "$wl" -k -o "$webdir/gobuster.txt" 2>&1 \
                    | tee "$webdir/gobuster.log" || true
            else
                warn "  No ffuf/gobuster available - skipping directory fuzzing."
            fi
        else
            warn "  No wordlist found (set SECLISTS_WORDLIST=/path/to/list) - skipping fuzzing."
        fi
    done
}

# -----------------------------------------------------------------------------
# Orchestration
# -----------------------------------------------------------------------------
run_nmap_phases || true
print_summary
maybe_web_enum || true

ok "Recon complete. All artifacts saved under: $OUTDIR"
