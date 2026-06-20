#!/usr/bin/env bash
#
# smart-scan.sh — Staged Nmap scanning orchestrator for CTF/hackathon recon.
#
# Runs a fast all-port discovery, then a focused service/version + -A scan on
# only the ports that turned out to be open, then an optional UDP top-ports
# scan. Results are parsed into a clean open-ports summary and the script
# suggests concrete next steps based on what it found.
#
# AUTHORIZED TARGETS ONLY. Scan only systems you have explicit written
# permission to test. Unauthorized scanning is illegal.
#
# Usage:
#   ./smart-scan.sh <target> [output_dir] [--udp]
#
#   <target>      IP, hostname, or CIDR (e.g. 10.10.10.5, target.htb)
#   [output_dir]  where to save results (default: ./scan-<target>-<timestamp>)
#   --udp         also run a UDP top-ports scan in phase 3
#
# Examples:
#   ./smart-scan.sh 10.10.10.5
#   ./smart-scan.sh target.htb ./loot --udp
#
# Output files (in the results dir):
#   phase1.xml            fast all-port discovery (XML)
#   phase2.xml / .txt     detailed -sCV -A scan
#   phase3-udp.xml/.txt   UDP scan (if --udp)
#   summary.txt           parsed open-ports summary
#
set -uo pipefail

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARSER="${SCRIPT_DIR}/nmap-parser.py"

c_info()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok()    { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_warn()  { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_err()   { printf '\033[1;31m[-]\033[0m %s\n' "$*" >&2; }

usage() {
    sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
TARGET=""
OUTDIR=""
DO_UDP=0

for arg in "$@"; do
    case "$arg" in
        -h|--help) usage 0 ;;
        --udp)     DO_UDP=1 ;;
        *)
            if [[ -z "$TARGET" ]]; then
                TARGET="$arg"
            elif [[ -z "$OUTDIR" ]]; then
                OUTDIR="$arg"
            fi
            ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    c_err "No target specified."
    usage 1
fi

# --------------------------------------------------------------------------- #
# Preflight checks
# --------------------------------------------------------------------------- #
if ! command -v nmap >/dev/null 2>&1; then
    c_err "nmap is not installed or not on PATH. Install it and retry."
    exit 127
fi

# Warn (do not fail) if not root — SYN scan and -A benefit from privileges.
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    c_warn "Not running as root. SYN scan (-sS), OS detection, and UDP scans"
    c_warn "work best with sudo. Consider: sudo $0 $*"
fi

# Default output dir: ./scan-<sanitized-target>-<timestamp>
if [[ -z "$OUTDIR" ]]; then
    SAFE_TARGET="$(printf '%s' "$TARGET" | tr -c 'A-Za-z0-9._-' '_')"
    OUTDIR="./scan-${SAFE_TARGET}-$(date +%Y%m%d-%H%M%S)"
fi
mkdir -p "$OUTDIR" || { c_err "Cannot create output dir: $OUTDIR"; exit 1; }
OUTDIR="$(cd "$OUTDIR" && pwd)"

c_info "Target:      $TARGET"
c_info "Output dir:  $OUTDIR"
c_info "UDP scan:    $([[ $DO_UDP -eq 1 ]] && echo enabled || echo disabled)"
echo

# --------------------------------------------------------------------------- #
# Phase 1 — fast all-port discovery
# --------------------------------------------------------------------------- #
# -p-         : scan all 65535 TCP ports
# --min-rate  : push packet rate up for speed (tune down on fragile targets)
# -T4         : aggressive timing
# -Pn         : skip host discovery (assume up; CTF hosts often block ping)
# --open      : only report open ports (cleaner output)
# -n          : no DNS resolution (faster)
PHASE1_XML="${OUTDIR}/phase1.xml"
c_info "Phase 1: fast all-port TCP discovery (this can take a minute)..."
nmap -p- --min-rate 2000 -T4 -Pn -n --open \
     -oX "$PHASE1_XML" -oN "${OUTDIR}/phase1.txt" "$TARGET"
PHASE1_RC=$?
if [[ $PHASE1_RC -ne 0 ]]; then
    c_warn "Phase 1 nmap exited with code $PHASE1_RC (continuing if possible)."
fi

# Extract the list of open TCP ports from the XML.
# Prefer the parser; fall back to grep if it (or python) is unavailable.
extract_open_ports() {
    local xml="$1"
    [[ -f "$xml" ]] || return 0
    # grep-based extraction: pull portid from <port ...> lines that contain an
    # open state. This is intentionally dependency-free and robust.
    grep -oE '<port protocol="tcp" portid="[0-9]+"><state state="open"' "$xml" 2>/dev/null \
        | grep -oE 'portid="[0-9]+"' \
        | grep -oE '[0-9]+' \
        | sort -un \
        | paste -sd, -
}

OPEN_PORTS="$(extract_open_ports "$PHASE1_XML")"

if [[ -z "$OPEN_PORTS" ]]; then
    c_warn "No open TCP ports discovered in phase 1."
    c_warn "Target may be down/filtered. Try without -Pn, or run with sudo."
else
    c_ok "Open TCP ports: $OPEN_PORTS"
fi
echo

# --------------------------------------------------------------------------- #
# Phase 2 — targeted service/version + aggressive scan on open ports
# --------------------------------------------------------------------------- #
PHASE2_XML="${OUTDIR}/phase2.xml"
PHASE2_TXT="${OUTDIR}/phase2.txt"
if [[ -n "$OPEN_PORTS" ]]; then
    # -sCV : default NSE scripts (-sC) + version detection (-sV)
    # -A   : OS detection, traceroute, etc.
    c_info "Phase 2: detailed -sCV -A scan on ports $OPEN_PORTS ..."
    nmap -sCV -A -Pn -n -p "$OPEN_PORTS" \
         -oX "$PHASE2_XML" -oN "$PHASE2_TXT" "$TARGET"
    PHASE2_RC=$?
    [[ $PHASE2_RC -ne 0 ]] && c_warn "Phase 2 nmap exited with code $PHASE2_RC."
    echo
else
    c_warn "Skipping phase 2 (no open ports)."
    echo
fi

# --------------------------------------------------------------------------- #
# Phase 3 — optional UDP top-ports scan
# --------------------------------------------------------------------------- #
PHASE3_XML="${OUTDIR}/phase3-udp.xml"
if [[ $DO_UDP -eq 1 ]]; then
    # -sU         : UDP scan (slow; needs root)
    # --top-ports : limit to the most common UDP ports for speed
    c_info "Phase 3: UDP top-100 ports scan (slow)..."
    nmap -sU --top-ports 100 -T4 -Pn -n --open \
         -oX "$PHASE3_XML" -oN "${OUTDIR}/phase3-udp.txt" "$TARGET"
    PHASE3_RC=$?
    [[ $PHASE3_RC -ne 0 ]] && c_warn "Phase 3 nmap exited with code $PHASE3_RC."
    echo
fi

# --------------------------------------------------------------------------- #
# Parse + summarize
# --------------------------------------------------------------------------- #
SUMMARY="${OUTDIR}/summary.txt"
# Choose the richest XML available for the summary.
SUMMARY_XML="$PHASE2_XML"
[[ -f "$SUMMARY_XML" ]] || SUMMARY_XML="$PHASE1_XML"

c_info "Parsing results..."
if [[ -f "$PARSER" ]] && command -v python3 >/dev/null 2>&1 && [[ -f "$SUMMARY_XML" ]]; then
    python3 "$PARSER" "$SUMMARY_XML" --format table | tee "$SUMMARY"
elif [[ -f "$SUMMARY_XML" ]]; then
    c_warn "nmap-parser.py/python3 not found — falling back to grep summary."
    grep -E 'Nmap scan report|open' "${PHASE2_TXT:-/dev/null}" 2>/dev/null \
        | tee "$SUMMARY" \
        || c_warn "No detailed text output to summarize."
else
    c_warn "No XML output available to summarize."
fi
echo

# --------------------------------------------------------------------------- #
# Suggest next steps based on discovered services
# --------------------------------------------------------------------------- #
# Build a quick "ip:port service" view to drive suggestions. Prefer parser
# --grep; fall back to the raw open-port numbers from phase 1.
SERVICES_VIEW=""
if [[ -f "$PARSER" ]] && command -v python3 >/dev/null 2>&1 && [[ -f "$SUMMARY_XML" ]]; then
    SERVICES_VIEW="$(python3 "$PARSER" "$SUMMARY_XML" --grep 2>/dev/null)"
fi

c_info "Suggested next steps:"

# Helper: does the services view (or open-port list) mention a port/service?
has() {
    local needle="$1"
    if [[ -n "$SERVICES_VIEW" ]] && grep -qiE "$needle" <<<"$SERVICES_VIEW"; then
        return 0
    fi
    return 1
}
# Helper: is a numeric port in the comma-separated OPEN_PORTS list?
has_port() {
    local p="$1"
    [[ ",$OPEN_PORTS," == *",$p,"* ]]
}

SUGGESTED=0
suggest() { c_ok "  $*"; SUGGESTED=1; }

if has '\b(ftp)\b' || has_port 21; then
    suggest "21/ftp     -> check anonymous login; nse-vuln-scan.sh <t> 21"
fi
if has '\b(ssh)\b' || has_port 22; then
    suggest "22/ssh     -> banner/version; try default creds, key auth, enum users"
fi
if has '\bsmtp\b' || has_port 25; then
    suggest "25/smtp    -> smtp-user-enum (VRFY/EXPN), check open relay"
fi
if has '\b(dns|domain)\b' || has_port 53; then
    suggest "53/dns     -> attempt zone transfer; nse-vuln-scan.sh <t> 53"
fi
if has 'http' || has_port 80 || has_port 8080 || has_port 8000; then
    suggest "80/http    -> web enum: gobuster/feroxbuster, nikto, nse-vuln-scan.sh <t> 80"
fi
if has '\b(microsoft-ds|netbios|smb)\b' || has_port 139 || has_port 445; then
    suggest "445/smb    -> enum4linux-ng, smbclient -L, nse-vuln-scan.sh <t> 445 (ms17-010!)"
fi
if has '\b(https|ssl)\b' || has_port 443 || has_port 8443; then
    suggest "443/https  -> ssl-enum-ciphers/heartbleed; web enum over TLS"
fi
if has '\b(ms-wbt-server|rdp)\b' || has_port 3389; then
    suggest "3389/rdp   -> check BlueKeep, NLA; try default creds"
fi
if has '\bmysql\b' || has_port 3306; then
    suggest "3306/mysql -> try default/blank creds, mysql NSE scripts"
fi
if has '\b(ms-sql|mssql)\b' || has_port 1433; then
    suggest "1433/mssql -> ms-sql-info, try sa/blank, mssql NSE scripts"
fi
if has '\bldap\b' || has_port 389 || has_port 636; then
    suggest "389/ldap   -> ldapsearch anonymous bind, enum domain objects"
fi

if [[ $SUGGESTED -eq 0 ]]; then
    c_warn "  No well-known services matched. Review $SUMMARY manually."
fi

echo
c_ok "Done. All artifacts saved to: $OUTDIR"
c_info "Recommended follow-up: ${SCRIPT_DIR}/nse-vuln-scan.sh $TARGET ${OPEN_PORTS:-<ports>}"
