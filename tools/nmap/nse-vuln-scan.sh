#!/usr/bin/env bash
#
# nse-vuln-scan.sh — Targeted Nmap Scripting Engine (NSE) vulnerability scanner.
#
# Maps discovered services to the most useful NSE scripts and runs them. You can
# pass the open ports explicitly, or let the script auto-detect them with a quick
# service scan first. Results are saved per run.
#
# AUTHORIZED TARGETS ONLY. Run only against systems you have explicit written
# permission to test. Several of these scripts (smb-vuln-*, ssl-heartbleed,
# http-vuln-*) actively probe for exploitable conditions — never point them at
# systems you don't own or aren't authorized to assess.
#
# Usage:
#   ./nse-vuln-scan.sh <target> [ports] [output_dir]
#
#   <target>      IP / hostname to scan
#   [ports]       comma-separated ports (e.g. 80,443,445). If omitted, the
#                 script runs a quick scan to auto-detect open ports.
#   [output_dir]  where to save results (default: ./nse-<target>-<timestamp>)
#
# Examples:
#   ./nse-vuln-scan.sh 10.10.10.5
#   ./nse-vuln-scan.sh 10.10.10.5 80,443,445
#   ./nse-vuln-scan.sh target.htb 21,22,80 ./loot
#
# Service -> NSE script map:
#   http/https  : http-enum, http-title, http-headers, http-vuln*, http-shellshock
#   smb         : smb-os-discovery, smb-enum-shares, smb-vuln-ms17-010, smb-vuln*
#   ftp         : ftp-anon, ftp-vsftpd-backdoor
#   ssl/tls     : ssl-enum-ciphers, ssl-heartbleed
#   dns         : dns-zone-transfer
#   (fallback)  : --script vuln
#
set -uo pipefail

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
c_info()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok()    { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_warn()  { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_err()   { printf '\033[1;31m[-]\033[0m %s\n' "$*" >&2; }

usage() {
    sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# --------------------------------------------------------------------------- #
# Arguments
# --------------------------------------------------------------------------- #
case "${1:-}" in
    -h|--help|"") [[ -z "${1:-}" ]] && c_err "No target specified."; usage 0 ;;
esac

TARGET="$1"
PORTS="${2:-}"
OUTDIR="${3:-}"

# --------------------------------------------------------------------------- #
# Preflight
# --------------------------------------------------------------------------- #
if ! command -v nmap >/dev/null 2>&1; then
    c_err "nmap is not installed or not on PATH."
    exit 127
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    c_warn "Not root. Some scripts/scan types work best with sudo."
fi

if [[ -z "$OUTDIR" ]]; then
    SAFE_TARGET="$(printf '%s' "$TARGET" | tr -c 'A-Za-z0-9._-' '_')"
    OUTDIR="./nse-${SAFE_TARGET}-$(date +%Y%m%d-%H%M%S)"
fi
mkdir -p "$OUTDIR" || { c_err "Cannot create output dir: $OUTDIR"; exit 1; }
OUTDIR="$(cd "$OUTDIR" && pwd)"

# --------------------------------------------------------------------------- #
# Auto-detect ports if none supplied
# --------------------------------------------------------------------------- #
# We keep a parallel "port -> service name" view so the service->script mapping
# is accurate even on non-standard ports.
DETECT_XML="${OUTDIR}/detect.xml"
declare -A PORT_SVC   # portid -> service name (e.g. 80 -> http)

if [[ -z "$PORTS" ]]; then
    c_info "No ports given — running a quick service scan to auto-detect..."
    # Quick version scan of the top 1000 ports; -Pn for CTF hosts that block ping.
    nmap -sV -T4 -Pn -n --open -oX "$DETECT_XML" "$TARGET" >/dev/null 2>&1
    if [[ ! -f "$DETECT_XML" ]]; then
        c_err "Quick scan produced no output. Specify ports manually."
        exit 1
    fi
    # Parse portid + service name from the XML (dependency-free).
    while IFS= read -r line; do
        pid="$(grep -oE 'portid="[0-9]+"' <<<"$line" | grep -oE '[0-9]+')"
        svc="$(grep -oE 'name="[^"]+"' <<<"$line" | head -n1 | sed 's/name="//;s/"//')"
        [[ -n "$pid" ]] && PORT_SVC["$pid"]="${svc:-unknown}"
    done < <(grep -oE '<port protocol="tcp" portid="[0-9]+"><state state="open"[^/]*/?>.*?</port>|<port [^>]*portid="[0-9]+"[^>]*>.*?<service [^>]*>' "$DETECT_XML" 2>/dev/null)

    # Robust fallback: re-extract any open port even if the regex above missed it.
    if [[ ${#PORT_SVC[@]} -eq 0 ]]; then
        while IFS= read -r pid; do
            PORT_SVC["$pid"]="unknown"
        done < <(grep -oE 'portid="[0-9]+"' "$DETECT_XML" | grep -oE '[0-9]+' | sort -un)
    fi

    PORTS="$(printf '%s\n' "${!PORT_SVC[@]}" | sort -un | paste -sd, -)"
    if [[ -z "$PORTS" ]]; then
        c_err "No open ports detected on $TARGET."
        exit 1
    fi
    c_ok "Detected open ports: $PORTS"
else
    # Ports supplied: service unknown, so map by well-known port number below.
    IFS=',' read -ra _plist <<<"$PORTS"
    for p in "${_plist[@]}"; do
        p="$(printf '%s' "$p" | tr -dc '0-9')"
        [[ -n "$p" ]] && PORT_SVC["$p"]="unknown"
    done
fi
echo

# --------------------------------------------------------------------------- #
# Service classification
# --------------------------------------------------------------------------- #
# Given a port number and (possibly "unknown") service name, decide a category.
classify() {
    local port="$1" svc="$2"
    svc="$(printf '%s' "$svc" | tr '[:upper:]' '[:lower:]')"

    # Prefer the detected service name; fall back to well-known port numbers.
    case "$svc" in
        *http*)               [[ "$svc" == *ssl* ]] && echo "ssl-http" || echo "http"; return ;;
        *ssl*|*https*|*tls*)  echo "ssl-http"; return ;;
        *microsoft-ds*|*netbios*|*smb*) echo "smb"; return ;;
        *ftp*)                echo "ftp"; return ;;
        *domain*|*dns*)       echo "dns"; return ;;
    esac

    case "$port" in
        80|8080|8000|8888) echo "http" ;;
        443|8443)          echo "ssl-http" ;;
        139|445)           echo "smb" ;;
        21)                echo "ftp" ;;
        53)                echo "dns" ;;
        *)                 echo "default" ;;
    esac
}

# --------------------------------------------------------------------------- #
# Build per-category port lists
# --------------------------------------------------------------------------- #
HTTP_PORTS=""; SSL_PORTS=""; SMB_PORTS=""; FTP_PORTS=""; DNS_PORTS=""; OTHER_PORTS=""

append() { local -n ref="$1"; ref="${ref:+$ref,}$2"; }

for port in $(printf '%s\n' "${!PORT_SVC[@]}" | sort -un); do
    cat="$(classify "$port" "${PORT_SVC[$port]}")"
    case "$cat" in
        http)     append HTTP_PORTS "$port" ;;
        ssl-http) append SSL_PORTS "$port"; append HTTP_PORTS "$port" ;;  # run http scripts over TLS too
        smb)      append SMB_PORTS "$port" ;;
        ftp)      append FTP_PORTS "$port" ;;
        dns)      append DNS_PORTS "$port" ;;
        *)        append OTHER_PORTS "$port" ;;
    esac
done

# --------------------------------------------------------------------------- #
# Run an NSE scan for a category and save output
# --------------------------------------------------------------------------- #
run_nse() {
    local label="$1" ports="$2" scripts="$3"
    [[ -z "$ports" ]] && return 0
    local base="${OUTDIR}/nse-${label}"
    c_info "[$label] ports $ports"
    c_info "        scripts: $scripts"
    # -sV gives the scripts service context; -Pn/-n keep it fast & quiet.
    nmap -sV -Pn -n -p "$ports" --script "$scripts" \
         -oN "${base}.txt" -oX "${base}.xml" "$TARGET"
    local rc=$?
    if [[ $rc -eq 0 ]]; then
        c_ok "        saved -> ${base}.txt"
    else
        c_warn "        nmap exited $rc (output may be partial: ${base}.txt)"
    fi
    echo
}

c_info "Target:     $TARGET"
c_info "Output dir: $OUTDIR"
echo

# --- HTTP / HTTPS ---------------------------------------------------------- #
# http-enum (dirs), http-title, http-headers, the http-vuln-* family, and the
# classic Shellshock check.
run_nse "http" "$HTTP_PORTS" \
    "http-enum,http-title,http-headers,http-shellshock,http-vuln*"

# --- SSL / TLS ------------------------------------------------------------- #
run_nse "ssl" "$SSL_PORTS" \
    "ssl-enum-ciphers,ssl-heartbleed"

# --- SMB ------------------------------------------------------------------- #
# Includes the EternalBlue check (smb-vuln-ms17-010) plus broader smb-vuln*.
run_nse "smb" "$SMB_PORTS" \
    "smb-os-discovery,smb-enum-shares,smb-enum-users,smb-vuln-ms17-010,smb-vuln*"

# --- FTP ------------------------------------------------------------------- #
run_nse "ftp" "$FTP_PORTS" \
    "ftp-anon,ftp-vsftpd-backdoor,ftp-syst"

# --- DNS ------------------------------------------------------------------- #
run_nse "dns" "$DNS_PORTS" \
    "dns-zone-transfer,dns-nsid"

# --- Fallback for everything else: the general vuln category --------------- #
if [[ -n "$OTHER_PORTS" ]]; then
    run_nse "vuln" "$OTHER_PORTS" "vuln"
fi

c_ok "All NSE scans complete. Results in: $OUTDIR"
c_info "Tip: grep -ri 'VULNERABLE' \"$OUTDIR\" to jump straight to findings."
