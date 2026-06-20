#!/usr/bin/env bash
#
# web-enum.sh - focused web-application enumeration helper
# -----------------------------------------------------------------------------
# Given a base URL it will:
#   1. Fingerprint the app with whatweb.
#   2. Grab HTTP response headers (curl -I).
#   3. Fetch robots.txt and sitemap.xml.
#   4. Directory/content fuzz with ffuf (preferred) or gobuster (fallback)
#      against a SecLists wordlist (sensible default, override via flag/env).
#   5. Optionally fuzz virtual hosts / subdomains (Host: header fuzzing).
#
# All output is written into a results folder for later review.
#
# -----------------------------------------------------------------------------
# AUTHORIZED USE ONLY: Use against CTF/lab targets or systems you are explicitly
# permitted to test. Active web fuzzing is intrusive and may be logged/blocked.
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./web-enum.sh <url> [output_dir] [-w wordlist] [-d domain_for_vhost]
#
# EXAMPLES:
#   ./web-enum.sh http://10.10.10.5
#   ./web-enum.sh https://target.htb ./web-results
#   ./web-enum.sh http://target.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
#   ./web-enum.sh http://target.htb -d target.htb        # also do vhost fuzzing
#
# ENV OVERRIDES:
#   SECLISTS_WORDLIST   - default content-discovery wordlist
#   VHOST_WORDLIST      - default vhost/subdomain wordlist
# -----------------------------------------------------------------------------

set -euo pipefail

c_reset='\033[0m'; c_blue='\033[1;34m'; c_green='\033[1;32m'
c_yellow='\033[1;33m'; c_red='\033[1;31m'
info()  { echo -e "${c_blue}[*]${c_reset} $*"; }
ok()    { echo -e "${c_green}[+]${c_reset} $*"; }
warn()  { echo -e "${c_yellow}[!]${c_reset} $*" >&2; }
err()   { echo -e "${c_red}[-]${c_reset} $*" >&2; }

have() {
    command -v "$1" >/dev/null 2>&1 && return 0
    warn "Tool '$1' not found - skipping its step."
    return 1
}

usage() { sed -n '2,40p' "$0"; exit "${1:-0}"; }

# --- defaults ---
WORDLIST="${SECLISTS_WORDLIST:-/usr/share/seclists/Discovery/Web-Content/common.txt}"
VHOST_WORDLIST="${VHOST_WORDLIST:-/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt}"
VHOST_DOMAIN=""
URL=""
OUTDIR=""

# --- parse args: first non-flag is URL, second non-flag is OUTDIR ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage 0;;
        -w|--wordlist) WORDLIST="$2"; shift 2;;
        -d|--domain)   VHOST_DOMAIN="$2"; shift 2;;
        -*)
            err "Unknown option: $1"; usage 1;;
        *)
            if [[ -z "$URL" ]]; then URL="$1"
            elif [[ -z "$OUTDIR" ]]; then OUTDIR="$1"
            else warn "Ignoring extra argument: $1"; fi
            shift;;
    esac
done

[[ -z "$URL" ]] && { err "No URL supplied."; usage 1; }

# Normalize: ensure scheme is present.
[[ "$URL" =~ ^https?:// ]] || URL="http://$URL"
# Strip trailing slash for consistency.
URL="${URL%/}"

SAFE="${URL//[^A-Za-z0-9]/_}"
OUTDIR="${OUTDIR:-./web-${SAFE}-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUTDIR"

info "URL:        $URL"
info "Wordlist:   $WORDLIST"
info "Results:    $OUTDIR"

# -----------------------------------------------------------------------------
# 1. whatweb fingerprint
# -----------------------------------------------------------------------------
if have whatweb; then
    info "Fingerprinting with whatweb..."
    whatweb -a 3 "$URL" 2>&1 | tee "$OUTDIR/whatweb.txt" || warn "whatweb failed."
fi

# -----------------------------------------------------------------------------
# 2 + 3. Headers, robots.txt, sitemap.xml (need curl)
# -----------------------------------------------------------------------------
if have curl; then
    info "Grabbing response headers..."
    curl -sS -k -I -L "$URL/" 2>&1 | tee "$OUTDIR/headers.txt" || warn "Header grab failed."

    info "Fetching robots.txt..."
    curl -sS -k -L "$URL/robots.txt" -o "$OUTDIR/robots.txt" 2>/dev/null \
        && [[ -s "$OUTDIR/robots.txt" ]] && cat "$OUTDIR/robots.txt" || warn "No robots.txt (or empty)."

    info "Fetching sitemap.xml..."
    curl -sS -k -L "$URL/sitemap.xml" -o "$OUTDIR/sitemap.xml" 2>/dev/null \
        && [[ -s "$OUTDIR/sitemap.xml" ]] && ok "sitemap.xml saved." || warn "No sitemap.xml (or empty)."
else
    warn "curl missing - skipping headers/robots/sitemap."
fi

# -----------------------------------------------------------------------------
# 4. Directory / content discovery
# -----------------------------------------------------------------------------
if [[ ! -f "$WORDLIST" ]]; then
    warn "Wordlist not found at: $WORDLIST"
    warn "Override with -w <path> or SECLISTS_WORDLIST env var. Skipping content fuzzing."
else
    if have ffuf; then
        info "Directory fuzzing with ffuf..."
        # -mc: match these status codes; -ac: auto-calibrate to filter junk;
        # -c: colorized; -of csv writes a machine-readable copy.
        ffuf -w "$WORDLIST" -u "$URL/FUZZ" \
            -mc 200,204,301,302,307,401,403,405 -ac -c \
            -of csv -o "$OUTDIR/ffuf.csv" 2>&1 | tee "$OUTDIR/ffuf.txt" || warn "ffuf failed."
    elif have gobuster; then
        info "Directory fuzzing with gobuster..."
        # -k: skip TLS verification (self-signed CTF certs); -o: output file.
        gobuster dir -u "$URL" -w "$WORDLIST" -k -t 40 \
            -o "$OUTDIR/gobuster.txt" 2>&1 | tee "$OUTDIR/gobuster.log" || warn "gobuster failed."
    else
        warn "Neither ffuf nor gobuster found - skipping directory fuzzing."
    fi
fi

# -----------------------------------------------------------------------------
# 5. Optional vhost / subdomain fuzzing (only when -d <domain> is given)
# -----------------------------------------------------------------------------
if [[ -n "$VHOST_DOMAIN" ]]; then
    if [[ ! -f "$VHOST_WORDLIST" ]]; then
        warn "vhost wordlist not found at: $VHOST_WORDLIST - skipping vhost fuzzing."
    elif have ffuf; then
        info "Vhost fuzzing for *.$VHOST_DOMAIN (filter false positives with -ac)..."
        ffuf -w "$VHOST_WORDLIST" -u "$URL/" \
            -H "Host: FUZZ.$VHOST_DOMAIN" -ac -c \
            -of csv -o "$OUTDIR/vhosts.csv" 2>&1 | tee "$OUTDIR/vhosts.txt" || warn "vhost ffuf failed."
    elif have gobuster; then
        info "Vhost fuzzing with gobuster..."
        gobuster vhost -u "$URL" -w "$VHOST_WORDLIST" -k --append-domain \
            -o "$OUTDIR/vhosts.txt" 2>&1 | tee "$OUTDIR/vhosts.log" || warn "vhost gobuster failed."
    else
        warn "No ffuf/gobuster for vhost fuzzing - skipping."
    fi
fi

ok "Web enumeration complete. Artifacts in: $OUTDIR"
