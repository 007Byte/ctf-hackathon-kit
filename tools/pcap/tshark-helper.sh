#!/usr/bin/env bash
#
# tshark-helper.sh - Common CTF tshark one-liners behind friendly subcommands.
#
# AUTHORIZED USE ONLY: Use only on CTF challenges, your own lab traffic, or
# captures you are explicitly authorised to inspect.
#
# Usage:
#   ./tshark-helper.sh <pcap> <subcommand> [args...]
#
# Subcommands:
#   proto                 Protocol hierarchy statistics (-z io,phs)
#   http                  HTTP requests (method, host, uri)
#   dns                   DNS queries and responses
#   creds                 Grep for auth headers / FTP / POST credential fields
#   objects <dir> [proto] Export objects to <dir> (proto: http|smb|tftp|imf; default http)
#   follow <n> [mode]     Follow TCP stream <n> (mode: ascii|hex|raw; default ascii)
#   ips                   Endpoint + conversation statistics
#   strings [minlen]      Extract printable strings from packet payloads (default 4)
#
# Examples:
#   ./tshark-helper.sh capture.pcap proto
#   ./tshark-helper.sh capture.pcap http
#   ./tshark-helper.sh capture.pcap objects ./loot http
#   ./tshark-helper.sh capture.pcap follow 3 ascii
#   ./tshark-helper.sh capture.pcap strings 6
#
set -euo pipefail

PROG="$(basename "$0")"

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
if ! command -v tshark >/dev/null 2>&1; then
    echo "[!] tshark not found in PATH." >&2
    echo "    Install it with one of:" >&2
    echo "      Debian/Kali : sudo apt install tshark" >&2
    echo "      Fedora      : sudo dnf install wireshark-cli" >&2
    echo "      macOS       : brew install wireshark" >&2
    exit 2
fi

usage() {
    # Print the comment header block (lines starting with '#').
    sed -n '3,33p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# Need at least: <pcap> <subcommand>
if [ "$#" -lt 2 ]; then
    usage 1
fi

PCAP="$1"
shift
SUBCMD="$1"
shift

if [ ! -f "$PCAP" ]; then
    echo "[!] PCAP file not found: $PCAP" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Subcommand dispatch
# ---------------------------------------------------------------------------
case "$SUBCMD" in
    proto)
        # Protocol hierarchy: great first look at what's in a capture.
        tshark -r "$PCAP" -q -z io,phs
        ;;

    http)
        # All HTTP requests with method, host and full URI.
        echo "[*] HTTP requests:"
        tshark -r "$PCAP" -Y "http.request" -T fields \
            -e ip.src -e http.request.method -e http.host -e http.request.uri \
            -E separator=" " 2>/dev/null
        echo
        echo "[*] HTTP responses (status / content-type):"
        tshark -r "$PCAP" -Y "http.response" -T fields \
            -e ip.src -e http.response.code -e http.content_type \
            -E separator=" " 2>/dev/null
        ;;

    dns)
        # DNS queries and answers.
        echo "[*] DNS queries:"
        tshark -r "$PCAP" -Y "dns.flags.response == 0" -T fields \
            -e ip.src -e dns.qry.name -e dns.qry.type \
            -E separator=" " 2>/dev/null
        echo
        echo "[*] DNS responses:"
        tshark -r "$PCAP" -Y "dns.flags.response == 1" -T fields \
            -e dns.qry.name -e dns.a -e dns.cname -e dns.txt \
            -E separator=" " 2>/dev/null
        ;;

    creds)
        # Best-effort cleartext credential hunt across common protocols.
        echo "[*] HTTP Basic auth headers:"
        tshark -r "$PCAP" -Y "http.authorization" -T fields \
            -e ip.src -e http.authorization 2>/dev/null || true
        echo
        echo "[*] FTP USER/PASS:"
        tshark -r "$PCAP" -Y 'ftp.request.command == "USER" || ftp.request.command == "PASS"' \
            -T fields -e ip.src -e ftp.request.command -e ftp.request.arg 2>/dev/null || true
        echo
        echo "[*] POST form data (urlencoded):"
        tshark -r "$PCAP" -Y "http.request.method == \"POST\"" -T fields \
            -e ip.src -e http.host -e http.request.uri -e urlencoded-form.key -e urlencoded-form.value \
            2>/dev/null || true
        echo
        echo "[*] Telnet data:"
        tshark -r "$PCAP" -Y "telnet" -T fields -e telnet.data 2>/dev/null || true
        echo
        echo "[*] Mail (IMAP/POP/SMTP) AUTH lines:"
        tshark -r "$PCAP" -Y "imap || pop || smtp" -T fields \
            -e ip.src -e imap.request -e pop.request -e smtp.req.parameter 2>/dev/null || true
        ;;

    objects)
        # Export transferred objects (files) to a directory.
        OUTDIR="${1:-exported_objects}"
        PROTO="${2:-http}"   # http | smb | tftp | imf | dicom
        mkdir -p "$OUTDIR"
        echo "[*] Exporting '$PROTO' objects to: $OUTDIR"
        tshark -r "$PCAP" --export-objects "$PROTO,$OUTDIR" -q
        echo "[*] Done. Contents:"
        ls -la "$OUTDIR"
        ;;

    follow)
        # Follow / reassemble a TCP stream by its index number.
        if [ "$#" -lt 1 ]; then
            echo "[!] Usage: $PROG <pcap> follow <stream-number> [ascii|hex|raw]" >&2
            exit 1
        fi
        STREAM="$1"
        MODE="${2:-ascii}"
        echo "[*] Following TCP stream $STREAM (mode: $MODE):"
        tshark -r "$PCAP" -q -z "follow,tcp,$MODE,$STREAM"
        ;;

    ips)
        # Endpoint and conversation statistics.
        echo "[*] IPv4 endpoints:"
        tshark -r "$PCAP" -q -z endpoints,ip
        echo
        echo "[*] IPv4 conversations:"
        tshark -r "$PCAP" -q -z conv,ip
        ;;

    strings)
        # Extract printable strings from packet data payloads.
        MINLEN="${1:-4}"
        echo "[*] Printable strings (min length $MINLEN) from packet payloads:"
        # Pull hex of the data field, convert to bytes, run strings over it.
        tshark -r "$PCAP" -T fields -e data 2>/dev/null \
            | tr -d '\n' \
            | { xxd -r -p 2>/dev/null || true; } \
            | { command -v strings >/dev/null 2>&1 && strings -n "$MINLEN" \
                || tr -c '[:print:]' '\n'; }
        ;;

    -h|--help|help)
        usage 0
        ;;

    *)
        echo "[!] Unknown subcommand: $SUBCMD" >&2
        echo >&2
        usage 1
        ;;
esac
