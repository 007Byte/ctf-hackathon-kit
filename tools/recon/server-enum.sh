#!/usr/bin/env bash
###############################################################################
# server-enum.sh - Deep multi-service enumeration orchestrator
#
# Part of the CY5770 Hackathon recon toolkit. This tool COMPLEMENTS (does not
# replace) the basic scripts in ../../scripts/recon/ (auto-recon.sh,
# web-enum.sh, port-scan.py, subdomain-enum.py, flag-finder.sh). It performs a
# quick port discovery pass and then runs DEEP, per-service enumeration for
# each open port, writing one output file per service.
#
# AUTHORIZED TARGETS ONLY. Only run this against systems you own or have
# explicit written permission to test. Unauthorized scanning/enumeration is
# illegal in most jurisdictions.
#
# USAGE:
#   ./server-enum.sh <target> [results_dir]
#
#   <target>        IP address or hostname of the authorized target.
#   [results_dir]   Optional output directory (default: ./server-enum-<target>-<ts>)
#
# EXAMPLES:
#   ./server-enum.sh 10.10.10.5
#   ./server-enum.sh target.htb /tmp/recon-target
#
# DEPENDENCIES (each is optional - missing tools are warned about and skipped):
#   nmap, dig, whatweb, curl, smbclient, smbmap, enum4linux-ng/enum4linux,
#   snmpwalk, ldapsearch, showmount, mysql, psql, redis-cli, mongosh/mongo,
#   nc (netcat). Falls back to ../../scripts/recon/port-scan.py if nmap missing.
###############################################################################

set -u  # treat unset variables as an error (but NOT -e: we want to continue past failures)

# ---------------------------------------------------------------------------
# Locate ourselves and the sibling basic-recon scripts directory
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASIC_RECON_DIR="$(cd "${SCRIPT_DIR}/../../scripts/recon" 2>/dev/null && pwd || echo "")"

# ---------------------------------------------------------------------------
# Colors (disabled if not a TTY)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    C_RESET="\033[0m"; C_RED="\033[31m"; C_GRN="\033[32m"
    C_YEL="\033[33m"; C_BLU="\033[34m"; C_CYN="\033[36m"; C_BOLD="\033[1m"
else
    C_RESET=""; C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_CYN=""; C_BOLD=""
fi

log()   { echo -e "${C_BLU}[*]${C_RESET} $*"; }
ok()    { echo -e "${C_GRN}[+]${C_RESET} $*"; }
warn()  { echo -e "${C_YEL}[!]${C_RESET} $*"; }
err()   { echo -e "${C_RED}[-]${C_RESET} $*" >&2; }
phase() { echo -e "\n${C_BOLD}${C_CYN}===== $* =====${C_RESET}"; }

# Check whether a command exists on PATH.
have() { command -v "$1" >/dev/null 2>&1; }

# Run a command only if its binary exists; otherwise warn and skip.
# Usage: run_if <binary> <description> -- <command...>
run_if() {
    local bin="$1"; local desc="$2"; shift 2
    [ "$1" = "--" ] && shift
    if have "$bin"; then
        log "Running: $desc"
        "$@"
    else
        warn "'$bin' not installed - skipping: $desc"
        return 127
    fi
}

# ---------------------------------------------------------------------------
# Usage / argument parsing
# ---------------------------------------------------------------------------
usage() {
    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

[ $# -lt 1 ] && { err "No target supplied."; usage 1; }
case "$1" in -h|--help) usage 0 ;; esac

TARGET="$1"
TS="$(date +%Y%m%d-%H%M%S)"
OUTDIR="${2:-./server-enum-${TARGET}-${TS}}"
mkdir -p "$OUTDIR" || { err "Cannot create output dir: $OUTDIR"; exit 1; }

# Track findings for the final summary.
FOUND_SERVICES=()
FOLLOWUPS=()
note_found()    { FOUND_SERVICES+=("$1"); }
note_followup() { FOLLOWUPS+=("$1"); }

phase "DEEP SERVER ENUMERATION :: target=${TARGET}"
log "Output directory: ${OUTDIR}"
log "Basic-recon scripts dir: ${BASIC_RECON_DIR:-<not found>}"
warn "AUTHORIZED TARGETS ONLY. Ensure you have written permission to test ${TARGET}."

###############################################################################
# STEP 1: Quick port discovery
###############################################################################
phase "STEP 1: Port discovery"
OPEN_PORTS=""
PORTSCAN_OUT="${OUTDIR}/00-portscan.txt"

if have nmap; then
    log "Using nmap for quick TCP discovery (top common ports + service/version)."
    # -Pn: skip host discovery (CTF boxes often block ping)
    # -sV: version detection so deeper modules can be smarter
    # --open: only report open ports
    nmap -Pn -sV --open \
         -p 21,22,25,53,80,110,139,143,161,389,443,445,587,2049,3306,3389,5432,6379,8080,27017 \
         "$TARGET" -oN "$PORTSCAN_OUT" 2>&1 | tee -a "$PORTSCAN_OUT" >/dev/null
    # Parse "PORT/tcp open" lines into a comma list of port numbers.
    OPEN_PORTS="$(grep -E '^[0-9]+/tcp[[:space:]]+open' "$PORTSCAN_OUT" \
                  | awk -F'/' '{print $1}' | sort -un | tr '\n' ' ')"
elif [ -n "$BASIC_RECON_DIR" ] && [ -f "${BASIC_RECON_DIR}/port-scan.py" ] && have python3; then
    warn "nmap not found - falling back to existing port-scan.py"
    python3 "${BASIC_RECON_DIR}/port-scan.py" "$TARGET" 2>&1 | tee "$PORTSCAN_OUT"
    # Be liberal in parsing: pull any 'NNN open' / 'NNN/tcp' style tokens.
    OPEN_PORTS="$(grep -oE '[0-9]{1,5}(/tcp)?[[:space:]]+(open|OPEN)' "$PORTSCAN_OUT" \
                  | grep -oE '^[0-9]{1,5}' | sort -un | tr '\n' ' ')"
else
    err "Neither nmap nor port-scan.py is available. Cannot discover ports."
    err "Install nmap (apt install nmap) or ensure ${BASIC_RECON_DIR}/port-scan.py exists."
    exit 1
fi

if [ -z "${OPEN_PORTS// /}" ]; then
    warn "No open ports detected on the scanned set. Nothing to enumerate."
    warn "Consider a full-range scan: nmap -Pn -p- ${TARGET}"
    exit 0
fi
ok "Open ports: ${OPEN_PORTS}"

# Helper: is a given port in the discovered open list?
port_open() {
    local p="$1"
    for op in $OPEN_PORTS; do [ "$op" = "$p" ] && return 0; done
    return 1
}

# Helper: grab a raw banner from a TCP port (best-effort, 5s timeout).
grab_banner() {
    local port="$1"; local out="$2"
    if have nc; then
        # -w timeout works on both traditional and openbsd netcat
        (echo "" | nc -w 5 "$TARGET" "$port") >"$out" 2>/dev/null
    elif have python3; then
        python3 - "$TARGET" "$port" >"$out" 2>/dev/null <<'PY'
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
try:
    s = socket.create_connection((host, port), timeout=5)
    s.settimeout(5)
    print(s.recv(2048).decode(errors="replace"))
    s.close()
except Exception as e:
    print(f"[banner grab failed: {e}]")
PY
    else
        echo "[no nc/python3 available for banner grab]" >"$out"
    fi
}

###############################################################################
# STEP 2: Per-service deep enumeration
###############################################################################
phase "STEP 2: Per-service deep enumeration"

# ---- 21 FTP ---------------------------------------------------------------
if port_open 21; then
    O="${OUTDIR}/ftp-21.txt"; note_found "FTP (21)"
    log "FTP detected -> ${O}"
    {
        echo "=== FTP banner ==="
        grab_banner 21 /dev/stdout
        echo; echo "=== Anonymous login check ==="
    } >"$O" 2>&1
    if have curl; then
        # List the root via anonymous; non-zero exit just means it failed.
        curl -s --connect-timeout 8 --max-time 20 "ftp://anonymous:anonymous@${TARGET}/" >>"$O" 2>&1 \
            && ok "Anonymous FTP listing succeeded (see $O)" \
            && note_followup "FTP anonymous login WORKS on ${TARGET}:21 - download files." \
            || warn "Anonymous FTP listing failed or empty."
    else
        warn "curl missing - cannot test anonymous FTP."
    fi
    have nmap && nmap -Pn -p21 --script ftp-anon,ftp-syst "$TARGET" >>"$O" 2>&1
fi

# ---- 22 SSH ---------------------------------------------------------------
if port_open 22; then
    O="${OUTDIR}/ssh-22.txt"; note_found "SSH (22)"
    log "SSH detected -> ${O}"
    {
        echo "=== SSH banner ==="
        grab_banner 22 /dev/stdout
    } >"$O" 2>&1
    if have ssh; then
        echo -e "\n=== Supported auth methods ===" >>"$O"
        # 'none' auth is rejected but the server replies with permitted methods.
        ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=8 \
            -o PreferredAuthentications=none "invaliduser@${TARGET}" 2>>"$O" || true
    fi
    if have nmap; then
        echo -e "\n=== Algorithms / host keys / auth (nmap) ===" >>"$O"
        nmap -Pn -p22 --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods "$TARGET" >>"$O" 2>&1
    fi
    note_followup "SSH on ${TARGET}:22 - try found creds; check for weak/old algos."
fi

# ---- 25 / 587 SMTP --------------------------------------------------------
for SMTP_PORT in 25 587; do
    if port_open "$SMTP_PORT"; then
        O="${OUTDIR}/smtp-${SMTP_PORT}.txt"; note_found "SMTP (${SMTP_PORT})"
        log "SMTP detected on ${SMTP_PORT} -> ${O}"
        { echo "=== SMTP banner ==="; grab_banner "$SMTP_PORT" /dev/stdout; } >"$O" 2>&1
        echo -e "\n=== VRFY / EXPN user enumeration attempt ===" >>"$O"
        if have nc; then
            for u in root admin administrator postmaster test user www-data; do
                printf 'VRFY %s\r\nEXPN %s\r\nQUIT\r\n' "$u" "$u" \
                    | nc -w 5 "$TARGET" "$SMTP_PORT" 2>/dev/null \
                    | sed "s/^/[$u] /" >>"$O"
            done
        else
            warn "nc missing - skipping VRFY/EXPN."
        fi
        have nmap && nmap -Pn -p"$SMTP_PORT" --script smtp-commands,smtp-enum-users,smtp-open-relay "$TARGET" >>"$O" 2>&1
        note_followup "SMTP on ${TARGET}:${SMTP_PORT} - check VRFY/EXPN output for valid users / open relay."
    fi
done

# ---- 53 DNS ---------------------------------------------------------------
if port_open 53; then
    O="${OUTDIR}/dns-53.txt"; note_found "DNS (53)"
    log "DNS detected -> ${O}"
    if have dig; then
        {
            echo "=== version.bind (CHAOS TXT) ==="
            dig @"$TARGET" version.bind CHAOS TXT +short
            echo; echo "=== Zone transfer attempt (AXFR) ==="
            # We don't know the zone; try the target name itself and a couple guesses.
            for ZONE in "$TARGET" "$(echo "$TARGET" | cut -d. -f2-)"; do
                [ -z "$ZONE" ] && continue
                echo "--- AXFR for zone: ${ZONE} ---"
                dig @"$TARGET" "$ZONE" AXFR +time=5 +tries=1
            done
        } >"$O" 2>&1
        grep -q "Transfer failed\|connection timed out\|; Transfer" "$O" || true
        if grep -qiE "XFR size|IN[[:space:]]+SOA" "$O"; then
            ok "Possible zone transfer data captured (see $O)"
            note_followup "DNS AXFR on ${TARGET} may have leaked records - review dns-53.txt."
        fi
    else
        warn "dig missing - install dnsutils/bind-utils."
    fi
fi

# ---- 80 / 443 / 8080 HTTP(S) ---------------------------------------------
for HP in 80 443 8080; do
    if port_open "$HP"; then
        case "$HP" in 443) SCHEME="https" ;; *) SCHEME="http" ;; esac
        URL="${SCHEME}://${TARGET}:${HP}/"
        O="${OUTDIR}/http-${HP}.txt"; note_found "HTTP(S) (${HP})"
        log "Web service on ${HP} -> ${O}  (${URL})"
        {
            echo "=== Target URL: ${URL} ==="
            echo; echo "=== Response headers (curl -I) ==="
        } >"$O"
        if have curl; then
            curl -sk -I --connect-timeout 8 --max-time 20 "$URL" >>"$O" 2>&1
            echo -e "\n=== Page title ===" >>"$O"
            curl -sk --max-time 20 "$URL" 2>/dev/null \
                | grep -oiE '<title>[^<]*</title>' | head -n1 >>"$O"
            echo -e "\n=== robots.txt ===" >>"$O"
            curl -sk --max-time 15 "${SCHEME}://${TARGET}:${HP}/robots.txt" >>"$O" 2>&1
        else
            warn "curl missing - limited HTTP enumeration."
        fi
        echo -e "\n=== whatweb fingerprint ===" >>"$O"
        run_if whatweb "whatweb on ${URL}" -- whatweb -a 3 "$URL" >>"$O" 2>&1 || true
        echo -e "\n=== nmap http NSE ===" >>"$O"
        have nmap && nmap -Pn -p"$HP" --script http-title,http-headers,http-methods,http-robots.txt "$TARGET" >>"$O" 2>&1
        # Point the operator at the deeper, dedicated web tools.
        if [ -n "$BASIC_RECON_DIR" ] && [ -f "${BASIC_RECON_DIR}/web-enum.sh" ]; then
            note_followup "Web on ${URL} - run dir/vhost fuzzing: ${BASIC_RECON_DIR}/web-enum.sh ${URL}"
        fi
        note_followup "Web on ${URL} - deep HTTP recon: ${SCRIPT_DIR}/http-recon.py ${URL}"
    fi
done

# ---- 110 POP3 / 143 IMAP --------------------------------------------------
for MP in 110 143; do
    if port_open "$MP"; then
        case "$MP" in 110) SVC="POP3" ;; 143) SVC="IMAP" ;; esac
        O="${OUTDIR}/mail-${MP}.txt"; note_found "${SVC} (${MP})"
        log "${SVC} detected on ${MP} -> ${O}"
        { echo "=== ${SVC} banner ==="; grab_banner "$MP" /dev/stdout; } >"$O" 2>&1
        have nmap && nmap -Pn -p"$MP" --script "${SVC,,}-capabilities" "$TARGET" >>"$O" 2>&1
        note_followup "${SVC} on ${TARGET}:${MP} - try found creds for mailbox access."
    fi
done

# ---- 139 / 445 SMB --------------------------------------------------------
if port_open 139 || port_open 445; then
    O="${OUTDIR}/smb.txt"; note_found "SMB (139/445)"
    log "SMB detected -> ${O}"
    {
        echo "=== SMB DEEP ENUM for ${TARGET} ==="
        echo "(For focused/credentialed SMB work use: ${SCRIPT_DIR}/smb-enum.sh)"
    } >"$O"

    # Prefer enum4linux-ng, fall back to classic enum4linux.
    if have enum4linux-ng; then
        echo -e "\n=== enum4linux-ng -A (all modules) ===" >>"$O"
        enum4linux-ng -A "$TARGET" >>"$O" 2>&1
    elif have enum4linux; then
        echo -e "\n=== enum4linux -a (all modules) ===" >>"$O"
        enum4linux -a "$TARGET" >>"$O" 2>&1
    else
        warn "Neither enum4linux-ng nor enum4linux installed - skipping AD/Samba enum."
    fi

    # Null + guest share listing via smbclient.
    if have smbclient; then
        echo -e "\n=== smbclient share list (null session) ===" >>"$O"
        smbclient -L "//${TARGET}/" -N >>"$O" 2>&1
        echo -e "\n=== smbclient share list (guest) ===" >>"$O"
        smbclient -L "//${TARGET}/" -U "guest%" >>"$O" 2>&1
    else
        warn "smbclient missing - skipping share listing."
    fi

    # smbmap for read/write permission mapping.
    if have smbmap; then
        echo -e "\n=== smbmap (null session) ===" >>"$O"
        smbmap -H "$TARGET" -u "" -p "" >>"$O" 2>&1
        echo -e "\n=== smbmap (guest) ===" >>"$O"
        smbmap -H "$TARGET" -u "guest" -p "" >>"$O" 2>&1
    else
        warn "smbmap missing - skipping permission mapping."
    fi

    # MS17-010 (EternalBlue) safe check.
    if have nmap; then
        echo -e "\n=== nmap smb-vuln-ms17-010 ===" >>"$O"
        nmap -Pn -p445 --script smb-vuln-ms17-010 "$TARGET" >>"$O" 2>&1
        grep -qi "VULNERABLE" "$O" && note_followup "SMB MS17-010 may be VULNERABLE on ${TARGET} - investigate."
    fi
    note_followup "SMB on ${TARGET} - deep/credentialed enum: ${SCRIPT_DIR}/smb-enum.sh -t ${TARGET}"
fi

# ---- 161 SNMP -------------------------------------------------------------
if port_open 161; then
    O="${OUTDIR}/snmp-161.txt"; note_found "SNMP (161)"
    log "SNMP detected -> ${O}"
    if have snmpwalk; then
        echo "=== snmpwalk public (SNMPv2c) ===" >"$O"
        # -Cc keeps walking past errors; common public community string.
        snmpwalk -v2c -c public -t 5 -r 1 "$TARGET" >>"$O" 2>&1
        # Also try v1 in case the device is old.
        echo -e "\n=== snmpwalk public (SNMPv1) ===" >>"$O"
        snmpwalk -v1 -c public -t 5 -r 1 "$TARGET" >>"$O" 2>&1
        [ -s "$O" ] && grep -qiE "STRING|INTEGER|Hex-STRING" "$O" \
            && note_followup "SNMP public community READABLE on ${TARGET} - mine for users/processes/software."
    else
        warn "snmpwalk missing - install snmp/snmp-utils."
    fi
fi

# ---- 389 LDAP -------------------------------------------------------------
if port_open 389; then
    O="${OUTDIR}/ldap-389.txt"; note_found "LDAP (389)"
    log "LDAP detected -> ${O}"
    if have ldapsearch; then
        echo "=== Anonymous RootDSE query ===" >"$O"
        # -x simple auth, -s base reads the RootDSE to learn naming contexts.
        ldapsearch -x -H "ldap://${TARGET}" -s base -b "" \
            namingContexts defaultNamingContext >>"$O" 2>&1
        # Try a full anonymous dump of the first naming context if exposed.
        NC="$(grep -i 'namingContexts:' "$O" | head -n1 | cut -d: -f2- | tr -d ' \r')"
        if [ -n "$NC" ]; then
            echo -e "\n=== Anonymous base dump of ${NC} ===" >>"$O"
            ldapsearch -x -H "ldap://${TARGET}" -b "$NC" >>"$O" 2>&1
            note_followup "LDAP anonymous bind exposes ${NC} on ${TARGET} - harvest users/objects."
        fi
    else
        warn "ldapsearch missing - install ldap-utils/openldap-clients."
    fi
fi

# ---- 2049 NFS -------------------------------------------------------------
if port_open 2049; then
    O="${OUTDIR}/nfs-2049.txt"; note_found "NFS (2049)"
    log "NFS detected -> ${O}"
    if have showmount; then
        echo "=== showmount -e (exports) ===" >"$O"
        showmount -e "$TARGET" >>"$O" 2>&1
        grep -qE '/' "$O" && note_followup "NFS exports found on ${TARGET} - mount and inspect (mount -t nfs)."
    else
        warn "showmount missing - install nfs-common/nfs-utils."
    fi
    have nmap && nmap -Pn -p2049 --script nfs-showmount,nfs-ls,nfs-statfs "$TARGET" >>"$O" 2>&1
fi

# ---- 3306 MySQL -----------------------------------------------------------
if port_open 3306; then
    O="${OUTDIR}/mysql-3306.txt"; note_found "MySQL (3306)"
    log "MySQL detected -> ${O}"
    { echo "=== MySQL banner ==="; grab_banner 3306 /dev/stdout; } >"$O" 2>&1
    if have mysql; then
        echo -e "\n=== Unauth access check (root, no password) ===" >>"$O"
        mysql -h "$TARGET" -u root --connect-timeout=8 -e "SELECT version();" >>"$O" 2>&1 \
            && note_followup "MySQL root LOGIN WITHOUT PASSWORD on ${TARGET}!" || true
    fi
    have nmap && nmap -Pn -p3306 --script mysql-info,mysql-empty-password "$TARGET" >>"$O" 2>&1
fi

# ---- 5432 PostgreSQL ------------------------------------------------------
if port_open 5432; then
    O="${OUTDIR}/postgres-5432.txt"; note_found "PostgreSQL (5432)"
    log "PostgreSQL detected -> ${O}"
    echo "=== PostgreSQL unauth check ===" >"$O"
    if have psql; then
        # Try default postgres/postgres and trust auth.
        PGCONNECT_TIMEOUT=8 PGPASSWORD=postgres psql -h "$TARGET" -U postgres -c "SELECT version();" >>"$O" 2>&1 \
            && note_followup "PostgreSQL login postgres:postgres works on ${TARGET}!" || true
    else
        warn "psql missing - install postgresql-client."
    fi
    have nmap && nmap -Pn -p5432 --script pgsql-brute "$TARGET" >>"$O" 2>&1 || true
fi

# ---- 6379 Redis -----------------------------------------------------------
if port_open 6379; then
    O="${OUTDIR}/redis-6379.txt"; note_found "Redis (6379)"
    log "Redis detected -> ${O}"
    echo "=== Redis unauth INFO ===" >"$O"
    if have redis-cli; then
        redis-cli -h "$TARGET" --connect-timeout 8 INFO server >>"$O" 2>&1 \
            && note_followup "Redis UNAUTHENTICATED access on ${TARGET} - check keys, RCE via module/cron." || true
    else
        # Fall back to raw protocol PING/INFO over nc.
        if have nc; then
            printf 'INFO\r\n' | nc -w 6 "$TARGET" 6379 >>"$O" 2>&1
        else
            warn "redis-cli and nc both missing - skipping Redis."
        fi
    fi
    have nmap && nmap -Pn -p6379 --script redis-info "$TARGET" >>"$O" 2>&1
fi

# ---- 27017 MongoDB --------------------------------------------------------
if port_open 27017; then
    O="${OUTDIR}/mongodb-27017.txt"; note_found "MongoDB (27017)"
    log "MongoDB detected -> ${O}"
    echo "=== MongoDB unauth check ===" >"$O"
    if have mongosh; then
        mongosh --host "$TARGET" --quiet --eval "db.adminCommand('listDatabases')" >>"$O" 2>&1 \
            && note_followup "MongoDB UNAUTHENTICATED on ${TARGET} - dump databases." || true
    elif have mongo; then
        mongo --host "$TARGET" --quiet --eval "db.adminCommand('listDatabases')" >>"$O" 2>&1 \
            && note_followup "MongoDB UNAUTHENTICATED on ${TARGET} - dump databases." || true
    else
        warn "mongosh/mongo missing - skipping Mongo."
    fi
    have nmap && nmap -Pn -p27017 --script mongodb-info,mongodb-databases "$TARGET" >>"$O" 2>&1
fi

# ---- 3389 RDP -------------------------------------------------------------
if port_open 3389; then
    O="${OUTDIR}/rdp-3389.txt"; note_found "RDP (3389)"
    log "RDP detected -> ${O}"
    if have nmap; then
        echo "=== nmap RDP scripts ===" >"$O"
        nmap -Pn -p3389 --script rdp-enum-encryption,rdp-ntlm-info "$TARGET" >>"$O" 2>&1
        grep -qi "CVE-2019-0708\|BlueKeep" "$O" && note_followup "RDP BlueKeep indicators on ${TARGET}."
    else
        warn "nmap missing - skipping RDP scripts."
    fi
    note_followup "RDP on ${TARGET}:3389 - try found creds (xfreerdp/rdesktop)."
fi

###############################################################################
# STEP 3: Final summary
###############################################################################
phase "STEP 3: Summary"
ok "Enumeration complete. Results saved under: ${OUTDIR}"

echo -e "\n${C_BOLD}Services enumerated:${C_RESET}"
if [ "${#FOUND_SERVICES[@]}" -eq 0 ]; then
    echo "  (none)"
else
    for s in "${FOUND_SERVICES[@]}"; do echo "  - $s"; done
fi

echo -e "\n${C_BOLD}Suggested follow-ups:${C_RESET}"
if [ "${#FOLLOWUPS[@]}" -eq 0 ]; then
    echo "  (no high-signal follow-ups auto-detected; review per-service files)"
else
    for f in "${FOLLOWUPS[@]}"; do echo -e "  ${C_YEL}->${C_RESET} $f"; done
fi

echo -e "\n${C_BOLD}Output files:${C_RESET}"
ls -1 "$OUTDIR" | sed 's/^/  /'

echo
log "Reminder: stay within authorized scope. Happy hunting."
