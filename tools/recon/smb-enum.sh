#!/usr/bin/env bash
###############################################################################
# smb-enum.sh - Focused SMB / NetBIOS enumeration tool
#
# Part of the CY5770 Hackathon recon toolkit. Goes deeper on SMB than the
# generic server-enum.sh: supports null, guest, and credentialed sessions;
# lists and spiders readable shares; enumerates users/groups/password policy;
# does RID cycling as a fallback; and checks for common SMB vulns (MS17-010).
#
# Uses enum4linux-ng if present (preferred), else falls back to enum4linux,
# plus smbclient / smbmap / rpcclient / nmap NSE.
#
# AUTHORIZED TARGETS ONLY. Only run against hosts you own or are explicitly
# permitted to test. Unauthorized access is illegal.
#
# USAGE:
#   ./smb-enum.sh -t <target> [-u user] [-p pass] [-d domain] [-o outdir]
#                 [-s] [-S] [-h]
#
#   -t <target>   Target IP / hostname               (REQUIRED)
#   -u <user>     Username for a credentialed session (default: null session)
#   -p <pass>     Password for the user               (default: empty)
#   -d <domain>   Domain / workgroup                  (optional)
#   -o <outdir>   Output directory                    (default: ./smb-enum-<target>-<ts>)
#   -s            Spider/list contents of readable shares (recursive listing)
#   -S            Skip the slower RID-cycling step
#   -h            Show this help
#
# EXAMPLES:
#   ./smb-enum.sh -t 10.10.10.5
#   ./smb-enum.sh -t 10.10.10.5 -u guest -p ''
#   ./smb-enum.sh -t dc01.corp.local -u jdoe -p 'P@ss' -d CORP -s
#
# DEPENDENCIES (missing tools warned + skipped):
#   enum4linux-ng or enum4linux, smbclient, smbmap, rpcclient, nmap, nmblookup
###############################################################################

set -u

# ---------------------------------------------------------------------------
# Pretty output helpers
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
have()  { command -v "$1" >/dev/null 2>&1; }

usage() { sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

# ---------------------------------------------------------------------------
# Argument parsing (getopts)
# ---------------------------------------------------------------------------
TARGET=""; USER=""; PASS=""; DOMAIN=""; OUTDIR=""
DO_SPIDER=0; SKIP_RID=0

while getopts ":t:u:p:d:o:sSh" opt; do
    case "$opt" in
        t) TARGET="$OPTARG" ;;
        u) USER="$OPTARG" ;;
        p) PASS="$OPTARG" ;;
        d) DOMAIN="$OPTARG" ;;
        o) OUTDIR="$OPTARG" ;;
        s) DO_SPIDER=1 ;;
        S) SKIP_RID=1 ;;
        h) usage 0 ;;
        \?) err "Unknown option: -$OPTARG"; usage 1 ;;
        :)  err "Option -$OPTARG requires an argument."; usage 1 ;;
    esac
done

[ -z "$TARGET" ] && { err "Target (-t) is required."; usage 1; }

TS="$(date +%Y%m%d-%H%M%S)"
OUTDIR="${OUTDIR:-./smb-enum-${TARGET}-${TS}}"
mkdir -p "$OUTDIR" || { err "Cannot create output dir: $OUTDIR"; exit 1; }

# Build the credential flavour string for messages and decide auth mode.
if [ -n "$USER" ]; then
    AUTH_DESC="credentialed (user='${USER}')"
    SMBCLIENT_AUTH=(-U "${DOMAIN:+${DOMAIN}\\}${USER}%${PASS}")
    SMBMAP_AUTH=(-u "$USER" -p "$PASS")
    [ -n "$DOMAIN" ] && SMBMAP_AUTH+=(-d "$DOMAIN")
    RPC_AUTH=(-U "${USER}%${PASS}")
else
    AUTH_DESC="null session (anonymous)"
    SMBCLIENT_AUTH=(-N)
    SMBMAP_AUTH=(-u "" -p "")
    RPC_AUTH=(-N)
fi

phase "FOCUSED SMB ENUMERATION :: target=${TARGET}"
log "Auth mode: ${AUTH_DESC}"
[ -n "$DOMAIN" ] && log "Domain/workgroup: ${DOMAIN}"
log "Output directory: ${OUTDIR}"
warn "AUTHORIZED TARGETS ONLY. Confirm permission to test ${TARGET}."

###############################################################################
# 1. NetBIOS / name info
###############################################################################
phase "1. NetBIOS / host info"
O="${OUTDIR}/01-netbios.txt"
if have nmblookup; then
    log "nmblookup -A ${TARGET}"
    nmblookup -A "$TARGET" | tee "$O"
else
    warn "nmblookup missing - skipping NetBIOS name lookup."
fi

###############################################################################
# 2. enum4linux(-ng) - the heavy lifter (users, groups, policy, shares, OS)
###############################################################################
phase "2. enum4linux(-ng) full enumeration"
O="${OUTDIR}/02-enum4linux.txt"
E4L_CREDS=()
[ -n "$USER" ] && E4L_CREDS+=(-u "$USER" -p "$PASS")
[ -n "$DOMAIN" ] && E4L_CREDS+=(-w "$DOMAIN")

if have enum4linux-ng; then
    log "enum4linux-ng -A ${E4L_CREDS[*]:-} (also exporting JSON)"
    # -A: all modules; -oJ: machine-readable JSON for later parsing.
    enum4linux-ng -A "${E4L_CREDS[@]}" -oJ "${OUTDIR}/02-enum4linux" "$TARGET" 2>&1 | tee "$O"
elif have enum4linux; then
    warn "enum4linux-ng not found - using classic enum4linux."
    # Classic enum4linux uses -u/-p for creds, -w for workgroup, -a for all.
    E4L_OLD=()
    [ -n "$USER" ] && E4L_OLD+=(-u "$USER" -p "$PASS")
    [ -n "$DOMAIN" ] && E4L_OLD+=(-w "$DOMAIN")
    log "enum4linux -a ${E4L_OLD[*]:-}"
    enum4linux -a "${E4L_OLD[@]}" "$TARGET" 2>&1 | tee "$O"
else
    warn "Neither enum4linux-ng nor enum4linux installed - skipping (install one!)."
fi

###############################################################################
# 3. Share enumeration (smbclient + smbmap permission mapping)
###############################################################################
phase "3. Share enumeration"
SHARES_FILE="${OUTDIR}/03-shares.txt"
: > "$SHARES_FILE"
SHARE_NAMES=()

if have smbclient; then
    log "smbclient -L //${TARGET}/ (${AUTH_DESC})"
    smbclient -L "//${TARGET}/" "${SMBCLIENT_AUTH[@]}" 2>&1 | tee -a "$SHARES_FILE"
    # Parse "Sharename  Disk" rows; skip IPC$/print$ for spidering but record all.
    while read -r name type _; do
        case "$type" in Disk|IPC) SHARE_NAMES+=("$name") ;; esac
    done < <(grep -E '^[[:space:]]+[^[:space:]].*(Disk|IPC|Printer)' "$SHARES_FILE" \
             | awk '{print $1, $2}')
else
    warn "smbclient missing - cannot list shares."
fi

if have smbmap; then
    log "smbmap permission mapping"
    smbmap -H "$TARGET" "${SMBMAP_AUTH[@]}" 2>&1 | tee "${OUTDIR}/03-smbmap.txt"
else
    warn "smbmap missing - skipping permission mapping."
fi

###############################################################################
# 4. Optional: spider readable shares (recursive listing only - non-destructive)
###############################################################################
if [ "$DO_SPIDER" -eq 1 ]; then
    phase "4. Spidering readable shares (recursive directory listing)"
    if have smbclient && [ "${#SHARE_NAMES[@]}" -gt 0 ]; then
        for share in "${SHARE_NAMES[@]}"; do
            case "$share" in IPC\$|print\$|Sharename) continue ;; esac
            SPIDER_OUT="${OUTDIR}/04-share-${share//[^A-Za-z0-9_]/_}.txt"
            log "Listing share: ${share}"
            # 'recurse ON; ls' walks the tree without downloading anything.
            smbclient "//${TARGET}/${share}" "${SMBCLIENT_AUTH[@]}" \
                -c 'recurse ON; ls' >"$SPIDER_OUT" 2>&1
            if grep -qiE "NT_STATUS_ACCESS_DENIED|NT_STATUS_LOGON_FAILURE" "$SPIDER_OUT"; then
                warn "  ${share}: access denied"
            else
                ok "  ${share}: readable (listing -> ${SPIDER_OUT})"
            fi
        done
    else
        warn "No readable shares discovered or smbclient missing - nothing to spider."
    fi
else
    log "Share spidering disabled (use -s to enable recursive listing)."
fi

###############################################################################
# 5. RID cycling fallback (find users when RestrictAnonymous blocks normal enum)
###############################################################################
if [ "$SKIP_RID" -eq 0 ]; then
    phase "5. RID cycling (rpcclient fallback for user discovery)"
    O="${OUTDIR}/05-rid-cycle.txt"
    if have rpcclient; then
        log "Looking up domain SID, then cycling RIDs 500-1100..."
        # First grab the domain SID via lsaquery.
        DOMSID="$(rpcclient "${RPC_AUTH[@]}" "$TARGET" -c 'lsaquery' 2>/dev/null \
                  | grep -oE 'S-1-5-21-[0-9-]+' | head -n1)"
        if [ -n "$DOMSID" ]; then
            ok "Domain SID: ${DOMSID}"
            echo "Domain SID: ${DOMSID}" >"$O"
            for rid in $(seq 500 1100); do
                res="$(rpcclient "${RPC_AUTH[@]}" "$TARGET" \
                       -c "lookupsids ${DOMSID}-${rid}" 2>/dev/null \
                       | grep -v 'S-1-5-21.*\*unknown\*')"
                [ -n "$res" ] && echo "$res" | tee -a "$O"
            done
            ok "RID cycling output -> ${O}"
        else
            warn "Could not obtain domain SID (anonymous lsaquery blocked?). Trying enumdomusers."
            rpcclient "${RPC_AUTH[@]}" "$TARGET" -c 'enumdomusers' 2>&1 | tee "$O"
        fi
    else
        warn "rpcclient missing - skipping RID cycling (install samba-common-bin)."
    fi
else
    log "RID cycling skipped (-S)."
fi

###############################################################################
# 6. Vulnerability checks (MS17-010 EternalBlue + general smb-vuln NSE)
###############################################################################
phase "6. SMB vulnerability checks"
O="${OUTDIR}/06-vulns.txt"
if have nmap; then
    log "nmap smb-vuln-* against ${TARGET}:445"
    nmap -Pn -p445 \
        --script smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve-2017-7494,smb-protocols,smb-security-mode \
        "$TARGET" 2>&1 | tee "$O"
    if grep -qi "VULNERABLE" "$O"; then
        ok "Potential SMB vulnerability flagged - review ${O} carefully!"
    fi
else
    warn "nmap missing - cannot run SMB vuln NSE scripts."
fi

###############################################################################
# Summary
###############################################################################
phase "Summary"
ok "SMB enumeration complete. Results under: ${OUTDIR}"
echo -e "\n${C_BOLD}Discovered shares:${C_RESET}"
if [ "${#SHARE_NAMES[@]}" -gt 0 ]; then
    for s in "${SHARE_NAMES[@]}"; do echo "  - $s"; done
else
    echo "  (none parsed - check 03-shares.txt)"
fi
echo -e "\n${C_BOLD}Output files:${C_RESET}"
ls -1 "$OUTDIR" | sed 's/^/  /'
echo
log "Tips: feed discovered users into service-brute.sh; check share contents for creds/flags."
log "Reminder: stay within authorized scope."
