#!/usr/bin/env bash
###############################################################################
# service-brute.sh - Safe(r) hydra wrapper for credential testing
#
# Part of the hackathon recon toolkit. A thin, well-guarded wrapper
# around THC-Hydra for credential testing against common services:
#   ssh, ftp, smb, rdp, mysql, http-post-form
#
# It supplies sane defaults (SecLists wordlists, conservative thread count),
# ALWAYS prints the exact hydra command before running, and warns loudly that
# this is a noisy/aggressive activity.
#
# ##########################################################################
# #  !!!  AUTHORIZED TARGETS ONLY  !!!                                      #
# #  Brute forcing is intrusive, noisy, and can lock out accounts or       #
# #  crash fragile services. Only run against systems you OWN or have       #
# #  EXPLICIT WRITTEN PERMISSION to test. Unauthorized use is a CRIME.      #
# #  Mind rate limits / lockout policies. Start with small wordlists.       #
# ##########################################################################
#
# USAGE:
#   ./service-brute.sh -s <service> -T <target> [options]
#
#   -s <service>   One of: ssh ftp smb rdp mysql http-post-form   (REQUIRED)
#   -T <target>    Target IP / hostname                            (REQUIRED)
#   -P <port>      Custom port (default: service default)
#   -u <user>      Single username
#   -U <userlist>  Username wordlist file
#   -p <pass>      Single password
#   -W <passlist>  Password wordlist file (default: SecLists rockyou-ish)
#   -f <form>      http-post-form spec (REQUIRED for http-post-form), e.g.
#                  "/login.php:user=^USER^&pass=^PASS^:F=Invalid credentials"
#   -t <threads>   Parallel tasks (default 4; keep LOW to avoid lockouts)
#   -S             Stop after first valid pair found (hydra -f)
#   -n             Dry run: print the hydra command but do NOT execute
#   -h             Show this help
#
# EXAMPLES:
#   ./service-brute.sh -s ssh   -T 10.10.10.5 -u root -W rockyou.txt
#   ./service-brute.sh -s ftp   -T 10.10.10.5 -U users.txt -W pass.txt -S
#   ./service-brute.sh -s smb   -T 10.10.10.5 -u admin -W pass.txt
#   ./service-brute.sh -s rdp   -T 10.10.10.5 -u admin -W pass.txt -t 1
#   ./service-brute.sh -s mysql -T 10.10.10.5 -u root  -W pass.txt
#   ./service-brute.sh -s http-post-form -T 10.10.10.5 -U users.txt -W pass.txt \
#        -f "/login:username=^USER^&password=^PASS^:F=incorrect"
#
# DEFAULT WORDLISTS (override with -U / -W):
#   users: /usr/share/seclists/Usernames/top-usernames-shortlist.txt
#   pass : /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt
#   (falls back to /usr/share/wordlists/rockyou.txt if SecLists absent)
###############################################################################

set -u

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    C_RESET="\033[0m"; C_RED="\033[31m"; C_GRN="\033[32m"
    C_YEL="\033[33m"; C_BLU="\033[34m"; C_CYN="\033[36m"; C_BOLD="\033[1m"
else
    C_RESET=""; C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_CYN=""; C_BOLD=""
fi
log()  { echo -e "${C_BLU}[*]${C_RESET} $*"; }
ok()   { echo -e "${C_GRN}[+]${C_RESET} $*"; }
warn() { echo -e "${C_YEL}[!]${C_RESET} $*"; }
err()  { echo -e "${C_RED}[-]${C_RESET} $*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() { sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
SERVICE=""; TARGET=""; PORT=""; SINGLE_USER=""; USERLIST=""
SINGLE_PASS=""; PASSLIST=""; FORM=""; THREADS=4; STOP_FIRST=0; DRY_RUN=0

# SecLists default locations with rockyou fallback.
DEF_USERLIST="/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
DEF_PASSLIST="/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt"
ROCKYOU="/usr/share/wordlists/rockyou.txt"

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
while getopts ":s:T:P:u:U:p:W:f:t:Snh" opt; do
    case "$opt" in
        s) SERVICE="$OPTARG" ;;
        T) TARGET="$OPTARG" ;;
        P) PORT="$OPTARG" ;;
        u) SINGLE_USER="$OPTARG" ;;
        U) USERLIST="$OPTARG" ;;
        p) SINGLE_PASS="$OPTARG" ;;
        W) PASSLIST="$OPTARG" ;;
        f) FORM="$OPTARG" ;;
        t) THREADS="$OPTARG" ;;
        S) STOP_FIRST=1 ;;
        n) DRY_RUN=1 ;;
        h) usage 0 ;;
        \?) err "Unknown option: -$OPTARG"; usage 1 ;;
        :)  err "Option -$OPTARG requires an argument."; usage 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Validate
# ---------------------------------------------------------------------------
[ -z "$SERVICE" ] && { err "Service (-s) is required."; usage 1; }
[ -z "$TARGET" ]  && { err "Target (-T) is required.";  usage 1; }

case "$SERVICE" in
    ssh|ftp|smb|rdp|mysql|http-post-form) ;;
    *) err "Unsupported service: '$SERVICE'. Choose: ssh ftp smb rdp mysql http-post-form"; usage 1 ;;
esac

if ! have hydra; then
    err "hydra is not installed. Install with: sudo apt install hydra"
    exit 1
fi

# Resolve user source: single user OR a list (default list if neither given).
USER_ARGS=()
if [ -n "$SINGLE_USER" ]; then
    USER_ARGS=(-l "$SINGLE_USER")
elif [ -n "$USERLIST" ]; then
    [ -f "$USERLIST" ] || { err "Userlist not found: $USERLIST"; exit 1; }
    USER_ARGS=(-L "$USERLIST")
else
    if [ -f "$DEF_USERLIST" ]; then
        warn "No user(list) supplied - using default: $DEF_USERLIST"
        USER_ARGS=(-L "$DEF_USERLIST")
    else
        err "No user(list) given and default SecLists userlist missing ($DEF_USERLIST)."
        err "Supply -u <user> or -U <userlist>."
        exit 1
    fi
fi

# Resolve password source: single pass OR a list (default list if neither given).
PASS_ARGS=()
if [ -n "$SINGLE_PASS" ]; then
    PASS_ARGS=(-p "$SINGLE_PASS")
elif [ -n "$PASSLIST" ]; then
    [ -f "$PASSLIST" ] || { err "Passlist not found: $PASSLIST"; exit 1; }
    PASS_ARGS=(-P "$PASSLIST")
else
    if [ -f "$DEF_PASSLIST" ]; then
        warn "No password(list) supplied - using default: $DEF_PASSLIST"
        PASS_ARGS=(-P "$DEF_PASSLIST")
    elif [ -f "$ROCKYOU" ]; then
        warn "SecLists default missing - falling back to rockyou: $ROCKYOU"
        PASS_ARGS=(-P "$ROCKYOU")
    else
        err "No password(list) given and no default wordlist found."
        err "Supply -p <pass> or -W <passlist>."
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Build the hydra command for the chosen service.
# ---------------------------------------------------------------------------
HYDRA_CMD=(hydra "${USER_ARGS[@]}" "${PASS_ARGS[@]}" -t "$THREADS" -V)

# -f: exit after first valid login per host (when -S requested).
[ "$STOP_FIRST" -eq 1 ] && HYDRA_CMD+=(-f)

# Apply custom port if given.
[ -n "$PORT" ] && HYDRA_CMD+=(-s "$PORT")

case "$SERVICE" in
    ssh)
        HYDRA_CMD+=("$TARGET" ssh)
        ;;
    ftp)
        HYDRA_CMD+=("$TARGET" ftp)
        ;;
    smb)
        # Hydra's smb module is single-threaded internally; warn the user.
        warn "SMB module is internally single-threaded; -t is largely ignored."
        warn "Watch for account lockout policies on Windows targets!"
        HYDRA_CMD+=("$TARGET" smb)
        ;;
    rdp)
        warn "RDP brute forcing is VERY noisy and lockout-prone. Use -t 1 and small lists."
        HYDRA_CMD+=("$TARGET" rdp)
        ;;
    mysql)
        HYDRA_CMD+=("$TARGET" mysql)
        ;;
    http-post-form)
        [ -z "$FORM" ] && { err "http-post-form requires -f \"<path>:<params>:<fail-condition>\""; usage 1; }
        # Form spec already contains ^USER^ / ^PASS^ placeholders and F=/S= condition.
        HYDRA_CMD+=("$TARGET" http-post-form "$FORM")
        ;;
esac

# ---------------------------------------------------------------------------
# Confirm + run
# ---------------------------------------------------------------------------
echo
echo -e "${C_BOLD}${C_RED}################# CREDENTIAL BRUTE FORCE #################${C_RESET}"
warn "AUTHORIZED TARGETS ONLY. This is intrusive and noisy."
warn "Respect lockout policies and rate limits. Prefer small, targeted lists."
echo
log "Service : ${SERVICE}"
log "Target  : ${TARGET}${PORT:+ (port ${PORT})}"
log "Threads : ${THREADS}"
echo
echo -e "${C_BOLD}Exact command to be executed:${C_RESET}"
# Print a copy-pasteable, properly-quoted version of the command.
printf '  '
for arg in "${HYDRA_CMD[@]}"; do
    case "$arg" in
        *[[:space:]\&\^\|\;]*) printf '%q ' "$arg" ;;
        *) printf '%s ' "$arg" ;;
    esac
done
printf '\n\n'

if [ "$DRY_RUN" -eq 1 ]; then
    ok "Dry run (-n): command NOT executed. Review it above and re-run without -n."
    exit 0
fi

log "Starting in 3 seconds... (Ctrl-C to abort)"
sleep 3
"${HYDRA_CMD[@]}"
RC=$?
echo
if [ "$RC" -eq 0 ]; then
    ok "hydra finished (exit 0). Review output above for any valid credentials."
else
    warn "hydra exited with code ${RC}. Check target reachability / syntax / lockout."
fi
log "Reminder: stay within authorized scope."
exit "$RC"
