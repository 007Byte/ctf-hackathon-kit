#!/usr/bin/env bash
#
# install-tools.sh
# ----------------------------------------------------------------------------
# CTF / hackathon tooling installer for Kali Linux (and Debian-based systems).
#
# Target OS : Kali Linux 2024.x+ / Debian / Ubuntu (apt based)
# Run as    : sudo ./install-tools.sh   (the script also re-checks for root)
#
# What it does:
#   1. apt update + installs the bread-and-butter CTF packages from the repos
#      (grouped by category: recon, web, RE/pwn, crypto, forensics, passwords).
#   2. Installs the "not in apt (or better from source)" tools via pipx / go /
#      cargo / git, each guarded with `command -v` so re-runs are idempotent.
#   3. Clones the wordlist/priv-esc repos every CTF player wants under ~/tools.
#
# Design notes:
#   - `set -euo pipefail` for safety, BUT every *optional* install is wrapped in
#     a helper that never aborts the whole run if one tool fails (networks die,
#     repos move, go toolchains break - we keep going and report at the end).
#   - Idempotent: safe to run twice. Re-running just upgrades / re-checks.
# ----------------------------------------------------------------------------

set -euo pipefail

# ---------------------------------------------------------------------------
# Pretty output helpers
# ---------------------------------------------------------------------------
C_RESET="\033[0m"; C_GREEN="\033[1;32m"; C_YELLOW="\033[1;33m"
C_RED="\033[1;31m"; C_BLUE="\033[1;34m"; C_CYAN="\033[1;36m"

log()   { echo -e "${C_BLUE}[*]${C_RESET} $*"; }
ok()    { echo -e "${C_GREEN}[+]${C_RESET} $*"; }
warn()  { echo -e "${C_YELLOW}[!]${C_RESET} $*"; }
err()   { echo -e "${C_RED}[-]${C_RESET} $*"; }
hdr()   { echo -e "\n${C_CYAN}==== $* ====${C_RESET}"; }

# Track optional failures so we can summarise them at the end.
FAILED_OPTIONAL=()

# Run an optional step; on failure record it but DO NOT abort the script.
# Usage: try_optional "human label" command arg arg ...
try_optional() {
  local label="$1"; shift
  if "$@"; then
    ok "$label"
  else
    warn "Optional step failed: $label (continuing)"
    FAILED_OPTIONAL+=("$label")
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# Root / environment checks
# ---------------------------------------------------------------------------
if [[ "${EUID}" -ne 0 ]]; then
  err "This script installs system packages and must be run as root."
  err "Re-run with:  sudo $0"
  exit 1
fi

# Figure out the *real* (non-root) user so pipx/go/git clones land in their HOME,
# not in /root, when the script is run via sudo.
REAL_USER="${SUDO_USER:-root}"
REAL_HOME="$(getent passwd "${REAL_USER}" | cut -d: -f6)"
REAL_HOME="${REAL_HOME:-/root}"
TOOLS_DIR="${REAL_HOME}/tools"

log "Installing for user: ${REAL_USER} (home: ${REAL_HOME})"

# Helper: run a command AS the real user (so files aren't root-owned).
as_user() {
  if [[ "${REAL_USER}" == "root" ]]; then
    bash -lc "$*"
  else
    sudo -u "${REAL_USER}" -H bash -lc "$*"
  fi
}

export DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------------------
# 1. apt update + base packages
# ---------------------------------------------------------------------------
hdr "Updating apt package index"
apt-get update -y

# Install a list of apt packages, skipping ones that don't exist in the repos
# (names drift between Kali/Debian/Ubuntu) instead of failing the whole batch.
apt_install() {
  local group="$1"; shift
  hdr "apt: ${group}"
  local pkg
  for pkg in "$@"; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then
      ok "${pkg} (already installed)"
      continue
    fi
    if apt-get install -y --no-install-recommends "$pkg" >/dev/null 2>&1; then
      ok "${pkg}"
    else
      warn "Could not install '${pkg}' via apt (not in repo on this distro?)"
      FAILED_OPTIONAL+=("apt:${pkg}")
    fi
  done
}

# --- Recon / enumeration -------------------------------------------------
apt_install "recon / enumeration" \
  nmap masscan gobuster ffuf feroxbuster nikto whatweb wfuzz \
  dnsenum dnsrecon enum4linux smbclient netcat-traditional

# --- Web ------------------------------------------------------------------
apt_install "web" \
  sqlmap burpsuite zaproxy wpscan

# --- Reverse engineering / pwn -------------------------------------------
# (gef/pwndbg/ghidra handled below; ghidra is huge - left as an apt option)
apt_install "reverse engineering / pwn" \
  gdb radare2 binutils ltrace strace patchelf file

# --- Crypto ---------------------------------------------------------------
apt_install "crypto" \
  john hashcat hashid hash-identifier

# --- Forensics / stego ----------------------------------------------------
apt_install "forensics / stego" \
  binwalk foremost libimage-exiftool-perl steghide ruby-zsteg outguess \
  sleuthkit autopsy pngcheck

# --- Passwords / wordlists ------------------------------------------------
apt_install "passwords / wordlists" \
  seclists crunch cewl hydra medusa

# --- Misc / quality-of-life ----------------------------------------------
apt_install "misc / toolchains" \
  tmux jq git python3 python3-pip python3-venv pipx golang-go ruby ruby-dev \
  curl wget unzip p7zip-full sox build-essential caca-utils

# ---------------------------------------------------------------------------
# 2. pipx / go / cargo / git installs (things not in apt or better from source)
# ---------------------------------------------------------------------------

# Make sure pipx is on PATH for the real user (PEP 668 friendly).
if have pipx || as_user "command -v pipx >/dev/null 2>&1"; then
  try_optional "pipx ensurepath" as_user "pipx ensurepath >/dev/null 2>&1 || true"
fi

# ---- pipx-installed CLI tools -------------------------------------------
hdr "pipx tools"

pipx_install() {
  # $1 = command name to check, $2 = pipx spec (package or git URL)
  local cmd="$1" spec="$2"
  if as_user "command -v ${cmd} >/dev/null 2>&1"; then
    ok "${cmd} (already installed)"
    return 0
  fi
  try_optional "pipx install ${spec}" as_user "pipx install '${spec}'"
}

# name-that-hash: modern hash identifier (replaces the aging hash-identifier).
pipx_install nth            name-that-hash
# search-that-hash: bundles nth + auto-lookup; handy companion.
pipx_install sth            search-that-hash
# updog: better-than-SimpleHTTPServer file server for transfers during boxes.
pipx_install updog          updog
# volatility3: memory forensics (heavy on deps; pipx keeps it isolated).
pipx_install vol            volatility3
# uploadserver: another quick file-upload receiver.
pipx_install uploadserver   uploadserver

# ---- Go-installed tools -------------------------------------------------
hdr "Go tools"
# Ensure GOBIN / GOPATH/bin is discoverable; default is ~/go/bin.
GO_BIN="${REAL_HOME}/go/bin"

go_install() {
  # $1 = resulting binary name, $2 = go install path@version
  local bin="$1" path="$2"
  if as_user "command -v ${bin} >/dev/null 2>&1" || [[ -x "${GO_BIN}/${bin}" ]]; then
    ok "${bin} (already installed)"
    return 0
  fi
  if ! have go && ! as_user "command -v go >/dev/null 2>&1"; then
    warn "go toolchain not found; skipping ${bin}"
    FAILED_OPTIONAL+=("go:${bin}")
    return 0
  fi
  try_optional "go install ${path}" as_user "go install '${path}'"
}

# katana: ProjectDiscovery's fast next-gen web crawler (JS-aware).
go_install katana    github.com/projectdiscovery/katana/cmd/katana@latest
# httpx: fast HTTP probing/tech detection.
go_install httpx     github.com/projectdiscovery/httpx/cmd/httpx@latest
# nuclei: templated vuln scanner, great for quick web wins.
go_install nuclei    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# gau: fetch known URLs from web archives for content discovery.
go_install gau       github.com/lc/gau/v2/cmd/gau@latest

# ---- Cargo-installed tools (rustscan) -----------------------------------
hdr "Cargo / Rust tools"
# rustscan: ultra-fast port scanner that hands ports off to nmap.
# Kali sometimes ships a .deb on the GitHub releases page; cargo is the
# officially-supported route, so try cargo if rustscan isn't present.
if as_user "command -v rustscan >/dev/null 2>&1"; then
  ok "rustscan (already installed)"
else
  if as_user "command -v cargo >/dev/null 2>&1"; then
    try_optional "cargo install rustscan" as_user "cargo install rustscan"
  else
    warn "cargo not found - install Rust (https://rustup.rs) then 'cargo install rustscan'"
    warn "Alternatively grab the .deb from https://github.com/bee-san/RustScan/releases"
    FAILED_OPTIONAL+=("rustscan (no cargo)")
  fi
fi

# ---------------------------------------------------------------------------
# 3. GDB enhancers: pwndbg + gef (pick pwndbg as default, gef available too)
# ---------------------------------------------------------------------------
hdr "GDB enhancers (pwndbg / gef)"

# pwndbg - install into ~/tools and wire up via setup.sh (idempotent clone).
install_pwndbg() {
  local dir="${TOOLS_DIR}/pwndbg"
  if grep -q "pwndbg" "${REAL_HOME}/.gdbinit" 2>/dev/null; then
    ok "pwndbg (already configured in ~/.gdbinit)"
    return 0
  fi
  as_user "mkdir -p '${TOOLS_DIR}'"
  if [[ ! -d "${dir}/.git" ]]; then
    as_user "git clone --depth 1 https://github.com/pwndbg/pwndbg '${dir}'"
  fi
  # setup.sh handles deps and adds 'source .../gdbinit.py' to ~/.gdbinit
  as_user "cd '${dir}' && ./setup.sh"
}
try_optional "pwndbg setup" install_pwndbg

# gef - clone alongside; NOT auto-sourced (only one GDB enhancer at a time).
# Switch by editing ~/.gdbinit. We just stage it so it's ready.
install_gef() {
  local dir="${TOOLS_DIR}/gef"
  if [[ -f "${dir}/gef.py" ]]; then
    ok "gef (already cloned at ${dir})"
  else
    as_user "mkdir -p '${TOOLS_DIR}'"
    as_user "git clone --depth 1 https://github.com/hugsy/gef '${dir}'"
  fi
  warn "gef staged at ${dir}. To use gef INSTEAD of pwndbg, put in ~/.gdbinit:"
  warn "    source ${dir}/gef.py"
  warn "  (comment out the pwndbg source line - don't load both)"
}
try_optional "gef stage" install_gef

# ---------------------------------------------------------------------------
# 4. Clone the must-have repos under ~/tools
# ---------------------------------------------------------------------------
hdr "Cloning helper repos into ${TOOLS_DIR}"

clone_repo() {
  # $1 = url, $2 = dest dir name, $3 = note
  local url="$1" name="$2" note="$3"
  local dest="${TOOLS_DIR}/${name}"
  as_user "mkdir -p '${TOOLS_DIR}'"
  if [[ -d "${dest}/.git" ]]; then
    ok "${name} (already cloned) - ${note}"
    try_optional "git pull ${name}" as_user "cd '${dest}' && git pull --ff-only"
  else
    try_optional "clone ${name}" as_user "git clone --depth 1 '${url}' '${dest}'"
    [[ -d "${dest}" ]] && echo -e "    ${C_CYAN}note:${C_RESET} ${note}"
  fi
}

# SecLists: the wordlist motherlode. apt installs to /usr/share/seclists too,
# but a fresh clone in ~/tools is handy and always current.
clone_repo "https://github.com/danielmiessler/SecLists" "SecLists" \
  "Wordlists: discovery, fuzzing, passwords. apt copy lives in /usr/share/seclists"

# PEASS-ng: linpeas.sh / winpeas - the priv-esc enumeration standard.
clone_repo "https://github.com/peass-ng/PEASS-ng" "PEASS-ng" \
  "linpeas: PEASS-ng/linPEAS/linpeas.sh | winpeas: PEASS-ng/winPEAS/"

# pspy: snoop on processes/cron without root - classic linux priv-esc helper.
clone_repo "https://github.com/DominicBreuker/pspy" "pspy" \
  "Prebuilt binaries: grab from the GitHub Releases page (pspy64 / pspy32)"

# Make sure everything under ~/tools is owned by the real user.
if [[ "${REAL_USER}" != "root" ]]; then
  chown -R "${REAL_USER}:${REAL_USER}" "${TOOLS_DIR}" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 5. Friendly summary
# ---------------------------------------------------------------------------
hdr "Summary"
ok "Base CTF toolset installed (recon / web / RE / pwn / crypto / forensics / passwords)."
echo
echo -e "${C_CYAN}Handy paths:${C_RESET}"
echo "  Wordlists (apt) : /usr/share/seclists  (rockyou: /usr/share/wordlists/rockyou.txt)"
echo "  Your tools dir  : ${TOOLS_DIR}"
echo "  linpeas         : ${TOOLS_DIR}/PEASS-ng/linPEAS/linpeas.sh"
echo "  pwndbg          : loaded via ${REAL_HOME}/.gdbinit"
echo "  gef (alt)       : ${TOOLS_DIR}/gef/gef.py"
echo
echo -e "${C_CYAN}PATH reminders:${C_RESET}"
echo "  Go binaries live in  ~/go/bin   (add to PATH if 'katana/httpx/nuclei' not found)"
echo "  pipx binaries live in ~/.local/bin"
echo '  Add to ~/.bashrc:  export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"'
echo "  rockyou is gzipped on fresh Kali: sudo gunzip /usr/share/wordlists/rockyou.txt.gz"
echo

if [[ ${#FAILED_OPTIONAL[@]} -gt 0 ]]; then
  warn "Some OPTIONAL items did not install (this is usually fine):"
  for f in "${FAILED_OPTIONAL[@]}"; do
    echo "    - ${f}"
  done
  echo
  warn "Re-run the script to retry, or install those manually."
else
  ok "All steps completed with no failures. Happy hacking!"
fi

echo -e "${C_GREEN}Done.${C_RESET} Open a NEW shell (or 'source ~/.bashrc') so PATH changes apply."
