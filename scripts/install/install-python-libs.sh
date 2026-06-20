#!/usr/bin/env bash
#
# install-python-libs.sh
# ----------------------------------------------------------------------------
# Install the Python libraries a CTF player reaches for (pwn / crypto / RE /
# web / networking) on Kali Linux / modern Debian / Ubuntu.
#
# IMPORTANT - PEP 668 ("externally-managed-environment"):
#   Kali (and Debian 12+/Ubuntu 23.04+) mark the system Python as
#   "externally managed". A bare `pip install foo` will be REFUSED with:
#       error: externally-managed-environment
#   You have three sane options, in order of preference:
#
#     (A) A dedicated virtualenv  <-- RECOMMENDED for CTF work
#         Clean, reproducible, can't break system tools. Activate per session.
#
#     (B) pipx for standalone CLI tools (ropper, etc.)
#         Each tool gets its own isolated venv but is on your PATH globally.
#
#     (C) Global install with --break-system-packages  <-- LAST RESORT
#         Convenient ("just works everywhere") but can clash with apt-managed
#         python packages and is harder to clean up. Use knowingly.
#
# Usage:
#   ./install-python-libs.sh            # default: create/refresh the venv (A)
#   ./install-python-libs.sh venv       # same as default
#   ./install-python-libs.sh global     # install globally with the PEP 668 override (C)
#   ./install-python-libs.sh pipx       # install the CLI-ish ones via pipx (B)
#
# Do NOT run this with sudo for the venv/pipx modes - keep it in your user.
# ----------------------------------------------------------------------------

set -euo pipefail

C_RESET="\033[0m"; C_GREEN="\033[1;32m"; C_YELLOW="\033[1;33m"
C_RED="\033[1;31m"; C_CYAN="\033[1;36m"
log()  { echo -e "${C_CYAN}[*]${C_RESET} $*"; }
ok()   { echo -e "${C_GREEN}[+]${C_RESET} $*"; }
warn() { echo -e "${C_YELLOW}[!]${C_RESET} $*"; }
err()  { echo -e "${C_RED}[-]${C_RESET} $*"; }

MODE="${1:-venv}"
VENV_DIR="${CTF_VENV:-$HOME/ctf-venv}"

# ---------------------------------------------------------------------------
# The library list.
#   - Core pure-python / common: pwntools, requests, bs4, pycryptodome, ...
#   - Heavy native builds (need apt headers): gmpy2, z3-solver, capstone,
#     unicorn, keystone-engine, angr.
#
# angr is HEAVY (symbolic execution; pulls capstone/unicorn/claripy/z3 and a
# big dep tree). It's separated so you can skip it if you don't need it.
# ---------------------------------------------------------------------------
PY_LIBS=(
  # exploitation / pwn
  pwntools
  ropper
  capstone
  unicorn
  keystone-engine
  # crypto / math
  pycryptodome
  gmpy2
  sympy
  z3-solver
  # web / networking
  requests
  beautifulsoup4
  scapy
  paramiko
  pyjwt
  # AD / SMB / network protocols
  impacket
  # imaging / data (stego, misc scripting)
  Pillow
  numpy
)

# angr installed separately (opt-in) because of its size.
PY_LIBS_HEAVY=( angr )

# Build prerequisites that the native wheels/builds frequently need.
# (Most ship manylinux wheels now, but gmpy2/angr occasionally compile.)
APT_BUILD_DEPS=(
  python3-dev build-essential pkg-config
  libgmp-dev libmpfr-dev libmpc-dev   # gmpy2
  libffi-dev libssl-dev                # cffi / cryptography backends
)

ensure_build_deps() {
  log "Checking native build dependencies (may prompt for sudo)..."
  if command -v apt-get >/dev/null 2>&1; then
    local missing=()
    for p in "${APT_BUILD_DEPS[@]}"; do
      dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
      warn "Installing build deps: ${missing[*]}"
      sudo apt-get update -y
      sudo apt-get install -y "${missing[@]}" || \
        warn "Some build deps failed; native wheels may still work."
    else
      ok "Build dependencies already present."
    fi
  else
    warn "apt-get not found; skipping build-dep check (non-Debian system?)."
  fi
}

# ---------------------------------------------------------------------------
# Mode A: virtualenv (RECOMMENDED)
# ---------------------------------------------------------------------------
install_venv() {
  ensure_build_deps
  if [[ ! -d "${VENV_DIR}" ]]; then
    log "Creating virtualenv at ${VENV_DIR}"
    python3 -m venv "${VENV_DIR}"
  else
    ok "Reusing existing venv at ${VENV_DIR}"
  fi

  # shellcheck disable=SC1091
  source "${VENV_DIR}/bin/activate"
  log "Upgrading pip/setuptools/wheel inside the venv"
  pip install --upgrade pip setuptools wheel

  log "Installing core CTF libraries..."
  pip install --upgrade "${PY_LIBS[@]}"

  warn "angr is large. Installing it now (Ctrl-C within 5s to skip)..."
  sleep 5 || true
  pip install --upgrade "${PY_LIBS_HEAVY[@]}" || \
    warn "angr install failed - re-run later with: source ${VENV_DIR}/bin/activate && pip install angr"

  deactivate || true

  cat <<EOF

$(ok "venv ready.")
To use it every CTF session:
    ${C_CYAN}source ${VENV_DIR}/bin/activate${C_RESET}

Add a shortcut to your ~/.bashrc / ~/.zshrc:
    alias ctfenv='source ${VENV_DIR}/bin/activate'

When you're done:  deactivate
EOF
}

# ---------------------------------------------------------------------------
# Mode C: global install with PEP 668 override (LAST RESORT)
# ---------------------------------------------------------------------------
install_global() {
  ensure_build_deps
  warn "Installing GLOBALLY with --break-system-packages."
  warn "This can conflict with apt-managed python3-* packages. You were warned."
  log "Upgrading pip first..."
  python3 -m pip install --upgrade --break-system-packages pip || true

  log "Installing core CTF libraries globally..."
  python3 -m pip install --upgrade --break-system-packages "${PY_LIBS[@]}"

  warn "Installing angr globally (heavy)..."
  python3 -m pip install --upgrade --break-system-packages "${PY_LIBS_HEAVY[@]}" || \
    warn "angr global install failed; consider the venv approach instead."

  ok "Global install done. Libraries available to system python3."
}

# ---------------------------------------------------------------------------
# Mode B: pipx (for the libs that double as CLI tools)
# ---------------------------------------------------------------------------
install_pipx() {
  if ! command -v pipx >/dev/null 2>&1; then
    log "Installing pipx via apt..."
    sudo apt-get update -y && sudo apt-get install -y pipx
  fi
  pipx ensurepath >/dev/null 2>&1 || true

  # Only the ones that provide useful command-line entry points.
  local PIPX_TOOLS=( ropper impacket )
  for t in "${PIPX_TOOLS[@]}"; do
    if pipx list 2>/dev/null | grep -qi "package ${t} "; then
      ok "${t} (already installed via pipx)"
    else
      pipx install "${t}" && ok "${t}" || warn "pipx install ${t} failed"
    fi
  done

  warn "pipx is for CLI tools only. For LIBRARIES you import in solve scripts"
  warn "(pwntools, pycryptodome, z3, ...), use the venv mode:"
  warn "    ./install-python-libs.sh venv"
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
case "${MODE}" in
  venv)   install_venv   ;;
  global) install_global ;;
  pipx)   install_pipx   ;;
  *)
    err "Unknown mode: ${MODE}"
    echo "Usage: $0 [venv|global|pipx]"
    exit 1
    ;;
esac

ok "Finished (mode: ${MODE})."
