#!/usr/bin/env python3
"""
pwn-template.py  --  pwntools binary-exploitation starter template
==================================================================
Copy this to `exploit.py` at the start of a pwn challenge, then fill in the
EXPLOIT section near the bottom.

USAGE
-----
    ./exploit.py                 # run LOCAL against ./<binary>
    ./exploit.py GDB             # run LOCAL and auto-attach GDB (gdbscript below)
    ./exploit.py REMOTE host port    # connect to a remote service
    # examples:
    ./exploit.py REMOTE 10.10.10.5 1337
    ./exploit.py GDB             # local + gdb

FIRST THINGS FIRST  --  run checksec before writing any code:
    checksec ./<binary>           (or: pwn checksec ./<binary>)
  Look at:
    - RELRO   (Partial -> GOT overwrite possible; Full -> not)
    - Canary  (Stack canary -> need a leak before smashing past it)
    - NX      (No-eXecute -> can't run shellcode on the stack; use ROP/ret2libc)
    - PIE     (PIE enabled -> code addresses randomized; need a code/PIE leak)

INSTALL:  pip install pwntools
"""

from pwn import *

# ----------------------------------------------------------------------------
# CONFIG  --  edit these for your challenge
# ----------------------------------------------------------------------------
BINARY = "./vuln"          # path to the target ELF
LIBC   = ""                # path to the provided libc, e.g. "./libc.so.6" ("" = none)
LD     = ""                # path to provided ld-linux loader ("" = none)

# Default remote endpoint (overridden by `REMOTE host port` on the command line)
HOST = "127.0.0.1"
PORT = 1337

# GDB script run on attach (GDB mode only). Add breakpoints / commands here.
GDBSCRIPT = """
# b *main
# b *vuln+123
# Examples once symbols/PIE are sorted:
#   break *0x......      (absolute, no PIE)
#   tbreak main
continue
"""

# ----------------------------------------------------------------------------
# CONTEXT  --  pwntools reads arch/bits/endianness from the binary automatically
# ----------------------------------------------------------------------------
context.binary = elf = ELF(BINARY, checksec=False)   # also sets context.arch/bits/os
context.log_level = "info"            # "debug" to see every byte sent/recv'd
context.terminal = ["wt.exe", "-w", "0", "nt", "wsl"]  # how pwntools opens a GDB window
# ^ tweak context.terminal for your setup. Common values:
#     ["tmux", "splitw", "-h"]            (tmux, recommended on Linux/WSL)
#     ["gnome-terminal", "--", "sh", "-c"]
#     ["wt.exe", "wsl"]                   (Windows Terminal launching WSL)

# Load libc if provided -- gives you symbol offsets (system, /bin/sh, ...).
libc = ELF(LIBC, checksec=False) if LIBC else None

# ----------------------------------------------------------------------------
# CONNECTION HELPER
# ----------------------------------------------------------------------------
def start(argv=None, *a, **kw):
    """
    Return a tube (process or remote) depending on argv:
      REMOTE host port  -> remote(host, port)
      GDB               -> process + gdb.attach (local debugging)
      (default)         -> plain local process
    """
    argv = argv or []

    if args.REMOTE:
        # `./exploit.py REMOTE host port`  -> sys.argv = [..., 'REMOTE', host, port]
        host = sys.argv[2] if len(sys.argv) > 2 else HOST
        port = int(sys.argv[3]) if len(sys.argv) > 3 else PORT
        return remote(host, port)

    # LOCAL. If a custom libc/ld was provided, launch through the matching loader
    # so the binary uses *that* libc (so your offsets line up).
    if LIBC and LD:
        run = [LD, "--library-path", os.path.dirname(os.path.abspath(LIBC)), BINARY]
    else:
        run = [BINARY]

    if args.GDB:
        return gdb.debug(run + argv, gdbscript=GDBSCRIPT, *a, **kw)
    return process(run + argv, *a, **kw)


# ----------------------------------------------------------------------------
# I/O SHORTHAND  --  thin wrappers so the exploit body stays readable
# ----------------------------------------------------------------------------
io = start()

def s(data):        return io.send(data)
def sl(data):       return io.sendline(data)
def sa(delim, data):  return io.sendafter(delim, data)
def sla(delim, data): return io.sendlineafter(delim, data)
def r(n):           return io.recv(n)
def ru(delim, drop=True): return io.recvuntil(delim, drop=drop)
def rl():           return io.recvline()
def rall():         return io.recvall()
def clean(t=0.2):   return io.clean(t)
def interactive():  return io.interactive()

# Packing helpers (context.bits picks 32/64-bit width automatically).
#   p64/p32 -> pack int to bytes   u64/u32 -> unpack bytes to int
# Handy for unpacking partial leaks:
def leak_u64(data):
    """Pad a short little-endian leak to 8 bytes and unpack."""
    return u64(data.ljust(8, b"\x00"))


# ----------------------------------------------------------------------------
# OFFSET / ROP SCAFFOLDING  --  uncomment and fill in as you go
# ----------------------------------------------------------------------------
# --- Finding the saved-RIP offset (overflow distance) ---
#   In GDB:  cyclic 200  -> send it -> on crash:  cyclic -l $rsp  (or the faulting value)
#   In code: OFFSET = cyclic_find(0x6161616b)
# OFFSET = 72

# --- Useful ELF symbols/addresses ---
# elf.sym["win"]            # address of a function (PIE-relative until elf.address set)
# elf.got["puts"]          # GOT entry (where the resolved libc addr is stored)
# elf.plt["puts"]          # PLT stub (call this to invoke puts)
# After a PIE leak:  elf.address = leaked_main - elf.sym["main"]

# --- ROP via pwntools ROP() object ---
# rop = ROP(elf)
# rop.raw(rop.find_gadget(["ret"])[0])   # stack alignment 'ret' (needed before system on x86-64)
# rop.puts(elf.got["puts"])              # auto-build: puts(puts@got) to leak libc
# rop.main()                             # return to main to loop again
# log.info(rop.dump())                   # preview the chain
# payload = flat({OFFSET: rop.chain()})

# --- ret2libc after a libc leak ---
# libc.address = leaked_puts - libc.sym["puts"]
# system   = libc.sym["system"]
# binsh    = next(libc.search(b"/bin/sh\x00"))
# one      = libc.address + 0x........   # one_gadget offset (run `one_gadget ./libc.so.6`)

# --- Manual flat() payload builder ---
# payload  = b"A" * OFFSET
# payload += p64(ret_gadget)
# payload += p64(pop_rdi)
# payload += p64(binsh)
# payload += p64(system)


# ============================================================================
# EXPLOIT  --  YOUR CODE GOES HERE
# ============================================================================
def exploit():
    # Example skeleton: leak libc with puts, return to main, then pop a shell.
    #
    # ru(b"some prompt: ")
    # payload = flat({OFFSET: rop.chain()})
    # sl(payload)
    # leak = leak_u64(ru(b"\n")[:6])
    # libc.address = leak - libc.sym["puts"]
    # log.success(f"libc base: {hex(libc.address)}")
    #
    # ... build second-stage chain ...
    # sl(stage2)

    interactive()   # drop to a shell / manual interaction


if __name__ == "__main__":
    exploit()
