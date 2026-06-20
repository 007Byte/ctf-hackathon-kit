#!/usr/bin/env python3
"""
crypto-template.py  --  CTF crypto toolkit (RSA / XOR / encodings)
==================================================================
A grab-bag of ready-to-use helpers for crypto challenges. Import what you need
or fill in the values in main() and run it.

INSTALL (all optional pieces degrade gracefully):
    pip install pycryptodome sympy requests
    pip install gmpy2        # big speedups for roots/inverses (optional)

NOTE on pycryptodome: import as `Crypto` (do NOT also install the old `pycrypto`).
"""

import sys
import base64
import binascii
from math import gcd, isqrt

# --- Optional: gmpy2 for fast big-int math. Fall back to pure Python if absent.
try:
    import gmpy2
    HAVE_GMPY2 = True
except ImportError:
    HAVE_GMPY2 = False
    print("[i] gmpy2 not installed -- using slower pure-Python fallbacks", file=sys.stderr)

# --- Optional: sympy for factoring / nthroot / primality.
try:
    import sympy
    HAVE_SYMPY = True
except ImportError:
    HAVE_SYMPY = False

# --- pycryptodome (only needed for key construction / padded decryption helpers)
try:
    from Crypto.PublicKey import RSA
    from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse, getPrime
    HAVE_PYCRYPTODOME = True
except ImportError:
    HAVE_PYCRYPTODOME = False
    # Minimal stand-ins so the encoding helpers still work without pycryptodome.
    def long_to_bytes(n):
        return n.to_bytes((n.bit_length() + 7) // 8, "big") or b"\x00"
    def bytes_to_long(b):
        return int.from_bytes(b, "big")


# ============================================================================
# ENCODING / CONVERSION HELPERS
# ============================================================================
def b64e(b):  return base64.b64encode(b if isinstance(b, bytes) else b.encode()).decode()
def b64d(s):  return base64.b64decode(s)
def hexe(b):  return (b if isinstance(b, bytes) else b.encode()).hex()
def hexd(s):  return bytes.fromhex(s.strip().replace(" ", ""))
def i2b(n):   return long_to_bytes(n)            # int  -> bytes
def b2i(b):   return bytes_to_long(b)            # bytes -> int


# ============================================================================
# MODULAR ARITHMETIC
# ============================================================================
def egcd(a, b):
    """Extended Euclid: return (g, x, y) with a*x + b*y = g = gcd(a, b)."""
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)

def modinv(a, m):
    """Modular inverse of a mod m. Uses gmpy2/pycryptodome if available."""
    if HAVE_GMPY2:
        return int(gmpy2.invert(a, m))
    if HAVE_PYCRYPTODOME:
        return inverse(a, m)
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("no modular inverse (a and m not coprime)")
    return x % m

def iroot(n, k):
    """
    Exact integer k-th root: returns (root, is_exact).
    Critical for small-e RSA -- never use floating point round(n ** (1/e))!
    """
    if HAVE_GMPY2:
        r, exact = gmpy2.iroot(gmpy2.mpz(n), k)
        return int(r), bool(exact)
    if HAVE_SYMPY:
        r = sympy.integer_nthroot(n, k)   # returns (root, is_exact)
        return int(r[0]), bool(r[1])
    # Pure-Python binary search fallback.
    lo, hi = 0, 1 << ((n.bit_length() // k) + 1)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** k < n:
            lo = mid + 1
        else:
            hi = mid
    return lo, lo ** k == n


# ============================================================================
# RSA ATTACKS
# ============================================================================
def rsa_decrypt_pq(c, e, p, q):
    """Full decryption given the factors p and q. Returns plaintext bytes."""
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    m = pow(c, d, n)
    return i2b(m)

def rsa_decrypt_d(c, d, n):
    """Decrypt when you already have the private exponent d."""
    return i2b(pow(c, d, n))

def rsa_small_e_cuberoot(c, e=3):
    """
    Small-e (no padding) attack: if m^e < n, then c == m^e exactly, so m is the
    exact e-th root of c. Returns plaintext bytes or None if not an exact root.
    """
    m, exact = iroot(c, e)
    if exact:
        return i2b(m)
    print("[-] c is not a perfect e-th root -- m^e probably wrapped mod n.")
    print("    Try the Hastad broadcast attack (CRT over several moduli) instead.")
    return None

def rsa_common_modulus(c1, c2, e1, e2, n):
    """
    Common-modulus attack: same m encrypted under the same n with two coprime
    exponents e1, e2. Recover m without any private key.
    Requires gcd(e1, e2) == 1.
    """
    g, a, b = egcd(e1, e2)
    if g != 1:
        raise ValueError("e1 and e2 must be coprime for the common-modulus attack")
    # Handle negative coefficients with modular inverse of the ciphertext.
    if a < 0:
        c1 = modinv(c1, n); a = -a
    if b < 0:
        c2 = modinv(c2, n); b = -b
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return i2b(m)

def rsa_from_n_factors(n):
    """
    Try to factor a (small/weak) modulus n into p, q via sympy. Returns (p, q)
    or None. Only works for genuinely weak n -- otherwise use factordb / Wiener.
    """
    if not HAVE_SYMPY:
        print("[-] sympy not installed; cannot factor locally.")
        return None
    factors = sympy.factorint(n)
    primes = []
    for prime, mult in factors.items():
        primes.extend([int(prime)] * mult)
    if len(primes) == 2:
        return primes[0], primes[1]
    print(f"[-] n did not split into exactly two primes: {factors}")
    return None

def fermat_factor(n, max_iter=1_000_000):
    """
    Fermat factorization: fast when p and q are close together (a common CTF
    weakness). Returns (p, q) or None.
    """
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return (a - b, a + b)
        a += 1
    return None

def factordb_lookup(n):
    """
    Query factordb.com for known factors of n. Returns a list of int factors,
    or None on failure. (Many CTF moduli are already in factordb.)
    Requires `requests`.
    """
    try:
        import requests
    except ImportError:
        print("[-] install requests to use factordb_lookup")
        return None
    try:
        r = requests.get("http://factordb.com/api", params={"query": str(n)}, timeout=10)
        data = r.json()
        if data.get("status") == "FF":   # FF = Fully Factored
            factors = []
            for base_str, mult in data["factors"]:
                factors.extend([int(base_str)] * int(mult))
            return factors
        print(f"[i] factordb status: {data.get('status')} (not fully factored)")
        return None
    except Exception as exc:
        print(f"[-] factordb lookup failed: {exc}")
        return None

def wiener_pointer():
    """
    Wiener's attack pointer: works when the private exponent d is small
    (roughly d < n^(1/4)), which usually shows up as a SUSPICIOUSLY LARGE e.
    Recovers d from continued fractions of e/n.

    Don't reinvent it -- grab a tested implementation:
        pip install owiener
        import owiener; d = owiener.attack(e, n)
    or use SageMath / RsaCtfTool (`python RsaCtfTool.py -n N -e E --uncipher C`).
    """
    print("Large e relative to n? -> try Wiener: `pip install owiener; owiener.attack(e, n)`")


# ============================================================================
# XOR UTILITIES
# ============================================================================
def _as_bytes(x):
    return x if isinstance(x, bytes) else x.encode()

def xor_bytes(a, b):
    """XOR two byte strings; the shorter is cycled (repeating-key XOR)."""
    a, b = _as_bytes(a), _as_bytes(b)
    return bytes(x ^ b[i % len(b)] for i, x in enumerate(a))

def xor_single(data, key_byte):
    """XOR every byte of `data` with one key byte (0-255)."""
    return bytes(x ^ key_byte for x in _as_bytes(data))

def xor_bruteforce_single(data, printable_only=True):
    """
    Try all 256 single-byte keys against `data`. Prints/returns candidates whose
    output looks like printable text. Great for the classic 'single-byte XOR'.
    """
    results = []
    for k in range(256):
        out = xor_single(data, k)
        if not printable_only or all(32 <= c < 127 or c in (9, 10, 13) for c in out):
            results.append((k, out))
            print(f"key={k:#04x} ({k:3d}): {out!r}")
    return results

def xor_known_plaintext(ciphertext, known_plain):
    """
    Recover (part of) the key from a known plaintext fragment:
        key_fragment = ciphertext[:len(known)] XOR known_plain
    Useful when you know a flag prefix like b'flag{' or a file header.
    """
    return xor_bytes(ciphertext[:len(_as_bytes(known_plain))], known_plain)


# ============================================================================
# MAIN SCAFFOLD  --  paste your challenge values here
# ============================================================================
def main():
    # ---- RSA example -------------------------------------------------------
    n = 0
    e = 65537
    c = 0
    if n and c:
        print(f"[*] n bits: {n.bit_length()}, e: {e}")

        # 1) small e? try the e-th root
        if e <= 5:
            pt = rsa_small_e_cuberoot(c, e)
            if pt:
                print("[+] small-e root:", pt)

        # 2) try factoring (local -> fermat -> factordb)
        factors = rsa_from_n_factors(n) or fermat_factor(n)
        if not factors:
            fdb = factordb_lookup(n)
            if fdb and len(fdb) == 2:
                factors = (fdb[0], fdb[1])
        if factors:
            p, q = factors
            print(f"[+] factored: p={p}\n               q={q}")
            print("[+] plaintext:", rsa_decrypt_pq(c, e, p, q))

        # 3) huge e? Wiener
        if e.bit_length() > n.bit_length() // 2:
            wiener_pointer()

    # ---- XOR example -------------------------------------------------------
    # ct = hexd("....")
    # xor_bruteforce_single(ct)
    # print(xor_known_plaintext(ct, b"flag{"))

    if not (n and c):
        print("Edit main() with your challenge values (n, e, c, ciphertext, ...).")


if __name__ == "__main__":
    main()
