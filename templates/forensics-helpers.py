#!/usr/bin/env python3
"""
forensics-helpers.py  --  CTF forensics swiss-army CLI
======================================================
Quick triage for forensics/stego challenges, no external binaries required for
the core features.

SUBCOMMANDS
-----------
    magic    FILE                 detect file type by magic bytes
    entropy  FILE                 Shannon entropy (spot encryption/packing)
    strings  FILE [-n MIN]        printable strings (ASCII + UTF-16LE), min length
    hexdump  FILE [-o OFF] [-l N]  classic hexdump view
    carve    FILE [-d OUTDIR]     find/extract embedded files by magic signature
    exif     FILE                 read EXIF metadata from an image (needs Pillow)

EXAMPLES
    python forensics-helpers.py entropy suspicious.bin
    python forensics-helpers.py strings dump.raw -n 6
    python forensics-helpers.py carve  challenge.png -d out/
    python forensics-helpers.py exif   photo.jpg

INSTALL (only needed for the `exif` subcommand):
    pip install pillow
"""

import os
import sys
import math
import argparse

# ----------------------------------------------------------------------------
# Magic-byte signatures.  (signature_bytes, label, file_extension)
# Used by both `magic` (identify) and `carve` (find embedded copies).
# ----------------------------------------------------------------------------
MAGICS = [
    (b"\x89PNG\r\n\x1a\n",       "PNG image",            "png"),
    (b"\xff\xd8\xff",            "JPEG image",           "jpg"),
    (b"GIF87a",                  "GIF image",            "gif"),
    (b"GIF89a",                  "GIF image",            "gif"),
    (b"BM",                      "BMP image",            "bmp"),
    (b"%PDF",                    "PDF document",         "pdf"),
    (b"PK\x03\x04",              "ZIP / Office / JAR",   "zip"),
    (b"PK\x05\x06",             "ZIP (empty archive)",  "zip"),
    (b"Rar!\x1a\x07\x00",        "RAR archive (v4)",     "rar"),
    (b"Rar!\x1a\x07\x01\x00",    "RAR archive (v5)",     "rar"),
    (b"\x1f\x8b\x08",            "GZIP archive",         "gz"),
    (b"\x42\x5a\x68",            "BZIP2 archive",        "bz2"),
    (b"\xfd7zXZ\x00",            "XZ archive",           "xz"),
    (b"7z\xbc\xaf\x27\x1c",      "7-Zip archive",        "7z"),
    (b"\x7fELF",                 "ELF executable",       "elf"),
    (b"MZ",                      "Windows PE/EXE",       "exe"),
    (b"OggS",                    "OGG media",            "ogg"),
    (b"ID3",                     "MP3 audio (ID3)",      "mp3"),
    (b"RIFF",                    "RIFF (WAV/AVI)",       "riff"),
    (b"\x00\x00\x01\x00",        "ICO icon",             "ico"),
    (b"SQLite format 3\x00",     "SQLite database",      "sqlite"),
]


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


# ----------------------------------------------------------------------------
# magic -- identify a file by its leading bytes
# ----------------------------------------------------------------------------
def cmd_magic(args):
    data = read_file(args.file)
    head = data[:32]
    for sig, label, _ext in MAGICS:
        if data.startswith(sig):
            print(f"[+] {label}  (signature {sig!r})")
            break
    else:
        print("[-] no known magic at offset 0")
    print(f"    first bytes: {head.hex(' ')}")
    print(f"    size: {len(data)} bytes")


# ----------------------------------------------------------------------------
# entropy -- Shannon entropy in bits/byte (0..8).
#   ~8.0  -> encrypted / compressed / packed
#   ~4-6  -> normal text / executables
#   low   -> sparse / padded data
# ----------------------------------------------------------------------------
def shannon_entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent

def cmd_entropy(args):
    data = read_file(args.file)
    ent = shannon_entropy(data)
    print(f"[*] entropy: {ent:.4f} bits/byte  ({len(data)} bytes)")
    if ent > 7.5:
        print("    -> HIGH: likely encrypted, compressed, or packed")
    elif ent > 6.0:
        print("    -> moderate: compressed/binary content")
    else:
        print("    -> low: plain text / structured / padded data")


# ----------------------------------------------------------------------------
# strings -- extract printable runs (ASCII and UTF-16LE) of >= min length
# ----------------------------------------------------------------------------
def extract_strings(data, min_len=4):
    results = []
    # ASCII runs
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                results.append(cur.decode("ascii"))
            cur = bytearray()
    if len(cur) >= min_len:
        results.append(cur.decode("ascii"))

    # UTF-16LE runs (ASCII char followed by 0x00) -- common in Windows artifacts
    cur = bytearray()
    i = 0
    while i < len(data) - 1:
        if 32 <= data[i] < 127 and data[i + 1] == 0:
            cur.append(data[i])
            i += 2
        else:
            if len(cur) >= min_len:
                results.append("(utf16) " + cur.decode("ascii"))
            cur = bytearray()
            i += 1
    if len(cur) >= min_len:
        results.append("(utf16) " + cur.decode("ascii"))
    return results

def cmd_strings(args):
    data = read_file(args.file)
    for s in extract_strings(data, args.n):
        print(s)


# ----------------------------------------------------------------------------
# hexdump -- classic offset | hex | ascii view
# ----------------------------------------------------------------------------
def hexdump(data, base=0, width=16):
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + off:08x}  {hexpart}  |{asciipart}|")
    return "\n".join(lines)

def cmd_hexdump(args):
    data = read_file(args.file)
    end = len(data) if args.length is None else args.offset + args.length
    print(hexdump(data[args.offset:end], base=args.offset))


# ----------------------------------------------------------------------------
# carve -- find magic signatures past offset 0 and dump each to a file.
# Simple/naive (no length parsing) but catches the classic "file hidden inside
# another file" trick. For thorough work use `binwalk`.
# ----------------------------------------------------------------------------
def cmd_carve(args):
    data = read_file(args.file)
    os.makedirs(args.outdir, exist_ok=True)
    found = 0
    for sig, label, ext in MAGICS:
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx == -1:
                break
            # Skip the file's own header at offset 0 -- we want EMBEDDED data.
            if idx != 0:
                out = os.path.join(args.outdir, f"carved_{idx}_{ext}.{ext}")
                with open(out, "wb") as f:
                    f.write(data[idx:])   # dump from signature to EOF
                print(f"[+] {label} at offset {idx} (0x{idx:x}) -> {out}")
                found += 1
            start = idx + 1
    if not found:
        print("[-] no embedded signatures found (try `binwalk` for deep carving)")
    else:
        print(f"[*] {found} candidate(s) written to {args.outdir}/  "
              f"(trim trailing data manually)")


# ----------------------------------------------------------------------------
# exif -- read image metadata via Pillow
# ----------------------------------------------------------------------------
def cmd_exif(args):
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
    except ImportError:
        print("[-] Pillow not installed -> pip install pillow  (or use exiftool)")
        return
    img = Image.open(args.file)
    print(f"[*] format={img.format} size={img.size} mode={img.mode}")

    exif = img.getexif()
    if not exif:
        print("[-] no EXIF metadata")
        return
    for tag_id, value in exif.items():
        tag = TAGS.get(tag_id, tag_id)
        if tag == "GPSInfo":
            print("    GPSInfo:")
            for gk, gv in value.items():
                print(f"        {GPSTAGS.get(gk, gk)}: {gv}")
        else:
            # Trim long binary blobs so the output stays readable.
            sval = str(value)
            print(f"    {tag}: {sval[:120]}")


# ----------------------------------------------------------------------------
# argparse wiring
# ----------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        description="CTF forensics helpers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="run a subcommand with -h for its options",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("magic", help="detect file type by magic bytes")
    sp.add_argument("file"); sp.set_defaults(func=cmd_magic)

    sp = sub.add_parser("entropy", help="Shannon entropy (encryption/packing)")
    sp.add_argument("file"); sp.set_defaults(func=cmd_entropy)

    sp = sub.add_parser("strings", help="extract printable strings")
    sp.add_argument("file")
    sp.add_argument("-n", type=int, default=4, help="minimum length (default 4)")
    sp.set_defaults(func=cmd_strings)

    sp = sub.add_parser("hexdump", help="hexdump a file (or a slice)")
    sp.add_argument("file")
    sp.add_argument("-o", "--offset", type=int, default=0, help="start offset")
    sp.add_argument("-l", "--length", type=int, default=None, help="byte count")
    sp.set_defaults(func=cmd_hexdump)

    sp = sub.add_parser("carve", help="carve embedded files by magic bytes")
    sp.add_argument("file")
    sp.add_argument("-d", "--outdir", default="carved", help="output dir")
    sp.set_defaults(func=cmd_carve)

    sp = sub.add_parser("exif", help="read image EXIF metadata (needs Pillow)")
    sp.add_argument("file"); sp.set_defaults(func=cmd_exif)

    return p


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
