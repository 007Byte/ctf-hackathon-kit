#!/usr/bin/env python3
"""
extract-files.py - Carve / extract files out of a PCAP.

AUTHORIZED USE ONLY: Use only on CTF challenges, your own lab traffic, or
captures you are explicitly authorised to inspect.

Two complementary passes:

  1. HTTP-aware extraction:
       Reassembles TCP streams, finds HTTP responses, splits headers from the
       body, decodes chunked / gzip / deflate transfer encodings, and saves the
       body with a filename derived from the request URI and/or content-type.

  2. Generic magic-byte carver:
       Concatenates every TCP/UDP payload per stream and scans for known file
       signatures (JPG, PNG, GIF, PDF, ZIP, GZIP, ELF), carving from each
       signature to a sensible end marker (or end of stream).

Pure scapy + stdlib.

Examples:
    python3 extract-files.py capture.pcap -o loot/
    python3 extract-files.py capture.pcap -o loot/ --carve-only
    python3 extract-files.py capture.pcap -o loot/ --http-only
"""

import sys
import os
import argparse
import re
import gzip
import zlib
import hashlib
from collections import defaultdict
from urllib.parse import urlparse, unquote

# ---------------------------------------------------------------------------
# Graceful scapy import
# ---------------------------------------------------------------------------
try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import rdpcap, Raw, IP, IPv6, TCP, UDP
except ImportError:
    sys.stderr.write(
        "[!] scapy is not installed.\n"
        "    Install it with:  pip install scapy\n"
    )
    sys.exit(2)


# ---------------------------------------------------------------------------
# Magic-byte table.  (signature_bytes, extension, optional_trailer)
# ---------------------------------------------------------------------------
MAGIC = [
    (b"\xff\xd8\xff", "jpg", b"\xff\xd9"),                 # JPEG (EOI marker)
    (b"\x89PNG\r\n\x1a\n", "png", b"IEND\xaeB`\x82"),      # PNG (IEND chunk)
    (b"GIF87a", "gif", b"\x00\x3b"),                       # GIF87a
    (b"GIF89a", "gif", b"\x00\x3b"),                       # GIF89a
    (b"%PDF", "pdf", b"%%EOF"),                            # PDF
    (b"PK\x03\x04", "zip", None),                          # ZIP / docx / jar...
    (b"\x1f\x8b\x08", "gz", None),                         # GZIP
    (b"\x7fELF", "elf", None),                             # ELF binary
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def load_pcap(path):
    if not os.path.isfile(path):
        sys.stderr.write(f"[!] File not found: {path}\n")
        sys.exit(1)
    try:
        return rdpcap(path)
    except Exception as exc:
        sys.stderr.write(f"[!] Failed to read pcap '{path}': {exc}\n")
        sys.exit(1)


def ensure_outdir(path):
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as exc:
        sys.stderr.write(f"[!] Cannot create output dir '{path}': {exc}\n")
        sys.exit(1)


def get_l3(pkt):
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    return None, None


def stream_key(pkt):
    """Directional key so we can keep request- and response-side bytes ordered."""
    src, dst = get_l3(pkt)
    if src is None or not pkt.haslayer(TCP):
        return None
    return (src, int(pkt[TCP].sport), dst, int(pkt[TCP].dport))


def bidi_key(pkt):
    """Canonical (sorted) key identifying both directions of one TCP stream."""
    src, dst = get_l3(pkt)
    if src is None or not pkt.haslayer(TCP):
        return None
    a = (src, int(pkt[TCP].sport))
    b = (dst, int(pkt[TCP].dport))
    return tuple(sorted((a, b)))


def safe_name(name, fallback):
    """Sanitise a candidate filename; fall back if it becomes empty."""
    name = unquote(name)
    name = os.path.basename(name)
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("._")
    return name or fallback


def write_file(outdir, name, data, written, label):
    """Write data, avoiding collisions; print a short report line."""
    path = os.path.join(outdir, name)
    base, ext = os.path.splitext(name)
    i = 1
    while os.path.exists(path):
        path = os.path.join(outdir, f"{base}_{i}{ext}")
        i += 1
    with open(path, "wb") as fh:
        fh.write(data)
    digest = hashlib.sha256(data).hexdigest()[:16]
    written.append(path)
    print(f"  [+] {label:<10} {os.path.basename(path):<32} "
          f"{len(data):>9} bytes  sha256:{digest}")


def detect_ext(data):
    """Return an extension based on leading magic bytes, or 'bin'."""
    for sig, ext, _ in MAGIC:
        if data.startswith(sig):
            return ext
    return "bin"


# ---------------------------------------------------------------------------
# Pass 1: HTTP-aware extraction
# ---------------------------------------------------------------------------
def reassemble_directional_streams(packets):
    """Return {directional_key: concatenated_payload_bytes}."""
    buffers = defaultdict(bytearray)
    for pkt in packets:
        if not pkt.haslayer(Raw):
            continue
        key = stream_key(pkt)
        if key is None:
            continue
        buffers[key] += bytes(pkt[Raw].load)
    return buffers


def parse_http_responses(blob):
    """
    Yield (headers_dict, body_bytes, status_line) for each HTTP response found
    in a concatenated server->client byte stream. Handles pipelined responses.
    """
    pos = 0
    while True:
        idx = blob.find(b"HTTP/", pos)
        if idx == -1:
            return
        hdr_end = blob.find(b"\r\n\r\n", idx)
        if hdr_end == -1:
            return
        header_blob = blob[idx:hdr_end]
        body_start = hdr_end + 4

        lines = header_blob.split(b"\r\n")
        status_line = lines[0].decode("latin-1", "replace")
        headers = {}
        for line in lines[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")

        # Determine body length / encoding.
        body = b""
        te = headers.get("transfer-encoding", "").lower()
        cl = headers.get("content-length")

        if "chunked" in te:
            body, consumed = _dechunk(blob[body_start:])
            next_pos = body_start + consumed
        elif cl is not None and cl.isdigit():
            length = int(cl)
            body = blob[body_start:body_start + length]
            next_pos = body_start + length
        else:
            # No length info: take until the next response or end of blob.
            nxt = blob.find(b"HTTP/", body_start)
            end = nxt if nxt != -1 else len(blob)
            body = blob[body_start:end]
            next_pos = end

        # Decompress content-encoding if present.
        ce = headers.get("content-encoding", "").lower()
        body = _decompress(body, ce)

        yield headers, body, status_line
        pos = max(next_pos, idx + 1)


def _dechunk(data):
    """Decode HTTP chunked transfer-encoding. Returns (body, bytes_consumed)."""
    out = bytearray()
    pos = 0
    n = len(data)
    while pos < n:
        line_end = data.find(b"\r\n", pos)
        if line_end == -1:
            break
        size_field = data[pos:line_end].split(b";")[0].strip()
        try:
            size = int(size_field, 16)
        except ValueError:
            break
        pos = line_end + 2
        if size == 0:
            # Skip trailing CRLF / trailers.
            trailer_end = data.find(b"\r\n", pos)
            pos = (trailer_end + 2) if trailer_end != -1 else n
            break
        out += data[pos:pos + size]
        pos += size + 2  # skip chunk data + trailing CRLF
    return bytes(out), pos


def _decompress(body, encoding):
    """Best-effort gzip/deflate decompression; return original on failure."""
    try:
        if encoding == "gzip":
            return gzip.decompress(body)
        if encoding == "deflate":
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
    except Exception:
        pass
    return body


def parse_http_request_uris(blob):
    """Yield request URIs (paths) found in a client->server byte stream."""
    for m in re.finditer(rb"(?:GET|POST|PUT|HEAD)\s+(\S+)\s+HTTP/", blob):
        yield m.group(1).decode("latin-1", "replace")


def http_extract(packets, outdir, written):
    print("[*] HTTP extraction pass")
    directional = reassemble_directional_streams(packets)

    # Map each bidi stream to its two directional buffers so we can correlate
    # response bodies with the request URIs from the opposite direction.
    bidi = defaultdict(dict)
    for (src, sport, dst, dport), buf in directional.items():
        key = tuple(sorted(((src, sport), (dst, dport))))
        bidi[key][(src, sport)] = buf

    count = 0
    for key, dirs in bidi.items():
        # Collect candidate request URIs from whichever side has them.
        uris = []
        for buf in dirs.values():
            uris.extend(parse_http_request_uris(buf))

        # Parse responses from whichever side contains "HTTP/" responses.
        for buf in dirs.values():
            for headers, body, status in parse_http_responses(buf):
                if not body:
                    continue
                ctype = headers.get("content-type", "")
                # Build a filename: prefer URI basename, else content-type ext.
                name = None
                if uris:
                    cand = urlparse(uris.pop(0)).path
                    name = safe_name(cand, "")
                if not name or "." not in name:
                    ext = _ext_from_ctype(ctype) or detect_ext(body)
                    name = safe_name(name, f"http_obj_{count}")
                    if "." not in name:
                        name = f"{name}.{ext}"
                write_file(outdir, name, body, written,
                           label=f"HTTP {status.split()[1] if len(status.split())>1 else ''}".strip())
                count += 1
    if count == 0:
        print("  (no HTTP response bodies recovered)")


def _ext_from_ctype(ctype):
    """Map a Content-Type to a file extension for common CTF objects."""
    ctype = ctype.split(";")[0].strip().lower()
    table = {
        "image/jpeg": "jpg", "image/png": "png", "image/gif": "gif",
        "application/pdf": "pdf", "application/zip": "zip",
        "application/gzip": "gz", "text/html": "html", "text/plain": "txt",
        "application/json": "json", "application/octet-stream": "bin",
        "application/javascript": "js", "text/css": "css",
        "application/x-executable": "elf",
    }
    return table.get(ctype)


# ---------------------------------------------------------------------------
# Pass 2: generic magic-byte carver
# ---------------------------------------------------------------------------
def carve_streams(packets, outdir, written):
    print("[*] Magic-byte carving pass")
    # Concatenate ALL payload bytes per bidirectional stream.
    buffers = defaultdict(bytearray)
    for pkt in packets:
        if not pkt.haslayer(Raw):
            continue
        key = bidi_key(pkt)
        if key is None:
            # Also carve UDP payloads (e.g. TFTP) under a UDP-ish key.
            if pkt.haslayer(UDP) and pkt.haslayer(Raw):
                src, dst = get_l3(pkt)
                if src:
                    key = ("udp", src, dst)
                else:
                    continue
            else:
                continue
        buffers[key] += bytes(pkt[Raw].load)

    count = 0
    for key, blob in buffers.items():
        blob = bytes(blob)
        for sig, ext, trailer in MAGIC:
            start = 0
            while True:
                idx = blob.find(sig, start)
                if idx == -1:
                    break
                if trailer:
                    end = blob.find(trailer, idx + len(sig))
                    end = (end + len(trailer)) if end != -1 else len(blob)
                else:
                    # Unbounded format: carve to next different signature or EOF.
                    end = len(blob)
                    for sig2, _, _ in MAGIC:
                        nxt = blob.find(sig2, idx + len(sig))
                        if nxt != -1:
                            end = min(end, nxt)
                data = blob[idx:end]
                if len(data) > len(sig):  # skip degenerate carves
                    write_file(outdir, f"carved_{count}.{ext}", data,
                               written, label="CARVE")
                    count += 1
                start = idx + len(sig)
    if count == 0:
        print("  (no files carved from raw payloads)")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Extract / carve files from a PCAP (authorised CTF/lab use only).",
    )
    parser.add_argument("pcap", help="Path to the .pcap / .pcapng file")
    parser.add_argument("-o", "--outdir", default="extracted",
                        help="Output directory (default: ./extracted)")
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--http-only", action="store_true",
                     help="Only run the HTTP-aware extraction pass")
    grp.add_argument("--carve-only", action="store_true",
                     help="Only run the generic magic-byte carver")
    args = parser.parse_args(argv)

    packets = load_pcap(args.pcap)
    ensure_outdir(args.outdir)
    print(f"[*] Loaded {len(packets)} packets from {args.pcap}")
    print(f"[*] Output directory: {os.path.abspath(args.outdir)}")

    written = []
    if not args.carve_only:
        http_extract(packets, args.outdir, written)
    if not args.http_only:
        carve_streams(packets, args.outdir, written)

    print(f"\n[*] Done. {len(written)} file(s) written to {os.path.abspath(args.outdir)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
