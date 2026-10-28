#!/usr/bin/env python3
"""Walk a sequence of raw DEFLATE streams (RFC1951) out of a legacy installer overlay.

Most 16-bit installers (Wise Installation System, and many InstallShield /
custom self-extractors of the Win16 era) store each payload file as:

    [ raw deflate stream ][ 4-byte little-endian CRC32 of the inflated data ]

with no zlib header, no gzip header, no container filenames and no signature.
binwalk / `file` therefore never match it, and the payload looks like one solid
block of ~7.9-bit/byte noise. This script finds the seams and dumps every member.

Usage:
    python3 deflate_walk.py <file>                  # auto-locate and dump
    python3 deflate_walk.py <file> --start 0x3e6e   # explicit offset
    python3 deflate_walk.py <file> --list-only

The CRC32 check is the anchor: a false positive would require 4 arbitrary bytes
to match crc32 of a successfully terminated inflate, which does not happen.
"""

import argparse
import os
import struct
import sys
import zlib

MAX_OUT = 256 * 1024 * 1024

MAGIC = [
    (b"\xff\xd8\xff", "jpg"),
    (b"\x89PNG", "png"),
    (b"GIF8", "gif"),
    (b"MZ", "exe"),
    (b"BM", "bmp"),
    (b"RIFF", "riff"),
    (b"PK\x03\x04", "zip"),
    (b"\x1f\x8b", "gz"),
    (b"%PDF", "pdf"),
    (b"\xd0\xcf\x11\xe0", "ole"),
    (b"II*\x00", "tif"),
    (b"MM\x00*", "tif"),
    (b"<!DOCTYPE", "html"),
    (b"<?xml", "xml"),
    (b"{\\rtf", "rtf"),
]


def sniff(b):
    for sig, ext in MAGIC:
        if b.startswith(sig):
            return ext
    printable = sum(1 for x in b[:1024] if 32 <= x < 127 or x in (9, 10, 13))
    if len(b) >= 128 and printable / min(len(b), 1024) > 0.92:
        return "txt"
    # 16-bit NE module without MZ? keep generic
    if len(b) > 64 and b[0:1] == b"\x00":
        return "bin"
    return "bin"


def try_inflate(d, p, window=None, max_out=MAX_OUT):
    """Inflate a raw deflate stream at p. Return (data, consumed) or None."""
    if p >= len(d) - 2:
        return None
    o = zlib.decompressobj(-15)
    limit = len(d) if window is None else min(len(d), p + window)
    pos = p
    parts = []
    got = 0
    step = 65536
    while pos < limit:
        chunk = d[pos:min(pos + step, limit)]
        try:
            out = o.decompress(chunk)
        except zlib.error:
            return None
        if out:
            got += len(out)
            if got > max_out:
                return None
            parts.append(out)
        pos += len(chunk)
        if o.eof:
            consumed = pos - p - len(o.unused_data)
            return b"".join(parts), consumed
    return None


def crc_at(d, p):
    if p + 4 > len(d):
        return None
    return struct.unpack_from("<I", d, p)[0]


def anchored(d, p, window=None, min_out=64):
    """A stream counts as a real seam only if it inflates to at least min_out bytes
    and is followed by its own CRC32. Requiring real output rejects the degenerate
    `03 00 00 00 00 00` empty-stream pattern that litters compiled binaries."""
    r = try_inflate(d, p, window)
    if not r:
        return None
    out, used = r
    if len(out) < min_out:
        return None
    if crc_at(d, p + used) == (zlib.crc32(out) & 0xFFFFFFFF):
        return out, used
    return None


def entropy_boundary(d, block=4096, thresh=7.5):
    """First block offset that starts a long run of high entropy, or None."""
    import collections, math
    flags = []
    for p in range(0, len(d) - block, block):
        c = collections.Counter(d[p:p + block])
        h = -sum(v / block * math.log2(v / block) for v in c.values())
        flags.append((p, h))
    for i, (p, h) in enumerate(flags):
        if h < thresh:
            continue
        run = sum(1 for _, hh in flags[i:i + 8] if hh >= thresh)
        if run >= min(6, len(flags) - i):
            return p
    return None


def auto_start(d, back=8192, window=131072):
    """Try entropy boundary first, then 0. Search backwards for an anchored stream."""
    b = entropy_boundary(d)
    cands = []
    if b is not None:
        cands.append(max(0, b - back))
    cands.append(0)
    for c in cands:
        if c == 0:
            continue
        for p in range(c, min(c + back + 64, len(d) - 8)):
            if (((d[p] >> 1) & 3)) == 3:      # BFINAL/BTYPE=11 is invalid
                continue
            if anchored(d, p, window):
                return p, f"entropy boundary 0x{b:x}, stream anchored at 0x{p:x}"
    # last resort: full scan with a small window
    for p in range(0, len(d) - 8):
        if (((d[p] >> 1) & 3)) == 3:
            continue
        if anchored(d, p, window):
            return p, f"full scan hit at 0x{p:x}"
    return None, "no anchored deflate stream found"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--start", type=lambda s: int(s, 0), default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--resync", type=int, default=256,
                    help="bytes to slide when a seam fails (default 256)")
    ap.add_argument("--min-size", type=int, default=0)
    ap.add_argument("--list-only", action="store_true")
    a = ap.parse_args()

    d = open(a.file, "rb").read()
    outdir = a.out or os.path.join(os.path.dirname(os.path.abspath(a.file)), "unpacked")
    if not a.list_only:
        os.makedirs(outdir, exist_ok=True)

    if a.start is None:
        start, why = auto_start(d)
        if start is None:
            sys.exit(f"{why}. Payload may use LZSS/custom RLE or a real container; "
                     f"run ne_probe.py to identify the packager first, then look for "
                     f"the corresponding extractor.")
        print(f"auto-located start: {why}\n")
    else:
        start = a.start
        hit = None
        for q in range(max(0, start - 64), start + 64):
            if anchored(d, q):
                hit = q
                break
        if hit is not None and hit != start:
            print(f"adjusted start 0x{start:x} -> 0x{hit:x}")
            start = hit

    p = start
    idx = 0
    tin = tout = 0
    last_end = start
    while p < len(d) - 8:
        r = try_inflate(d, p)
        if not r or crc_at(d, p + r[1]) != (zlib.crc32(r[0]) & 0xFFFFFFFF):
            nxt = None
            for q in range(p + 1, min(p + 1 + a.resync, len(d) - 8)):
                if anchored(d, q):
                    nxt = q
                    break
            if nxt is None:
                print(f"stop at 0x{p:x}: no further validated stream "
                      f"({len(d) - p} bytes unaccounted)")
                break
            print(f"  resync 0x{p:x} -> 0x{nxt:x} (skipped {nxt - p} bytes)")
            p = nxt
            continue

        out, used = r
        ext = sniff(out)
        name = f"{idx:02d}_{p:08x}.{ext}"
        if len(out) >= a.min_size:
            if not a.list_only:
                with open(os.path.join(outdir, name), "wb") as f:
                    f.write(out)
            print(f"[{idx:02d}] 0x{p:08x} comp={used:7d} infl={len(out):8d} {ext:4s} "
                  f"crc=OK  {out[:16].hex()}")
            idx += 1
            tin += used
            tout += len(out)
            last_end = p + used + 4
        p += used + 4

    print(f"\n{idx} members, {tin} compressed -> {tout} inflated bytes")
    if last_end < len(d):
        print(f"trailing bytes after last member: {len(d) - last_end}")
    if idx and not a.list_only:
        print(f"output: {outdir}")


if __name__ == "__main__":
    main()
