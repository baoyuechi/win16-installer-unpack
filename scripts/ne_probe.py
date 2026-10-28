#!/usr/bin/env python3
"""Probe a legacy 16-bit Windows executable (NE/LE/LX) and locate unreferenced payload.

Usage:
    python3 ne_probe.py <file.exe> [--strings] [--json]

Reports:
  * MZ/NE header field values at their real offsets
  * segment table (file offset, size, flags)
  * which byte ranges of the file are NOT covered by any segment or resource
    -> that "orphan tail" is where installer overlays / packed payloads live
  * per-4KiB entropy profile across the orphan tail
  * printable strings in the low region, matched against known installer-builder
    signatures (Wise, InstallShield, Inno, NSIS, ...)

Exit code is always 0 unless the file is unreadable; use the printed report.
"""

import argparse
import collections
import json
import math
import re
import struct
import sys

NE_MAGIC = b"NE"
LE_MAGIC = b"LE"

# Strings that identify which packager produced the file.
BUILDER_SIGNATURES = {
    "Wise Installation System": [b"WISEMAIN", b"WISE0001", b"GLBSInstall", b"WiseMain",
                                 b"UpdateScreen", b"DisplayGraphics", b"DiskPrompt"],
    "InstallShield (16-bit)": [b"_isys", b"InstallShield", b"ISInst", b"_SETUP.DLL"],
    "Inno Setup": [b"Inno Setup Setup", b"InnoSetup"],
    "NSIS": [b"Nullsoft.NSIS", b"NSIS Error"],
    "InstallShield 5+/cab": [b"ISc("],
    "Delphi/BCB self-extractor": [b"Inno Setup", b"Setup Factory"],
    "Setup Factory": [b"Setup Factory", b"setupfactory"],
    "Visual Basic 3 runtime": [b"VBRUN300", b"___EXPORTEDSTUB"],
    "Win32 NE->PE thunk": [b"This program requires Microsoft Windows"],
}


def read(path):
    with open(path, "rb") as f:
        return f.read()


def parse_ne(d):
    """Return dict with NE header fields using the real (documented) offsets."""
    if d[:2] != b"MZ":
        raise SystemExit("not an MZ file")
    e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    if e_lfanew + 2 > len(d) or d[e_lfanew:e_lfanew + 2] not in (NE_MAGIC, LE_MAGIC):
        raise SystemExit(f"no NE/LE signature at 0x{e_lfanew:x} (sig={d[e_lfanew:e_lfanew+2]!r})")
    n = e_lfanew

    def B(o):
        return d[n + o]

    def w(o):
        return struct.unpack_from("<H", d, n + o)[0]

    def dw(o):
        return struct.unpack_from("<I", d, n + o)[0]

    h = {
        "ne_offset": n,
        "magic": d[n:n + 2].decode(),
        "ver": (B(2), B(3)),
        "enttab": w(4), "cbenttab": w(6), "crc": dw(8),
        "flags": w(0x0C), "autodata": w(0x0E),
        "heap": w(0x10), "stack": w(0x12),
        "csip": (w(0x14), w(0x16)), "sssp": (w(0x18), w(0x1A)),
        "cseg": w(0x1C), "cmod": w(0x1E),
        "cbnrestab": w(0x20),
        "segtab": w(0x22), "rsrctab": w(0x24), "restab": w(0x26),
        "modtab": w(0x28), "imptab": w(0x2A),
        "nrestab": dw(0x2C),
        "cmovent": w(0x30), "align": w(0x32), "cres": w(0x34),
        "exetyp": B(0x36), "flagsothers": B(0x37),
        "pretthunks": w(0x38), "psegrefbytes": w(0x3A),
        "swaparea": w(0x3C), "expver": w(0x3E),
    }
    h["is_library"] = bool(h["flags"] & 0x8000)
    return h


def parse_segments(d, h):
    """Walk the segment table. `align` is a shift count; length is in align units."""
    n = h["ne_offset"]
    shift = h["align"] or 9
    segtab = n + h["segtab"]
    segs = []
    cseg = h["cseg"]
    for i in range(cseg):
        o = segtab + i * 8
        if o + 8 > len(d):
            break
        so, ln, sf, mn = struct.unpack_from("<HHHH", d, o)
        if so == 0 and ln == 0:
            segs.append(None)
            continue
        foff = so << shift
        size = (ln << shift) if ln else 0x10000
        segs.append({
            "index": i + 1, "file_off": foff, "size": size,
            "flags": sf,
            "kind": "DATA" if sf & 1 else "CODE",
            "reloc": bool(sf & 0x100),
            "minalloc": mn,
            "end": min(foff + size, len(d)),
        })
    return segs


def parse_resources(d, h):
    """Best-effort resource walk. Returns (list, note)."""
    n = h["ne_offset"]
    RT = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING",
          7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE",
          12: "GROUP_CURSOR", 14: "GROUP_ICON", 15: "VERSION", 16: "DLGINCLUDE"}
    try:
        rb = n + h["rsrctab"]
        shift = struct.unpack_from("<H", d, rb)[0]
        if shift > 16:
            return [], f"implausible align shift {shift} at 0x{rb:x}"

        def read_name(p):
            ln = d[p]
            if ln == 0:
                return struct.unpack_from("<H", d, p + 1)[0], p + 3
            return d[p + 1:p + 1 + ln].decode("latin-1"), p + 1 + ln

        out = []
        p = rb + 2
        guard = 0
        while guard < 64:
            guard += 1
            tname, p2 = read_name(p)
            if tname == 0:
                break
            cnt = struct.unpack_from("<H", d, p2)[0]
            p2 += 2
            for _ in range(cnt):
                nname, p3 = read_name(p2)
                off = struct.unpack_from("<H", d, p3)[0]
                p2 = p3 + 2
                q = rb + off
                rtype = struct.unpack_from("<H", d, q + 4)[0]
                rmov = struct.unpack_from("<I", d, q + 6)[0]
                rlen = struct.unpack_from("<I", d, q + 10)[0]
                out.append({
                    "type": tname if isinstance(tname, str) else RT.get(tname, tname),
                    "id": nname, "file_off": rmov << shift,
                    "size": rlen << shift if rlen else 0,
                })
            p = p2
        return out, ""
    except Exception as e:  # malformed tables are common
        return [], f"resource table parse stopped: {e}"


def coverage_gaps(d, segs, resources):
    """Byte ranges not claimed by any segment or resource."""
    spans = []
    for s in segs:
        if s:
            spans.append((s["file_off"], s["end"]))
    for r in resources:
        if r["size"] and r["file_off"] < len(d):
            spans.append((r["file_off"], min(r["file_off"] + r["size"], len(d))))
    spans.sort()
    merged = []
    for a, b in spans:
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    gaps = []
    cur = 0
    for a, b in merged:
        if a > cur:
            gaps.append((cur, a))
        cur = max(cur, b)
    if cur < len(d):
        gaps.append((cur, len(d)))
    return [g for g in gaps if g[1] - g[0] >= 4096], merged


def entropy_profile(d, start, end, block=4096):
    rows = []
    for p in range(start, end, block):
        chunk = d[p:p + block]
        if len(chunk) < 256:
            break
        c = collections.Counter(chunk)
        h = -sum(v / len(chunk) * math.log2(v / len(chunk)) for v in c.values())
        rows.append((p, round(h, 2), round(c[0] * 100 / len(chunk))))
    return rows


def high_entropy_start(d, block=4096, thresh=7.5, run=6):
    """First block offset that begins a sustained high-entropy run (payload candidate)."""
    flags = []
    for p in range(0, len(d) - block, block):
        c = collections.Counter(d[p:p + block])
        h = -sum(v / block * math.log2(v / block) for v in c.values())
        flags.append((p, h))
    for i, (p, h) in enumerate(flags):
        if h < thresh:
            continue
        if sum(1 for _, hh in flags[i:i + 8] if hh >= thresh) >= min(run, len(flags) - i):
            return p
    return None


def scan_strings(d, limit, minlen=4):
    return [(m.start(), m.group().decode("latin-1"))
            for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, d[:limit])]


def identify_builders(strings_blob):
    hits = {}
    for name, sigs in BUILDER_SIGNATURES.items():
        found = [s.decode("latin-1") for s in sigs if s in strings_blob]
        if found:
            hits[name] = found
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--strings", action="store_true", help="dump all strings found")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    d = read(a.file)
    h = parse_ne(d)
    segs = parse_segments(d, h)
    resources, rnote = parse_resources(d, h)

    seg_end = max([s["end"] for s in segs if s] or [h["ne_offset"]])
    gaps, merged = coverage_gaps(d, segs, resources)
    low = scan_strings(d, max(seg_end, 0x8000) + 0x2000)
    low_blob = b"\n".join(s.encode("latin-1") for _, s in low)
    builders = identify_builders(low_blob)

    rep = {
        "file": a.file, "size": len(d),
        "header": h, "segments": segs,
        "segment_end": seg_end,
        "resources": resources, "resource_note": rnote,
        "orphan_gaps": gaps,
        "builders": builders,
    }

    if a.json:
        print(json.dumps(rep, indent=2, default=str))
        return

    print(f"file            : {a.file}  ({len(d)} bytes, 0x{len(d):x})")
    print(f"NE offset       : 0x{h['ne_offset']:x}  magic={h['magic']}  ver={h['ver'][0]}.{h['ver'][1]}")
    print(f"flags           : 0x{h['flags']:04x}  {'LIBRARY' if h['is_library'] else 'APPLICATION'}")
    print(f"align shift     : {h['align']}   cseg={h['cseg']}  cmod={h['cmod']}  cres={h['cres']}")
    print(f"ne_segtab       : 0x{h['segtab']:x}  ne_rsrctab=0x{h['rsrctab']:x}  ne_restab=0x{h['restab']:x}")
    print("\nsegments:")
    for s in segs:
        if not s:
            print("  <empty entry>")
            continue
        print(f"  seg{s['index']:2d} @0x{s['file_off']:08x} size={s['size']:7d} "
              f"{s['kind']} reloc={s['reloc']} minalloc={s['minalloc']}"
              f"{'   <-- past EOF!' if s['file_off'] >= len(d) else ''}")

    print(f"\nresources: {len(resources)} entries" + (f"  ({rnote})" if rnote else ""))
    for r in resources[:20]:
        print(f"  {str(r['type']):14s} id={str(r['id']):6s} @0x{r['file_off']:08x} size={r['size']}")
    if len(resources) > 20:
        print(f"  ... {len(resources)-20} more")

    print(f"\norphan (unclaimed) ranges >=4KiB:")
    for g in gaps:
        print(f"  0x{g[0]:08x} .. 0x{g[1]:08x}   {g[1]-g[0]:8d} bytes  ({100*(g[1]-g[0])/len(d):.1f}% of file)")
    if not gaps:
        print("  none — every byte is claimed by a segment or resource")

    # Segment tables in installer-built NE files are frequently junk: entries can
    # overlap each other or extend past EOF. Say so, because the "orphan" math then
    # understates where the payload really begins.
    spans = sorted([(s["file_off"], s["end"]) for s in segs if s])
    overlap = any(spans[i][0] < spans[i - 1][1] for i in range(1, len(spans)))
    oversize = any(s["file_off"] + s["size"] > len(d) for s in segs if s)
    if overlap or oversize:
        print("\n** WARNING: segment table is unreliable "
              f"({'overlapping entries' if overlap else ''}"
              f"{', ' if overlap and oversize else ''}"
              f"{'entries extend past EOF' if oversize else ''}).")
        print("   Trust the entropy boundary below, not the segment sizes.")

    hb = high_entropy_start(d)
    if hb is not None:
        print(f"\nhigh-entropy run starts at 0x{hb:08x} -> payload candidate; "
              f"try: deflate_walk.py {a.file}")

    print(f"\nentropy of the largest orphan range (4KiB blocks), first 12 + last 3:")
    if gaps:
        big = max(gaps, key=lambda g: g[1] - g[0])
        prof = entropy_profile(d, big[0], big[1])
        for row in prof[:12] + (prof[-3:] if len(prof) > 15 else []):
            print(f"  0x{row[0]:08x}  H={row[1]:5.2f}  zero={row[2]:3d}%")
        if len(prof) > 15:
            print(f"  ({len(prof)} blocks total)")
        print("  H ~= 7.9 over a long contiguous run => compressed/encrypted payload, "
              "NOT random damage")

    print("\ninstaller / runtime signatures found in low region:")
    if builders:
        for k, v in builders.items():
            print(f"  * {k}: {', '.join(v)}")
    else:
        print("  (none recognised — inspect strings manually with --strings)")

    if a.strings:
        print("\nall strings:")
        for off, s in low:
            print(f"  0x{off:08x}  {s}")


if __name__ == "__main__":
    sys.exit(main())
