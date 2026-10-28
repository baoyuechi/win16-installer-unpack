---
name: win16-installer-unpack
description: Recover files embedded in legacy 16-bit Windows executables (NE/LE format) — 1990s installers and screensavers built with Wise Installation System, InstallShield, or custom self-extractors. This skill should be used when a Win16 .exe/.dll has high-entropy data at its tail that binwalk and `file` cannot identify, when a resource extractor returns only icons, or when asked to unpack an old shareware/installer/screensaver whose payload is assumed to be encrypted or custom-compressed.
agent_created: true
---

# Unpacking 16-bit Windows installers

Payload in a Win16 installer is almost never encrypted or "custom compressed". It is
raw DEFLATE (sometimes LZSS) sitting in an overlay that the NE header does not
describe. Two failure modes dominate:

1. **Assuming the .exe is the program.** A 1990s "screensaver" or "utility" floppy
   usually holds an *installer*; the real program and its data are members of an
   archive inside it. Read strings before reverse engineering anything.
2. **Trusting signature scanners.** A bare deflate stream has no header, no trailer,
   no magic. Entropy ~7.9 bit/byte with zero signature hits is the expected shape,
   not evidence of encryption.

## Workflow

### 1. Identify the packager from strings

Run the probe. It parses the NE header at the real field offsets, walks the segment
table, computes which bytes no structure claims, and matches packager signatures.

```bash
python3 scripts/ne_probe.py target.exe            # report
python3 scripts/ne_probe.py target.exe --strings  # dump all low-region strings
```

Signatures worth acting on: `WiseMain` / `WISE0001` / `GLBSInstall` (Wise
Installation System), `_isys` / `InstallShield` (InstallShield 16-bit), `VBRUN300`
(Visual Basic 3 runtime — the shipped app is VB3, expect VBX/DLL companions),
`Please run this installation under Windows 3.1` (installer stub, not the app).

| Packager | Approach |
|---|---|
| Wise Installation System (16-bit) | raw deflate walk — step 3 |
| InstallShield 3.x `_isys` | `unshield` / `i6comp` on the packed data; not deflate |
| LZSS-style stub | walk with an LZSS decoder anchored on CRC or length fields |
| Unknown | try the deflate walk first; it is by far the most common |

### 2. Establish where the payload starts

Do not use the segment table for this. Installer stubs frequently declare segments
that overlap each other or extend past EOF; the probe warns when it detects that.
Use the **entropy boundary** instead: the first 4 KiB block that begins a sustained
run above ~7.5 bit/byte.

Treat the boundary as an upper bound only. The true first stream commonly starts a
few hundred bytes earlier, because the boundary is block-aligned and the tail of the
last code block may already look random.

### 3. Walk the streams

```bash
python3 scripts/deflate_walk.py target.exe                 # auto-locate + dump
python3 scripts/deflate_walk.py target.exe --start 0x3e6e  # explicit offset
python3 scripts/deflate_walk.py target.exe --list-only     # inspect before writing
```

The script anchors on structure, not signatures: a stream counts only if it inflates
to completion, yields at least 64 bytes, **and** the next 4 bytes equal
`crc32(inflated)`. That CRC check makes false positives effectively impossible and
verifies every member during extraction.

Expected member layout:

```
[ raw deflate stream ][ uint32 LE crc32 of inflated data ]
```

Members are contiguous apart from the 4-byte CRC after each one. If the walk stops
early, re-run with `--resync 1024`; some installers pad to 4- or 8-byte alignment.

### 4. Recover real filenames instead of guessing

Extracted members land as `NN_<offset>.<ext>`. The real names live **inside the
archive**, in two places:

- A **name table** member near the start of the payload, usually fixed-width records
  (80 bytes is common: `NAME.EXT`, a type word, NUL padding). Split on the record
  size and take the first field.
- The **installation script**, which is itself just a member (first entry in Wise
  archives, typically 1–4 KB of plaintext): `%WIN%\APPNAME.SCR`, `%SYS%\VBRUN300.DLL`
  and so on. Grep it for `%WIN%`, `%SYS%`, `.EXE`, `.DLL`, `.JPG`.

Rename from the manifest when the two disagree — the script records what the
installer actually did, including target directories and install order.

### 5. Verify before reporting

Every member's CRC must match. If one fails, the stream boundary is wrong: fix the
boundary rather than accepting the file. For media payloads, confirm dimensions with
`sips -g pixelWidth -g pixelHeight` (macOS) or `file`.

## Reporting the result

State the mechanism explicitly, because the mechanism is the finding:

- what the file actually is (packager, target Windows version, wrapper vs application);
- the seam structure (deflate + crc32, contiguous, N members, ends exactly at EOF);
- why signature scanning was blind to it (no header/trailer/magic in raw deflate);
- a table of members with compressed/inflated sizes and identified types;
- for media, dimensions/codec, and a note that they are ordinary files rather than a
  proprietary format.

When appending to an existing analysis note, keep the original wrong conclusions and
add a correction section listing what was overturned and why. The reasoning trail is
the value, not a clean summary.

## Pitfalls

- **Empty deflate streams.** `03 00` inflates to zero bytes and `crc32(b"")` is 0, so
  a following `00 00 00 00` validates perfectly. Compiled binaries contain thousands
  of these. Always require real output before accepting an anchor.
- **16-bit disassembly is not required** to unpack a payload. Disassemble only to
  explain runtime behaviour (which files the app opens, what it writes to the
  registry). Strings plus structure are enough for extraction.
- **Do not slice at `xxd` hits** like `0a05`, `ffd8`, `424d`. Two-byte patterns occur
  by chance roughly every 64 KiB of random data. Only act after a stream boundary is
  established.
- **VB3-era companions matter.** `VBRUN300.DLL` and `.VBX` controls in the archive
  mean the shipped binary cannot run standalone; say so if the user plans to run it.
- **Bad CRC = wrong boundary.** Never skip the check to make progress.

## Reference

`references/ne-format.md` — NE header field offsets, segment and resource table
layout, the Wise overlay header, and a worked case study (McDonnell Douglas 1997
screen saver) with exact offsets and timings.
