# NE (New Executable) format notes

## Header field offsets

`e_lfanew` at MZ+0x3C (uint32) points at the `NE` signature. All offsets below are
relative to that signature. Getting these wrong is the single most common way to
conclude "the file is corrupt" — the fields are byte/word mixed, so a naive
"all uint16" read shifts everything.

| Off | Size | Field | Notes |
|-----|------|-------|-------|
| 0x00 | 2 | `ne_magic` | `NE` |
| 0x02 | 1 | `ne_ver` | linker major |
| 0x03 | 1 | `ne_rev` | linker minor |
| 0x04 | 2 | `ne_enttab` | offset to entry table, from NE start |
| 0x06 | 2 | `ne_cbenttab` | entry table length |
| 0x08 | 4 | `ne_crc` | |
| 0x0C | 2 | `ne_flags` | bit 0x8000 = library / no entry point |
| 0x0E | 2 | `ne_autodata` | |
| 0x10 | 2 | `ne_heap` | |
| 0x12 | 2 | `ne_stack` | |
| 0x14 | 4 | `ne_csip` | IP then CS (two uint16) |
| 0x18 | 4 | `ne_sssp` | SP then SS |
| 0x1C | 2 | `ne_cseg` | segment count |
| 0x1E | 2 | `ne_cmod` | module reference count |
| 0x20 | 2 | `ne_cbnrestab` | non-resident names length |
| 0x22 | 2 | `ne_segtab` | **segment table offset** |
| 0x24 | 2 | `ne_rsrctab` | **resource table offset** |
| 0x26 | 2 | `ne_restab` | resident names offset |
| 0x28 | 2 | `ne_modtab` | module reference table offset |
| 0x2A | 2 | `ne_imptab` | imported names offset |
| 0x2C | 4 | `ne_nrestab` | non-resident names, **absolute file offset** |
| 0x30 | 2 | `ne_cmovent` | movable entry count |
| 0x32 | 2 | `ne_align` | **alignment shift** (9 = 512 bytes, 4 = 16 bytes) |
| 0x34 | 2 | `ne_cres` | resource count (often 0 even when resources exist) |
| 0x36 | 1 | `ne_exetyp` | 1 = fullscreen, 2 = Windows PM, 3 = PM, 4 = PM, 5 = PM |
| 0x3E | 2 | `ne_expver` | expected Windows version |

Note `ne_nrestab` is a **file offset**, everything else in the header is NE-relative.

## Segment table

`ne_seg_count` entries of 8 bytes, each: `uint16 sector_offset`, `uint16 length`,
`uint16 flags`, `uint16 min_alloc`.

- File offset is `sector_offset << ne_align`.
- Length is in units of `1 << ne_align`. `length == 0` means 65536.
- Flag bit 0x0001 = data (else code), 0x0100 = segment has relocation data (the
  on-disk length then includes the relocation block), 0x8000 = segment is loaded
  into the data area.

**`ne_align == 4` is legal and a red flag for installers.** With 16-byte alignment a
`length` field of `0x30af` means 199408 bytes, which can easily overlap the next
declared segment and exceed the real code. Installer stubs routinely emit segment
tables that describe nothing real. Never derive the payload start from them.

## Resource table

At `ne_rsrctab`: `uint16 alignment_shift`, then a type table. Each type record is
`namelen byte + name` (namelen 0 means a uint16 type ID follows), then `uint16
count`, then that many `namelen + name` + `uint16 record_offset` (relative to
`ne_rsrctab`).

Each resource record: `uint16 name_off`, `uint16 name_len`, `uint16 type`,
`uint32 data_offset`, `uint32 length`, `uint16 flags`, `uint16 id`. Data offset is
in alignment-shift units.

Parse failures here are normal. `ne_cres == 0` does not mean no resources, and a
malformed table usually only costs you the icons — never the overlay payload, which
this table does not describe at all.

## Wise Installation System overlay

Wise 32-bit installers carry a documented overlay header (`DllNameLen` byte, then
deflated sizes for `WiseColors.dib`, `WiseScript.bin`, `WISE0001.DLL`, `CTL3D32.DLL`,
`OCXREG32.EXE`, `PROGRESS.DLL`, `FILE00XX.DAT`, ending with an `EOF` field).

The **16-bit** Wise installers do not use that structure reliably. The stream-level
truth is simpler and more useful:

```
[ raw deflate stream ][ uint32 LE crc32(inflated) ]  repeated until EOF
```

Member order observed: install script, `WISE0001.DLL`, `CTL3D.DLL`, the application
binary, a fixed-width filename table, the data files, then the runtime DLLs. The
install script is plaintext and holds the whole manifest.

Wise payload is **not** zlib (`0x78` header) and **not** gzip (`1f 8b`). It is bare
DEFLATE, so `zlib.decompressobj(-15)` is the correct call and no signature scanner
will ever find its start.

---

# Case study: McDonnell Douglas screen saver (1997)

`mdc.exe`, 1 451 728 bytes, recovered from a 3.5" floppy. NE, `ver 5.60`,
`ne_align = 4`, `cseg = 2`, no entry point of interest.

### What previous attempts got wrong

| Assumption | Reality |
|---|---|
| The file is the screen saver | It is an installer; the saver is a member |
| Payload is encrypted / custom-compressed | Standard DEFLATE (RFC1951), `zlib` handles it |
| Payload sits in the resource table | Table holds icons only; payload is an overlay the NE header never describes |
| binwalk found nothing, so nothing is embedded | Raw deflate has no header to match |

`xxd` hits at `0a05`, `ffd8`, `424d` were all coincidence — random bytes produce a
two-byte pattern roughly every 64 KiB.

### How the packager was identified

Strings in the low region, found before any disassembly:

```
Please run this installation $under Windows 3.1 or higher.
GLBSInstall / WiseMain / UpdateScreen / DisplayGraphics / DiskPrompt / FileWrite
WISE0001 / WISEMAIN / CTL3D.DLL
```

Decision made in one step: Wise Installation System → raw deflate walk.

### Structure recovered

Deflate walk from `0x3e6e`, 21 members, ending exactly at EOF `0x1626d0`:

| # | Offset | Comp | Infl | Content |
|---|--------|------|------|---------|
| 0 | 0x3e6e | 1478 | 3129 | WiseScript — plaintext install manifest |
| 1 | 0x4438 | 40077 | 71968 | `WISE0001.DLL` (installer engine) |
| 2 | 0xe0c9 | 12027 | 26000 | `CTL3D.DLL` |
| 3 | 0x10fc8 | 21993 | 64337 | `MCDONNEL.SCR` — the screen saver itself |
| 4 | 0x165b5 | 86 | 880 | filename table: 11 × 80-byte records |
| 5–15 | 0x1660f… | — | — | 11 × JPEG, 640×480, JFIF |
| 16 | 0x1060d5 | 27712 | 62688 | `FXIMG300.VBX` |
| 17 | 0x10cd19 | 64013 | 132544 | `IMGFX300.DLL` |
| 18 | 0x11c72a | 28703 | 72352 | `FXTLS300.DLL` |
| 19 | 0x12374d | 26686 | 62944 | `FXLBL300.VBX` |
| 20 | 0x129f8f | 231229 | 398416 | `VBRUN300.DLL` |

Manifest inside the install script:

```
%WIN%\MCDONNEL.SCR           Screen Saver
%WIN%\MCDONNEL.DAT           config, generated at install (not in the archive)
%WIN%\MCDONNEL\*.JPG         Images ×11
%SYS%\FXIMG300.VBX / IMGFX300.DLL / FXTLS300.DLL / FXLBL300.VBX / VBRUN300.DLL
```

The `.SCR` carries `Cannot access data files. Please reinstall this screen saver.` —
it resolves images relative to `%WIN%\MCDONNEL\`, so the directory layout from the
manifest must be reproduced for the saver to run.

### Detail worth remembering

The screen saver engine is third-party: **Screen Pix**, with a shareware string
still embedded — `You may select up to four images in this shareware version`. The
company only badge-engineered it. Checking for such limitations is worth doing
before promising that the extracted program is the "full" product.

### Timing

Full pipeline, automatic: ~0.35 s for the probe-and-walk on a 1.4 MB file, versus
minutes of manual slicing. Earlier manual `dd` slicing plus binwalk produced nothing
in far longer.
