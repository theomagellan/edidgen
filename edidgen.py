#!/usr/bin/env python3

"""
EDID generator for Wayland dummy sinks (e.g., Sunshine headless HDR display)

Usage
-----
python edidgen_v2.py spec.json -o deckhdr.bin [--quiet] [--validate] [--print]
"""

import argparse
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------- Constants & helpers ----------------------
EDID_BLOCK_LEN = 128
EDID_V14 = (1, 4)
CTA_TAG = 0x02
CTA_REV = 0x03  # minimum rev that supports extended colorimetry/HDR static metadata

# CTA short data block tags
CTA_SVD = 0x01
CTA_AUDIO = 0x02
CTA_VENDOR = 0x03
CTA_SPEAKER = 0x04
CTA_VESA_DTC = 0x05
CTA_COLORIMETRY = 0x07  # short block (legacy)
CTA_EXTENDED = 0x07     # indicates Extended Tag follows

# CTA Extended Tags (when CTA_EXTENDED is used)
EXT_COLORIMETRY = 0x05  # extended colorimetry
EXT_HDR_STATIC_MD = 0x06

# Base block video input bits (digital)
INTERFACE_DP = 0b0101
INTERFACE_HDMI_A = 0b0001

EOTF_BITS = {
    "SDR": 0,
    "TRADITIONAL_HDR": 1,
    "PQ": 2,
    "HLG": 3,
}

COLORIMETRY_FLAGS = {
    # extended colorimetry flags per CTA-861-G/H (payload bits)
    "BT2020_YCC": (0, 0b0010_0000),  # first byte bit5
    "BT2020_RGB": (0, 0b0100_0000),  # first byte bit6
    "DCI_P3_RGB": (1, 0b0000_1100),  # second byte bits2-3 (common practice)
}

@dataclass
class Mode:
    w: int
    h: int
    refresh: List[float]
    porches: Optional[Dict[str, int]] = None  # {hfp,hsw,hbp,vfp,vsw,vbp}


def u8(x: int) -> int:
    return x & 0xFF


def checksum(block: bytes) -> int:
    return (-sum(block) & 0xFF)


def encode_manufacturer_id(eisa3: str) -> bytes:
    """EISA 3-char to 2-byte 5-bit packed code."""
    if len(eisa3) != 3 or not eisa3.isascii():
        raise ValueError("manufacturer must be 3 ASCII chars")
    c1, c2, c3 = (ord(c.upper()) - 64 for c in eisa3)
    val = (c1 & 0x1F) << 10 | (c2 & 0x1F) << 5 | (c3 & 0x1F)
    return struct.pack(">H", val)


def ascii_descriptor(tag: int, text: str) -> bytes:
    """Build an 18-byte ASCII descriptor (0xFC name or 0xFE text)."""
    raw = text.encode("ascii", "ignore")[:13]
    if not raw.endswith(b"\n"):
        raw += b"\n"
    raw = raw[:13].ljust(13, b" ")
    # Spec: 00 00 00 <tag> 00 + 13-byte text
    desc = b"\x00\x00\x00" + bytes([tag, 0x00]) + raw
    return desc


def range_limits_descriptor(vmin: int, vmax: int, hmin: int, hmax: int, pclk_max_mhz: int) -> bytes:
    """
    EDID 1.4 Range Limits (0xFD), 'no timing info' class:
      bytes +5..+9  : vmin, vmax, hmin(kHz), hmax(kHz), max pclk (10 MHz units)
      byte  +10     : 0x01  (range class = 'no timing information')
      bytes +11..17 : 0x0A 0x20 0x20 0x20 0x20 0x20 0x20  (required padding)
    """
    pclk10 = max(0, min(255, pclk_max_mhz // 10))
    payload = bytes([
        vmin & 0xFF, vmax & 0xFF, hmin & 0xFF, hmax & 0xFF, pclk10,
        0x01,                   # byte 10: range class
        0x0A, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20  # bytes 11..17
    ])
    return b"\x00\x00\x00\xFD\x00" + payload


def dtd_from_explicit(w: int, h: int, rr: float, porches: Dict[str, int]) -> bytes:
    """EDID 1.4 Detailed Timing Descriptor (progressive, separate sync)."""
    hfp, hsw, hbp = porches["hfp"], porches["hsw"], porches["hbp"]
    vfp, vsw, vbp = porches["vfp"], porches["vsw"], porches["vbp"]

    hblank = hfp + hsw + hbp
    vblank = vfp + vsw + vbp
    htotal = w + hblank
    vtotal = h + vblank

    pclk_hz = int(round(htotal * vtotal * rr))
    pclk10 = pclk_hz // 10_000  # 10 kHz units

    d = bytearray(18)
    # Pixel clock
    d[0:2] = struct.pack("<H", pclk10)

    # H active / blank
    d[2] = w & 0xFF
    d[3] = hblank & 0xFF
    d[4] = ((w >> 8) & 0xF) << 4 | ((hblank >> 8) & 0xF)

    # V active / blank
    d[5] = h & 0xFF
    d[6] = vblank & 0xFF
    d[7] = ((h >> 8) & 0xF) << 4 | ((vblank >> 8) & 0xF)

    # Sync offsets/widths
    d[8]  = hfp & 0xFF
    d[9]  = hsw & 0xFF
    d[10] = ((vfp & 0xF) << 4) | (vsw & 0xF)
    d[11] = (((hfp >> 8) & 0x3) << 6) | (((hsw >> 8) & 0x3) << 4) \
          | (((vfp >> 4) & 0x3) << 2) | (((vsw >> 4) & 0x3) << 0)

    # Image size/borders: 0 for virtual sink
    d[12] = 0
    d[13] = 0
    d[14] = 0
    d[15] = 0
    d[16] = 0

    # Flags: non-interlaced, digital separate sync, +H +V
    d[17] = 0b00011010  # 0x1A (common choice)
    return bytes(d)


def dtd_from_cvt_rb2(w: int, h: int, rr: float) -> bytes:
    """Simplified CVT-RB v2 timing (safe for high refresh 4K+ modes)."""
    # Typical reduced blanking v2 porches
    porches = dict(hfp=8, hsw=32, hbp=40, vfp=3, vsw=6, vbp=32)
    return dtd_from_explicit(w, h, rr, porches)


# ---------------------- CTA builder ----------------------

def pack_cta_ext_block(payload: bytes) -> bytes:
    """Wrap an Extended CTA Data Block (CTA_EXTENDED)."""
    if len(payload) < 1:
        raise ValueError("extended payload must include tag byte")
    length = len(payload)  # already counts extended tag
    if length > 31:
        raise ValueError("CTA data block too long")
    return bytes([ (CTA_EXTENDED << 5) | length ]) + payload


def cta_colorimetry_block(names: List[str]) -> bytes:
    b0 = 0
    b1 = 0
    for name in names:
        if name not in COLORIMETRY_FLAGS:
            continue
        idx, mask = COLORIMETRY_FLAGS[name]
        if idx == 0:
            b0 |= mask
        else:
            b1 |= mask
    payload = bytes([EXT_COLORIMETRY, b0, b1])
    return pack_cta_ext_block(payload)


def cta_hdr_static_metadata_block() -> bytes:
    # Ensuring maximum HDR compatibility
    eotf_bits = 0b00001111  # SDR, Trad HDR, PQ, HLG
    smd = 0b00000001        # Static metadata type 1 supported
    payload = bytes([EXT_HDR_STATIC_MD, eotf_bits, smd])
    return pack_cta_ext_block(payload)


# ---------------------- EDID builders ----------------------

def build_base_edid(spec: dict, first_dtd: bytes) -> bytes:
    base = bytearray(EDID_BLOCK_LEN)
    # Header
    base[0:8] = b"\x00\xff\xff\xff\xff\xff\xff\x00"

    # Vendor/Product
    man = spec.get("id", {}).get("manufacturer", "SUN")
    base[8:10] = encode_manufacturer_id(man)
    prod = 1
    base[10:12] = struct.pack("<H", prod)
    serial = 0
    base[12:16] = struct.pack("<I", serial)
    base[16] = 0  # mfg week
    base[17] = 2025 - 1990  # mfg year (cosmetic)

    # EDID version/revision
    base[18], base[19] = EDID_V14

    # Video input params (digital)
    bpc = 10 if spec.get("hdr", False) else 8
    bpc_code = {8:2, 10:3}[bpc]
    iface = INTERFACE_DP if spec.get("interface", "DP").upper().startswith("DP") else INTERFACE_HDMI_A
    base[20] = 0x80 | (bpc_code << 4) | iface

    # Physical size (cm)
    base[21] = base[22] = 0  # undefined physical since virtual only

    # Gamma: 2.2 -> 120
    base[23] = 120

    # Color/Features: sRGB default chromaticity, DPMS none, preferred timing present
    base[24] = 0x0A  # default RGB, no DPMS, preferred timing yes (bit1)

# --- Standard Timings (bytes 38–53): set invalid code 0x0101 per EDID 1.4
    for i in range(8):
        base[38 + 2*i] = 0x01
        base[38 + 2*i + 1] = 0x01

    # Chromaticity: leave zeros (virtual); OSes ignore for headless
    # Established/Standard timings -> zero

    # Detailed Timing Descriptors / Monitor descriptors
    ofs = 54
    base[ofs:ofs+18] = first_dtd
    ofs += 18

    # Monitor name
    name = spec.get("monitor_name", "Virtual HDR")
    base[ofs:ofs+18] = ascii_descriptor(0xFC, name)
    ofs += 18

    # Range limits
    # hardcoded with max refresh rate of 144hz
    rl = {"vmin": 48, "vmax": 144, "hmin_khz": 30, "hmax_khz": 255, "pclk_max_mhz": 600}
    base[ofs:ofs+18] = range_limits_descriptor(rl["vmin"], rl["vmax"], rl["hmin_khz"], rl["hmax_khz"], rl["pclk_max_mhz"])
    ofs += 18

    # ASCII text (optional branding)
    base[ofs:ofs+18] = ascii_descriptor(0xFE, "edidgen_v2")

    # Number of extensions
    base[126] = 1

    # pad or truncate base to exactly 128 bytes
    base = (base + b"\x00" * 128)[:128]
    base[127] = checksum(base)

    return bytes(base)


def build_cta_ext(spec: dict, remaining_dtds: List[bytes]) -> bytes:
    cta = bytearray(EDID_BLOCK_LEN)
    cta[0] = CTA_TAG
    cta[1] = CTA_REV

    # Byte 3: CTA flags: set YCbCr 4:4:4 and 4:2:2 support
    cta[3] = 0xC0

    ofs = 4  # start of data block collection

    # Colorimetry block
    # Hardcoded colorimetry values for now, might be useful to be passed in json
    # if needed later on?
    color_list = ["BT2020_RGB", "BT2020_YCC", "DCI_P3_RGB"]
    blk = cta_colorimetry_block(color_list)
    if ofs + len(blk) < 127:
        cta[ofs:ofs+len(blk)] = blk
        ofs += len(blk)

    # HDR static metadata block
    if spec.get("hdr", False):
        blk = cta_hdr_static_metadata_block()
        if ofs + len(blk) < 127:
            cta[ofs:ofs+len(blk)] = blk
            ofs += len(blk)

    # Set DTD offset
    cta[2] = ofs

    # Append remaining DTDs
    for dtd in remaining_dtds:
        if ofs + 18 > 127:
            break  # out of space
        cta[ofs:ofs+18] = dtd
        ofs += 18

    cta[127] = checksum(cta)
    return bytes(cta)


# ---------------------- Validation ----------------------

def basic_validate(edid: bytes) -> Tuple[bool, str]:
    if len(edid) % EDID_BLOCK_LEN != 0:
        return False, "EDID length must be multiple of 128"
    if edid[0:8] != b"\x00\xff\xff\xff\xff\xff\xff\x00":
        return False, "Bad EDID header"
    # Per-block checksum
    for i in range(0, len(edid), EDID_BLOCK_LEN):
        blk = edid[i:i+EDID_BLOCK_LEN]
        if (sum(blk) & 0xFF) != 0:
            return False, f"Checksum fail at block {i//128}"
    # Extension count
    ext = edid[126]
    if ext * 128 + 128 != len(edid):
        return False, "Extension count mismatch"
    # First extension should be CTA
    if ext >= 1 and edid[128] != CTA_TAG:
        return False, "First extension is not CTA-861"
    # CTA DTD offset sanity
    if ext >= 1:
        dtd_ofs = edid[130]
        if not (4 <= dtd_ofs <= 127):
            return False, "CTA DTD offset out of range"
    return True, "OK"


# ---------------------- JSON spec ----------------------

def load_spec(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        spec = json.load(f)
    # Minimal schema guard
    if "modes" not in spec or not isinstance(spec["modes"], list) or not spec["modes"]:
        raise ValueError("spec.modes must be a non-empty list")
    # Normalize modes
    modes: List[Mode] = []
    for m in spec["modes"]:
        w = int(m["w"])
        h = int(m["h"])
        ref = m["refresh"]
        if isinstance(ref, (int, float)):
            ref_list = [float(ref)]
        elif isinstance(ref, list):
            ref_list = [float(x) for x in ref]
        porches = m.get("porches")
        modes.append(Mode(w, h, ref_list, porches))
    spec["_modes"] = modes
    return spec


# ---------------------- Main build ----------------------

def build_edid(spec: dict) -> bytes:
    modes: List[Mode] = spec["_modes"]

    # DTDs
    dtds: List[bytes] = []
    for m in modes:
        for rr in m.refresh:
            if m.porches:
                dtds.append(dtd_from_explicit(m.w, m.h, rr, m.porches))
            else:
                dtds.append(dtd_from_cvt_rb2(m.w, m.h, rr))
    base = build_base_edid(spec, dtds[0])
    cta = build_cta_ext(spec, dtds[1:])
    return base + cta


# ---------------------- CLI ----------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="EDID 1.4 + CTA-861 generator for Wayland dummy HDR sinks")
    p.add_argument("spec", type=Path, help="JSON spec file")
    p.add_argument("-o", "--out", type=Path, required=True, help="Output EDID binary path")
    p.add_argument("--print", action="store_true", help="Print EDID as hex dump")
    p.add_argument("--validate", action="store_true", help="Run internal validator")
    p.add_argument("--quiet", action="store_true", help="Suppress non-error output")
    args = p.parse_args(argv)

    try:
        spec = load_spec(args.spec)
        edid = build_edid(spec)
        if args.validate:
            ok, msg = basic_validate(edid)
            if not ok:
                print(f"Validation failed: {msg}", file=sys.stderr)
                return 2
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_bytes(edid)
        if not args.quiet:
            print(f"Wrote {len(edid)} bytes to {args.out}")
        if args.print:
            print(edid.hex())
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
