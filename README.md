# EDID generator for Wayland dummy sinks (HDR-capable)

A lightweight, dependency-free Python tool that generates **EDID 1.4 + CTA-861** binaries from a small JSON spec.
Ideal for **headless / virtual HDR displays** (e.g., Sunshine, wlroots dummy sinks).

As far as I know, Sunshine was implementing capture over virtual wlroots sinks but HDR was not supported.

## Features
- EDID 1.4 base block + CTA-861 extension
- HDR static metadata (PQ, HLG, SDR, Traditional HDR)
- Extended colorimetry: BT.2020, DCI-P3
- Multiple modes, refresh rates, or explicit porches
- Built-in validation & hex dump

## Quick Start

You can find a JSON example in the `json_examples` folder.

Example:
- Input spec defines resolutions, refresh rates, and HDR capability
- Output is a `.bin` file containing a valid EDID (e.g., `out/virtual_hdr.bin`)

## Usage
**Command format:**
```bash
python edidgen_v2.py spec.json -o deckhdr.bin [--validate] [--print]
```

Common options:
- `--validate` — Run internal checks
- `--print` — Print EDID as hex dump

Exit codes:
- `0` success
- `1` error
- `2` validation failed

## JSON Spec
Define at least one mode with width (`w`), height (`h`), and refresh rate (`refresh`).
Optionally include:
- `hdr`: enable HDR metadata and 10-bit depth flag
- `interface`: `"DP"` or `"HDMI"`
- `monitor_name`: string shown in EDID
- `porches`: specify custom sync timings (optional)

## Typical Use
- Use generated `.bin` for dummy HDR outputs on Wayland or Sunshine
- Kernel or compositor EDID overrides can reference this file

## Validation
`--validate` ensures:
- Correct 128-byte block alignment
- Valid checksums
- Proper CTA structure

## Limitations
While this script generates valid EDIDs with HDR and modern colorimetry, there are **practical and specification-level limits** you should be aware of:

- **EDID 1.4 pixel clock limit:**
  The Detailed Timing Descriptor (DTD) stores the pixel clock in 10 kHz units using a 16-bit field, so the maximum representable clock is **655.35 MHz**.
  This means:
  - 4K @ 60 Hz (≈ 518 MHz) → OK
  - 4K @ 120 Hz (≈ 1035 MHz) → Not supported (exceeds the EDID limit)
  Modes that exceed this will cause struct packing errors.

- **Static HDR metadata only:**
  The generator advertises HDR (EOTF = PQ, HLG, Traditional HDR) and static metadata type 1 but **does not encode real panel luminance or chromaticity**.

- **Single CTA extension:**
  The current implementation supports only one CTA-861 extension block, so total DTD space is limited. There is a hard limit of 7 resolution/refresh pairs the script can generate. 1080p@60 + 1080p@144 count as 2 pairs.

- **Spec version ceiling:**
  This tool intentionally stays within **EDID 1.4 + CTA-861-G/H** boundaries. It does not yet emit HDMI 2.1 or DisplayID 2.0 blocks that would allow ultra-high-bandwidth modes like 4K120 HDR or 8K60.

## Contributing
PRs and issues welcome!
