#!/usr/bin/env python3
"""Shrink the bundled Inter variable font to the glyphs DirtyFrag can render.

res/font/inter_vf.ttf is upstream Inter v4.1 (rsms/inter, SIL OFL 1.1) in full:
2,852 codepoints / 2,937 glyphs, axes opsz 14-32 and wght 100-900. Half the file
is `gvar` (variable deltas) and a sixth is `GPOS` (kern/mark pairs), both of
which scale with glyph count. The font carries no hinting tables at all, so
subsetting cannot change how a surviving glyph rasterises: outlines, metrics and
variation behaviour of every retained glyph are untouched. Features that are off
by default (cv01-cv14, ss01-ss08, dlig, frac, subs, sups, sinf, numr, ordn, case,
zero, pnum, dnom, aalt, salt) are dropped; the ones a renderer may enable itself
(calt, ccmp, kern, locl, mark, mkmk, rlig, liga) are kept.

Codepoints outside the retained set are not lost - Android walks the system font
fallback chain per character, so a Cyrillic module description renders in
SamsungOne/Noto instead of Inter. Emoji already behave that way; Inter has none.

Provenance: https://github.com/rsms/inter/releases (InterVariable.ttf, v4.1).
Re-download the original and re-run this to regenerate.

    python -m pip install fonttools
    python tools/subset_font.py            # rewrite res/font/inter_vf.ttf, "ship" preset
    python tools/subset_font.py --out C:/tmp.001/cand.ttf
    python tools/subset_font.py --wide     # add Latin Ext-A/B, IPA, math, box drawing
    python tools/subset_font.py --latin-only   # smallest set, Latin-1 plus symbols
    python tools/subset_font.py --pin-opsz     # drop the opsz axis too (opt-in, see below)
"""

import argparse
import os
import sys

from fontTools import subset
from fontTools.ttLib import TTFont

# What the app can plausibly be asked to draw: its own strings (ASCII plus U+2014
# em dash and U+2192 right arrow) and dynamic text - device model, kernel version,
# uname output, module names and descriptions from module.prop, GitHub release
# text, su/log output. Accented Latin and combining marks stay in Inter;
# Cyrillic/Greek/CJK do not, which costs 250+ glyphs per script for text this app
# essentially never shows.
RANGES = [
    (0x0020, 0x007E),  # Basic Latin
    (0x00A0, 0x00FF),  # Latin-1 Supplement (accents, middot, degree)
    (0x0100, 0x017F),  # Latin Extended-A
    (0x0180, 0x024F),  # Latin Extended-B
    (0x0250, 0x02AF),  # IPA Extensions
    (0x02B0, 0x02FF),  # Spacing modifier letters
    (0x0300, 0x036F),  # Combining diacritical marks
    (0x2000, 0x206F),  # General punctuation: dashes, quotes, bullet, ellipsis
    (0x20A0, 0x20BF),  # Currency signs
    (0x2100, 0x214F),  # Letterlike symbols
    (0x2150, 0x218F),  # Number forms
    (0x2190, 0x21FF),  # Arrows (U+2192 lives here)
    (0x2200, 0x22FF),  # Mathematical operators
    (0x2500, 0x257F),  # Box drawing
    (0x2580, 0x259F),  # Block elements (progress bars)
    (0x25A0, 0x25FF),  # Geometric shapes (U+25CF black circle)
    (0x2600, 0x26FF),  # Miscellaneous symbols
    (0x2700, 0x27BF),  # Dingbats (U+2713 check, U+2717 ballot X)
    (0x2B00, 0x2BFF),  # Arrows and symbols supplement
    (0xFB00, 0xFB04),  # Standard ligature forms (fi fl ffi ffl)
    (0xFE00, 0xFE0F),  # Variation selectors (keep emoji sequences intact)
]

LATIN_ONLY_RANGES = [
    (0x0020, 0x007E),
    (0x00A0, 0x00FF),
    (0x2000, 0x206F),
    (0x2190, 0x21FF),
    (0x25A0, 0x25FF),
    (0x2700, 0x27BF),
]

# The set DirtyFrag ships with: everything LATIN_ONLY_RANGES covers plus the
# combining diacritical marks, so a name written in decomposed Unicode (NFD -
# base letter plus a combining mark, which is what macOS-derived filenames and
# some module.prop files contain) still renders its accents in Inter instead of
# half in Inter and half in the system fallback.
SHIP_RANGES = [
    (0x0020, 0x007E),  # Basic Latin
    (0x00A0, 0x00FF),  # Latin-1 Supplement (accents, middot, degree)
    (0x0300, 0x036F),  # Combining diacritical marks
    (0x2000, 0x206F),  # General punctuation: dashes, quotes, bullet, ellipsis
    (0x2100, 0x214F),  # Letterlike symbols (trademark, ohm, estimated)
    (0x2190, 0x21FF),  # Arrows (U+2192 lives here)
    (0x25A0, 0x25FF),  # Geometric shapes (U+25CF black circle)
    (0x2600, 0x26FF),  # Miscellaneous symbols
    (0x2700, 0x27BF),  # Dingbats (U+2713 check, U+2717 ballot X)
]

PRESETS = {
    "ship": SHIP_RANGES,
    "latin-only": LATIN_ONLY_RANGES,
    "wide": RANGES,
}

KEEP_FEATURES = ["calt", "ccmp", "kern", "liga", "locl", "mark", "mkmk", "rlig"]
REQUIRED = (0x2014, 0x2192, 0x25CF, 0x2022, 0x2026, 0x2713, 0x2717, 0x00B7)


def codepoints(ranges):
    out = set()
    for lo, hi in ranges:
        out.update(range(lo, hi + 1))
    out.discard(0)
    return sorted(out)


def summarize(font, label, size):
    print(f"  {label:24s} {size:9,d} B  glyphs={font['maxp'].numGlyphs:5d}  "
          f"codepoints={len(font.getBestCmap()):5d}")
    if "fvar" in font:
        axes = ", ".join(f"{a.axisTag} {a.minValue:g}-{a.maxValue:g}" for a in font["fvar"].axes)
        print(f"    axes: {axes}   named instances: {len(font['fvar'].instances)}")


def report(font, tag):
    for t in ("gvar", "GPOS", "GSUB", "glyf", "cmap", "HVAR", "post"):
        if t in font.reader.tables:
            print(f"    {t:5s} {font.reader.tables[t].length:9,d} B")
    if "GSUB" in font:
        feats = sorted({r.FeatureTag for r in font["GSUB"].table.FeatureList.FeatureRecord})
        print(f"    {tag} features kept: {' '.join(feats)}")


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    default_font = os.path.join(os.path.dirname(here),
                                "app", "src", "main", "res", "font", "inter_vf.ttf")
    ap = argparse.ArgumentParser(description="subset the bundled Inter variable font")
    ap.add_argument("--in", dest="src", default=default_font)
    ap.add_argument("--out", dest="dst", default=None,
                    help="output path (default: rewrite the source in place)")
    ap.add_argument("--preset", choices=sorted(PRESETS), default="ship",
                    help="which codepoint set to keep (default: ship)")
    ap.add_argument("--latin-only", action="store_true",
                    help="shorthand for --preset latin-only")
    ap.add_argument("--wide", action="store_true", help="shorthand for --preset wide")
    ap.add_argument("--pin-opsz", action="store_true",
                    help="pin the opsz axis away, leaving wght only")
    ap.add_argument("--check", action="store_true", help="only report the source")
    args = ap.parse_args()

    src = os.path.abspath(args.src)
    dst = os.path.abspath(args.dst) if args.dst else src
    print(f"source: {src}")
    font = TTFont(src)
    print("-- before --")
    before = font.getBestCmap()
    summarize(font, "source", os.path.getsize(src))
    if args.check:
        return 0

    for cp in (0x2014, 0x2192):
        if cp not in before:
            print(f"refusing: source font lacks U+{cp:04X}", file=sys.stderr)
            return 1

    opts = subset.Options()
    opts.layout_features = KEEP_FEATURES
    # Name ID 0 (copyright notice) and 13/14 (license description / vendor URL)
    # must survive: Inter is under the SIL Open Font License 1.1, which requires
    # the copyright and licence notice to travel with any modified version.
    opts.name_IDs = [0, 1, 2, 3, 4, 5, 6, 11, 13, 14, 16, 17]
    opts.hinting = True
    opts.notdef_outline = True
    opts.desubroutinize = False
    opts.retain_gids = False
    opts.drop_tables += ["DSIG"]

    preset = args.preset
    if args.latin_only:
        preset = "latin-only"
    if args.wide:
        preset = "wide"
    print(f"  preset: {preset}")

    subsetter = subset.Subsetter(options=opts)
    subsetter.populate(unicodes=codepoints(PRESETS[preset]))
    subsetter.subset(font)

    # Pinning after subsetting keeps gvar's lazy glyph dicts consistent; doing it
    # first makes the subsetter walk glyph names that instancing has already
    # dropped (KeyError on the space-named glyphs).
    if args.pin_opsz:
        from fontTools.varLib import instancer
        font = instancer.instantiateVariableFont(font, {"opsz": None}, updateFontNames=False)
        print("  opsz axis pinned at its default (14)")

    os.makedirs(os.path.dirname(dst), exist_ok=True)
    font.save(dst)

    print("-- after --")
    out = TTFont(dst)
    after = out.getBestCmap()
    summarize(out, os.path.basename(dst), os.path.getsize(dst))
    report(out, "GSUB")

    missing = [f"U+{c:04X}" for c in REQUIRED if c not in after]
    ascii_missing = [c for c in range(0x20, 0x7F) if c not in after]
    print(f"  required glyphs present : {'yes' if not missing else 'MISSING ' + str(missing)}")
    print(f"  Basic Latin complete    : {'yes' if not ascii_missing else 'MISSING ' + str(ascii_missing)}")
    saved = os.path.getsize(src) - os.path.getsize(dst)
    print(f"  saved {saved:,d} B raw ({100.0 * saved / os.path.getsize(src):.1f}%)")
    return 0 if not missing and not ascii_missing else 1


if __name__ == "__main__":
    sys.exit(main())
