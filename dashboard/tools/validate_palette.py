"""Python twin of the dataviz skill's validate_palette.js, since the Pi has no node.

Same constants and same Machado 2009 severity-1.0 transforms, so the numbers are
comparable to the JS runs quoted in references/palette.md.
"""

import itertools
import math
import sys

BAND = {"light": (0.43, 0.77), "dark": (0.48, 0.67)}
CHROMA_FLOOR = 0.10
CVD_TARGET, CVD_FLOOR = 8.0, 6.0
NORMAL_FLOOR = 15.0
CONTRAST_MIN = 3.0
DEFAULT_SURFACE = {"light": "#fcfcfb", "dark": "#1a1a19"}

MACHADO = {
    "protan": [[0.152286, 1.052583, -0.204868],
               [0.114503, 0.786281, 0.099216],
               [-0.003882, -0.048116, 1.051998]],
    "deutan": [[0.367322, 0.860646, -0.227968],
               [0.280085, 0.672501, 0.047413],
               [-0.011820, 0.042940, 0.968881]],
    "tritan": [[1.255528, -0.076749, -0.178779],
               [-0.078411, 0.930809, 0.147602],
               [0.004733, 0.691367, 0.303900]],
}


def hex2srgb(h):
    h = h.strip().lstrip("#")
    return [int(h[i:i + 2], 16) / 255.0 for i in (0, 2, 4)]


def s2lin(c):
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def lin(h):
    return [s2lin(c) for c in hex2srgb(h)]


def rel_lum(h):
    r, g, b = lin(h)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a, b):
    hi, lo = sorted((rel_lum(a), rel_lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def oklab_from_lin(rgb):
    r, g, b = rgb
    l = (0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b) ** (1 / 3)
    m = (0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b) ** (1 / 3)
    s = (0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b) ** (1 / 3)
    return [0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s,
            1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s,
            0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s]


def oklch(h):
    L, a, b = oklab_from_lin(lin(h))
    return L, math.hypot(a, b)


def simulate(h, kind):
    r, g, b = lin(h)
    M = MACHADO[kind]
    return [min(1.0, max(0.0, M[i][0] * r + M[i][1] * g + M[i][2] * b)) for i in range(3)]


def delta_e(h1, h2, kind=None):
    a = oklab_from_lin(simulate(h1, kind) if kind else lin(h1))
    b = oklab_from_lin(simulate(h2, kind) if kind else lin(h2))
    return 100 * math.dist(a, b)


def validate(palette, mode="light", surface=None, pairs="all"):
    surface = surface or DEFAULT_SURFACE[mode]
    lo, hi = BAND[mode]
    failed = False
    print("mode %s, surface %s, pairs %s" % (mode, surface, pairs))
    print("%-9s %-7s %-7s %-8s %s" % ("hex", "L", "C", "contrast", "checks"))
    for h in palette:
        L, C = oklch(h)
        ratio = contrast(h, surface)
        notes = []
        if not (lo <= L <= hi):
            notes.append("L out of band")
        if C < CHROMA_FLOOR:
            notes.append("chroma below floor")
        if ratio < CONTRAST_MIN:
            notes.append("contrast WARN (needs label)")
        print("%-9s %-7.3f %-7.3f %-8.2f %s" % (h, L, C, ratio, ", ".join(notes) or "ok"))
    pairlist = (list(itertools.combinations(range(len(palette)), 2)) if pairs == "all"
                else [(i, i + 1) for i in range(len(palette) - 1)])
    print("\n%-9s %-9s %-7s %-7s %-7s %-7s %s"
          % ("a", "b", "normal", "protan", "deutan", "tritan", "verdict"))
    for i, j in pairlist:
        a, b = palette[i], palette[j]
        normal = delta_e(a, b)
        p, d, t = (delta_e(a, b, k) for k in ("protan", "deutan", "tritan"))
        worst = min(p, d)
        verdict = "ok"
        if normal < NORMAL_FLOOR:
            verdict, failed = "FAIL normal-vision floor", True
        elif worst < CVD_FLOOR:
            verdict, failed = "FAIL cvd", True
        elif worst < CVD_TARGET:
            verdict = "WARN cvd (secondary encoding required)"
        print("%-9s %-9s %-7.1f %-7.1f %-7.1f %-7.1f %s" % (a, b, normal, p, d, t, verdict))
    return failed


if __name__ == "__main__":
    colors = [c for c in sys.argv[1].split(",") if c.strip()]
    mode = sys.argv[2] if len(sys.argv) > 2 else "light"
    surf = sys.argv[3] if len(sys.argv) > 3 else None
    sys.exit(1 if validate(colors, mode, surf) else 0)
