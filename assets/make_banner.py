#!/usr/bin/env python3
"""Render the terminal banner to assets/hyeongi-banner.png for the README.

Text-based ASCII art breaks on GitHub: characters such as ╲ ╱ ╳ ● have
different widths in different fonts, and font glyphs leave seams between rows.
So the art is drawn as geometry instead: every character occupies one grid
cell; █ is a filled cell and ═ ║ ╔ ╗ ╚ ╝ are double strokes that reach the cell
edges. The name is drawn in white; the words it stands for sit under it in the
logo's red (Pillow's built-in font, so the result does not depend on installed fonts).

  python3 assets/make_banner.py        (needs Pillow)
"""
import os
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))

S = 2                      # supersampling for a crisp result
CW, CH = 13 * S, 26 * S    # cell size (terminal cells are ~1:2)
PAD = 30 * S
BG = (13, 17, 23)          # GitHub dark
RED = (226, 59, 46)        # the logo's red (#e23b2e)
WHITE = (255, 255, 255)
TAGLINE = "Host-based, Your-network-gated Enforcement with On-device Network Guard & Inspection"
GAP = 14 * S               # space between the name and the tagline

WORD = [
    "██╗  ██╗██╗   ██╗███████╗ ██████╗ ███╗   ██╗ ██████╗ ██╗",
    "██║  ██║╚██╗ ██╔╝██╔════╝██╔═══██╗████╗  ██║██╔════╝ ██║",
    "███████║ ╚████╔╝ █████╗  ██║   ██║██╔██╗ ██║██║  ███╗██║",
    "██╔══██║  ╚██╔╝  ██╔══╝  ██║   ██║██║╚██╗██║██║   ██║██║",
    "██║  ██║   ██║   ███████╗╚██████╔╝██║ ╚████║╚██████╔╝██║",
    "╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚═╝",
]

# double-line glyphs: (horizontal direction, vertical direction)
DOUBLE = {"═": (2, 0), "║": (0, 2), "╔": (1, 1), "╗": (-1, 1), "╚": (1, -1), "╝": (-1, -1)}


def draw_cell(d, x, y, ch, color):
    if ch == " ":
        return
    if ch == "█":
        d.rectangle([x, y, x + CW, y + CH], fill=color)   # +1px overlap: no seams
        return
    g = CW * 0.2              # half gap between the two strokes
    lw = max(2, round(CW * 0.11))
    cx, cy = x + CW / 2, y + CH / 2
    h, v = DOUBLE[ch]
    if (h, v) == (2, 0):
        for o in (-g, g):
            d.line([(x, cy + o), (x + CW, cy + o)], fill=color, width=lw)
    elif (h, v) == (0, 2):
        for o in (-g, g):
            d.line([(cx + o, y), (cx + o, y + CH)], fill=color, width=lw)
    else:                     # corner: outer and inner L
        ex = cx + h * CW / 2  # horizontal edge it reaches
        ey = cy + v * CH / 2  # vertical edge it reaches
        for s in (-1, 1):     # -1 outer, +1 inner
            px, py = cx + s * h * g, cy + s * v * g
            d.line([(px, ey), (px, py), (ex, py)], fill=color, width=lw, joint="curve")


def fit_font(d, text, width):
    """The largest built-in font size at which `text` is no wider than `width`."""
    size = 40 * S
    while size > 8 * S and d.textlength(text, font=ImageFont.load_default(size=size)) > width:
        size -= 1
    return ImageFont.load_default(size=size)


def main():
    cols = len(WORD[0])
    width = PAD * 2 + cols * CW
    probe = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    font = fit_font(probe, TAGLINE, cols * CW)
    top, bottom = probe.textbbox((0, 0), TAGLINE, font=font)[1::2]
    art = len(WORD) * CH
    height = PAD * 2 + art + GAP + (bottom - top)      # name, then the tagline
    img = Image.new("RGB", (width, height), BG)
    d = ImageDraw.Draw(img)
    for r, line in enumerate(WORD):
        for c, ch in enumerate(line):
            draw_cell(d, PAD + c * CW, PAD + r * CH, ch, WHITE)
    d.text((PAD, PAD + art + GAP - top), TAGLINE, font=font, fill=RED)

    img = img.resize((width // S, height // S), Image.LANCZOS)
    out = os.path.join(HERE, "hyeongi-banner.png")
    img.save(out, optimize=True)
    print(f"wrote {out} ({img.width}x{img.height})")


if __name__ == "__main__":
    main()
