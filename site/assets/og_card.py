"""Render the hiss OG card (1200x630): the brand lockup on ink.

Static ticks enter from the left, the wordmark holds the silence, a clean
cyan signal leaves right; tagline below; the honest caveat bottom-left.

Regenerate `og.png` (needs Pillow, and macOS's Menlo for the mono face):

    python3 site/assets/og_card.py
"""

import math
import os

from PIL import Image, ImageDraw, ImageFont

W, H = 1200, 630
INK = (11, 11, 12)
SILVER_BRIGHT = (232, 234, 236)
SILVER_DIM = (135, 141, 149)
SILVER_FAINT = (90, 96, 104)
CYAN = (91, 200, 214)
WARN = (255, 122, 24)

img = Image.new("RGB", (W, H), INK)
d = ImageDraw.Draw(img)

# faint cyan glow, top right (radial-ish, cheap)
glow = Image.new("L", (W, H), 0)
gd = ImageDraw.Draw(glow)
for r in range(420, 0, -6):
    a = int(10 * (1 - r / 420))
    gd.ellipse([980 - r, -140 - r * 0.6, 980 + r, -140 + r * 0.6], fill=a)
img = Image.composite(Image.new("RGB", (W, H), (18, 42, 46)), img, glow)
d = ImageDraw.Draw(img)


def font(size, bold=False):
    path = "/System/Library/Fonts/Menlo.ttc"
    for idx in [1, 0] if bold else [0]:
        try:
            f = ImageFont.truetype(path, size, index=idx)
            if not bold or "bold" in (f.getname()[1] or "").lower() or idx == 1:
                return f
        except OSError:
            continue
    return ImageFont.truetype(path, size)


# ---- lockup row, vertically centred around y = 265 ----
mid = 265

# static ticks: varied heights, entering from the left
heights = [26, 44, 18, 38, 52, 24, 34, 14, 42, 30, 48, 20, 36, 26, 44, 18]
x = 100
for h in heights:
    d.rectangle([x, mid - h / 2, x + 3, mid + h / 2], fill=SILVER_FAINT)
    x += 13

# wordmark
d.text((360, mid), "hiss", font=font(150, bold=True), fill=SILVER_BRIGHT, anchor="lm")

# clean signal leaving right
prev = None
for px in range(780, 1101, 2):
    py = mid + 34 * math.sin((px - 780) / 320 * math.pi * 4)
    if prev:
        d.line([prev, (px, py)], fill=CYAN, width=5)
    prev = (px, py)

# ---- tagline ----
d.text(
    (W / 2, 430),
    "encrypted, authenticated channels between two peers you control",
    font=font(30),
    fill=SILVER_DIM,
    anchor="mm",
)
d.text(
    (W / 2, 478),
    "the handshake checked by the compiler",
    font=font(26),
    fill=SILVER_FAINT,
    anchor="mm",
)

# ---- footer row ----
ff = font(22)
d.text((100, 566), "unaudited · pre-1.0", font=ff, fill=WARN, anchor="lm")
d.text((1100, 566), "primetype.co.uk/hiss", font=ff, fill=SILVER_FAINT, anchor="rm")

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "og.png")
img.save(out, optimize=True)
print(out, os.path.getsize(out), "bytes")
