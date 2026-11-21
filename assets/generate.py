#!/usr/bin/env python3
"""Generate the EyeOFmX icon at every hicolor size.

The shapes are drawn directly with Pillow and anti-aliased by supersampling,
so no external SVG renderer is needed. The matching vector source is
assets/eyeofmx.svg.
"""
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent
SIZES = (16, 32, 48, 64, 128, 256)
SS = 8

BG = (11, 27, 43, 255)
PANEL = (18, 48, 68, 255)
CYAN = (56, 189, 248, 255)
LIGHT = (186, 230, 253, 255)
AMBER = (251, 191, 36, 255)
DARK = (7, 18, 30, 255)
WHITE = (255, 255, 255, 255)


def render(size):
    w = size * SS
    im = Image.new("RGBA", (w, w), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)

    # Rounded shield-like badge with a cyan border.
    d.rounded_rectangle(
        (0, 0, w - 1, w - 1),
        radius=round(w * 0.22),
        fill=BG,
        outline=CYAN,
        width=max(1, round(w * 0.018)),
    )
    pad = round(w * 0.075)
    d.rounded_rectangle(
        (pad, pad, w - 1 - pad, w - 1 - pad),
        radius=round(w * 0.16),
        fill=PANEL,
    )

    # The eye: light outline, dark opening, amber iris, dark pupil, glint.
    d.ellipse(
        (round(w * 0.12), round(w * 0.33), round(w * 0.88), round(w * 0.67)),
        fill=LIGHT,
    )
    d.ellipse(
        (round(w * 0.19), round(w * 0.385), round(w * 0.81), round(w * 0.615)),
        fill=PANEL,
    )

    c = w / 2
    iris = w * 0.105
    pupil = w * 0.055
    glint = w * 0.022
    d.ellipse(
        (round(c - iris), round(c - iris), round(c + iris), round(c + iris)),
        fill=AMBER,
    )
    d.ellipse(
        (round(c - pupil), round(c - pupil), round(c + pupil), round(c + pupil)),
        fill=DARK,
    )
    gx, gy = c - iris * 0.35, c - iris * 0.38
    d.ellipse(
        (round(gx - glint), round(gy - glint), round(gx + glint), round(gy + glint)),
        fill=WHITE,
    )

    return im.resize((size, size), Image.Resampling.LANCZOS)


def main():
    for size in SIZES:
        target = ROOT / "icons" / f"{size}x{size}" / "apps" / "eyeofmx.png"
        target.parent.mkdir(parents=True, exist_ok=True)
        render(size).save(target, optimize=True)
        print(f"wrote {target.relative_to(ROOT.parent)}")


if __name__ == "__main__":
    main()
