#!/usr/bin/env python3
"""Draw a stylised, cropped view of the EyeOFmX desktop window for the site.

The image is illustrative rather than a real screenshot: it shows the header,
tabs and one table of a native GTK 3 window in the same dark palette as the
application. Output: site/back.png.
"""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent
SITE = ROOT.parent / "site"
W, H = 1200, 700

INK = (20, 20, 20)
PANEL = (15, 20, 24)
BAR = (27, 36, 42)
BAR_2 = (22, 32, 40)
LINE = (51, 65, 74)
TEXT = (232, 238, 242)
DIM = (147, 163, 173)
CYAN = (56, 189, 248)
AMBER = (251, 191, 36)
GREEN = (74, 222, 128)

MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"


def font(size, bold=False):
    return ImageFont.truetype(BOLD if bold else MONO, size)


def main():
    im = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)

    # Window with a hard offset shadow, matching the site's card style.
    x0, y0, x1, y1 = 46, 56, 1154, 652
    d.rectangle((x0 + 10, y0 + 10, x1 + 10, y1 + 10), fill=(20, 20, 20, 150))
    d.rectangle((x0, y0, x1, y1), fill=PANEL, outline=INK, width=3)

    # Title bar.
    d.rectangle((x0 + 2, y0 + 2, x1 - 2, y0 + 54), fill=BAR)
    d.line((x0 + 2, y0 + 54, x1 - 2, y0 + 54), fill=LINE, width=2)
    for cx, color in ((76, (168, 50, 50)), (104, (201, 162, 39)), (132, (46, 125, 66))):
        d.ellipse((cx - 7, 86 - 7, cx + 7, 86 + 7), fill=color, outline=INK)

    icon = Image.open(ROOT / "icons" / "64x64" / "apps" / "eyeofmx.png").convert("RGBA")
    im.alpha_composite(icon.resize((30, 30), Image.Resampling.LANCZOS), (162, 71))
    d = ImageDraw.Draw(im)
    d.text((204, 73), "EyeOFmX — Linux Monitoring & Security Inspector", font=font(19, True), fill=TEXT)

    # Menu bar.
    d.rectangle((x0 + 2, y0 + 56, x1 - 2, y0 + 92), fill=BAR_2)
    d.text((70, 66), "File     Tools     View     Help", font=font(15), fill=DIM)

    # Notebook tabs, with the active one underlined in cyan.
    tab_y = 150
    d.rectangle((x0 + 2, tab_y, x1 - 2, tab_y + 42), fill=(17, 24, 30))
    tabs = [("Connections", 70, 224), ("Files", 238, 322), ("Live", 336, 410),
            ("History", 424, 540), ("Logs", 554, 632), ("Scan", 646, 722)]
    for label, a, b in tabs:
        active = label == "Connections"
        d.rectangle((a, tab_y + 2, b, tab_y + 40), fill=PANEL if active else (20, 29, 36))
        d.text((a + 12, tab_y + 12), label, font=font(15, active), fill=TEXT if active else DIM)
    d.line((70, tab_y + 41, 224, tab_y + 41), fill=CYAN, width=3)

    # Table header and rows.
    d.rectangle((x0 + 2, 196, x1 - 2, 232), fill=BAR)
    cols = [(70, "PROTOCOL"), (220, "LOCAL ADDRESS"), (470, "REMOTE ADDRESS"),
            (730, "PROCESS"), (980, "STATE")]
    for cx, label in cols:
        d.text((cx, 204), label, font=font(15, True), fill=DIM)

    rows = [
        ("TCP", "127.0.0.1:5432", "0.0.0.0:*", "postgres", "LISTEN", GREEN),
        ("TCP", "192.168.1.42:52234", "93.184.216.34:443", "firefox", "ESTAB", CYAN),
        ("TCP", "0.0.0.0:22", "0.0.0.0:*", "sshd", "LISTEN", GREEN),
        ("UDP", "127.0.0.1:53", "0.0.0.0:*", "systemd-resolve", "LISTEN", GREEN),
        ("TCP", "10.0.0.4:8080", "10.0.0.12:4412", "nginx", "ESTAB", CYAN),
        ("TCP", "127.0.0.1:631", "0.0.0.0:*", "cupsd", "LISTEN", GREEN),
        ("TCP", "192.168.1.42:443", "172.17.0.3:51204", "docker-proxy", "ESTAB", CYAN),
    ]
    for i, (proto, local, remote, proc, state, color) in enumerate(rows):
        y = 238 + i * 50
        d.rectangle((x0 + 2, y, x1 - 2, y + 46), fill=(17, 24, 30) if i % 2 == 0 else PANEL)
        d.text((70, y + 13), proto, font=font(15, True), fill=CYAN)
        d.text((220, y + 13), local, font=font(15), fill=TEXT)
        d.text((470, y + 13), remote, font=font(15), fill=TEXT)
        d.text((730, y + 13), proc, font=font(15), fill=AMBER)
        d.text((980, y + 13), state, font=font(15, True), fill=color)

    # Status bar.
    d.rectangle((x0 + 2, 606, x1 - 2, 650), fill=BAR_2)
    d.line((x0 + 2, 606, x1 - 2, 606), fill=LINE, width=2)
    d.ellipse((68, 624, 80, 636), fill=GREEN)
    d.text((92, 621), "root  ·  6 tabs  ·  collectors ready  ·  12 findings", font=font(14), fill=DIM)
    d.text((1010, 621), "v1.0.1", font=font(14), fill=DIM)

    # Fade the outer edges so the window reads as a fragment, not a screenshot.
    px = im.load()
    for y in range(H):
        fy = min(1.0, (H - y) / 70.0, y / 30.0)
        for x in range(W):
            fx = min(1.0, x / 70.0, (W - x) / 45.0)
            r, g, b, a = px[x, y]
            px[x, y] = (r, g, b, int(a * min(fx, fy)))

    SITE.mkdir(parents=True, exist_ok=True)
    target = SITE / "back.png"
    im.save(target, optimize=True)
    print(f"wrote {target.relative_to(ROOT.parent)}")


if __name__ == "__main__":
    main()
