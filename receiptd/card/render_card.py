"""Pillow-based visual card renderer: card.png + card.svg (1200x630).

Pure Pillow - no browser, no Playwright, no HTML. The SVG is generated as a
companion vector file with the same layout primitives (rect / text), for
users who want scalable output.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from receiptd.card.models import CATEGORIES, Report

WIDTH, HEIGHT = 1200, 630

# Dark theme palette.
BG = (13, 17, 23)
PANEL = (22, 27, 34)
FG = (230, 237, 243)
DIM = (139, 148, 158)
RED = (248, 81, 73)
GREEN = (63, 185, 80)
YELLOW = (210, 153, 34)
ACCENT = (88, 166, 255)

LEVEL_COLOR = {"RED": RED, "YELLOW": YELLOW, "GREEN": GREEN}
LEVEL_TITLE = {"RED": "LETHAL TRIFECTA", "YELLOW": "2 OF 3", "GREEN": "CLEAN"}

FONTS = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf",
]
REGULAR_FONTS = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
]


def _load_font(candidates, size):
    for path in candidates:
        if Path(path).exists():
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
    return ImageFont.load_default()


def font_bold(size):
    return _load_font(FONTS, size)


def font_regular(size):
    return _load_font(REGULAR_FONTS, size)


def _short_hash(report) -> str:
    """Short evidence hash: first 12 hex chars of SHA-256 over the evidence
    rows' canonical fields."""
    import hashlib

    material = "|".join(
        f"{h.category},{h.index},{h.tool},{h.target},{h.rule}" for h in report.hits
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


def _session_date(report) -> str:
    dates = [s.started[:10] for s in report.sessions if s.started]
    return dates[0] if dates else "unknown date"


def _evidence_lines(report, limit=3):
    lines = []
    for hit in report.top_evidence(limit):
        label = f"{hit.category}  {hit.tool}  {hit.target}  #{hit.index}"
        lines.append(label)
    return lines


def _hex(rgb):
    return "#{:02x}{:02x}{:02x}".format(*rgb)


# ---------------------------------------------------------------------------
# PNG (Pillow)
# ---------------------------------------------------------------------------


def render_card_png(report: Report, path) -> None:
    image = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(image)
    level_color = LEVEL_COLOR[report.level]

    # Header band.
    draw.rectangle([0, 0, WIDTH, 8], fill=level_color)

    # Enormous title.
    title_font = font_bold(72)
    title = LEVEL_TITLE[report.level]
    draw.text((60, 48), title, font=title_font, fill=level_color)

    subtitle = "Trifecta Card - receiptd"
    draw.text((62, 132), subtitle, font=font_regular(22), fill=DIM)

    # Three status rows.
    row_y = 190
    labels = {
        "PRIVATE": "PRIVATE DATA",
        "UNTRUSTED": "UNTRUSTED INPUT",
        "EGRESS": "EGRESS",
    }
    mark_font = font_bold(34)
    label_font = font_regular(30)
    count_font = font_bold(30)
    for category in CATEGORIES:
        count = report.counts[category]
        color = level_color if count else DIM
        mark = "PASS" if count else "ok"
        symbol = "✗" if count else "✓"
        if count:
            symbol = "✗"
            mark_color = RED
        else:
            symbol = "✓"
            mark_color = GREEN
        row = f"{symbol}  {labels[category]}"
        draw.text((60, row_y), symbol, font=mark_font, fill=mark_color)
        draw.text((110, row_y + 4), labels[category], font=label_font, fill=FG if count else DIM)
        count_text = str(count)
        count_w = draw.textlength(count_text, font=count_font)
        draw.text((WIDTH - 80 - count_w, row_y + 4), count_text, font=count_font, fill=color)
        row_y += 56

    # Ordered warning.
    if report.ordered:
        draw.text((60, row_y + 2), "⚠ ORDERED KILL CHAIN", font=font_bold(26), fill=YELLOW)
    row_y += 52

    # Top evidence lines in a panel.
    panel_top = row_y
    panel_bottom = HEIGHT - 96
    draw.rounded_rectangle(
        [48, panel_top, WIDTH - 48, panel_bottom], radius=12, fill=PANEL
    )
    evidence_font = font_regular(22)
    ey = panel_top + 14
    lines = _evidence_lines(report, limit=3)
    if not lines:
        lines = ["no rule hits recorded"]
    for line in lines:
        for wrapped in textwrap.wrap(line, width=72)[:2]:
            draw.text((68, ey), wrapped, font=evidence_font, fill=FG)
            ey += 28
        ey += 4

    # Footer: date + evidence hash + repo link + dynamic verify command.
    footer = f"{_session_date(report)}  ·  evidence {_short_hash(report)}  ·  github.com/NickAltstein/receiptd"
    draw.text((60, HEIGHT - 62), footer, font=font_regular(20), fill=DIM)
    json_name = Path(path).with_suffix(".json").name
    verify_text = f"verify: receiptd verify-card {json_name}"
    verify_w = draw.textlength(verify_text, font=font_regular(20))
    draw.text((WIDTH - 60 - verify_w, HEIGHT - 62), verify_text, font=font_regular(20), fill=ACCENT)

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    image.save(str(path), format="PNG")


# ---------------------------------------------------------------------------
# SVG companion (same layout, hand-generated)
# ---------------------------------------------------------------------------


def _svg_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def render_card_svg(report: Report, path) -> None:
    level_color = _hex(LEVEL_COLOR[report.level])
    title = LEVEL_TITLE[report.level]
    parts = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" '
        f'viewBox="0 0 {WIDTH} {HEIGHT}">'
    )
    parts.append(f'<rect width="{WIDTH}" height="{HEIGHT}" fill="{_hex(BG)}"/>')
    parts.append(f'<rect x="0" y="0" width="{WIDTH}" height="8" fill="{level_color}"/>')
    parts.append(
        f'<text x="60" y="110" font-family="DejaVu Sans, Liberation Sans, sans-serif" '
        f'font-size="72" font-weight="bold" fill="{level_color}">{_svg_escape(title)}</text>'
    )
    parts.append(
        f'<text x="62" y="152" font-family="DejaVu Sans, Liberation Sans, sans-serif" '
        f'font-size="22" fill="{_hex(DIM)}">Trifecta Card - receiptd</text>'
    )
    labels = {"PRIVATE": "PRIVATE DATA", "UNTRUSTED": "UNTRUSTED INPUT", "EGRESS": "EGRESS"}
    row_y = 228
    for category in CATEGORIES:
        count = report.counts[category]
        symbol = "✗" if count else "✓"
        mark_color = _hex(RED if count else GREEN)
        text_color = level_color if count else _hex(DIM)
        parts.append(
            f'<text x="60" y="{row_y}" font-family="DejaVu Sans, sans-serif" '
            f'font-size="34" font-weight="bold" fill="{mark_color}">{symbol}</text>'
        )
        parts.append(
            f'<text x="110" y="{row_y}" font-family="DejaVu Sans, sans-serif" '
            f'font-size="30" fill="{text_color}">{labels[category]}</text>'
        )
        parts.append(
            f'<text x="{WIDTH - 80}" y="{row_y}" text-anchor="end" '
            f'font-family="DejaVu Sans, sans-serif" font-size="30" '
            f'font-weight="bold" fill="{text_color}">{count}</text>'
        )
        row_y += 56
    if report.ordered:
        parts.append(
            f'<text x="60" y="{row_y - 4}" font-family="DejaVu Sans, sans-serif" '
            f'font-size="26" font-weight="bold" fill="{_hex(YELLOW)}">⚠ ORDERED KILL CHAIN</text>'
        )
    panel_top = row_y + 44
    parts.append(
        f'<rect x="48" y="{panel_top}" width="{WIDTH - 96}" height="{HEIGHT - 96 - panel_top}" '
        f'rx="12" fill="{_hex(PANEL)}"/>'
    )
    ey = panel_top + 36
    lines = _evidence_lines(report, limit=3) or ["no rule hits recorded"]
    for line in lines:
        parts.append(
            f'<text x="68" y="{ey}" font-family="DejaVu Sans, sans-serif" '
            f'font-size="22" fill="{_hex(FG)}">{_svg_escape(line)}</text>'
        )
        ey += 32
    json_name = Path(path).with_suffix(".json").name
    parts.append(
        f'<text x="60" y="{HEIGHT - 42}" font-family="DejaVu Sans, sans-serif" '
        f'font-size="20" fill="{_hex(DIM)}">{_session_date(report)}  ·  '
        f"evidence {_short_hash(report)}  ·  github.com/NickAltstein/receiptd</text>"
    )
    parts.append(
        f'<text x="{WIDTH - 60}" y="{HEIGHT - 42}" text-anchor="end" '
        f'font-family="DejaVu Sans, sans-serif" font-size="20" fill="{_hex(ACCENT)}">'
        f"verify: receiptd verify-card {json_name}</text>"
    )
    parts.append("</svg>")

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(parts) + "\n", encoding="utf-8")


def render_card_files(report: Report, out_png) -> dict:
    """Write card.png + card.svg + signed card.json next to each other.
    Returns the paths written."""
    out_png = Path(out_png)
    if out_png.suffix.lower() != ".png":
        out_png = out_png.with_suffix(".png")
    out_svg = out_png.with_suffix(".svg")
    out_json = out_png.with_suffix(".json")
    render_card_png(report, out_png)
    render_card_svg(report, out_svg)
    from receiptd.card.signing import write_signed_card
    write_signed_card(report, out_json)
    return {"png": str(out_png), "svg": str(out_svg), "json": str(out_json)}
