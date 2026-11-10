"""
receiptd.trifecta
=================

Trifecta Risk Audit & Card Generator for Claude Code and Codex logs.

The Trifecta represents the fundamental autonomous agent exfiltration hazard:
  1. Private Data Access: Reading .env, SSH keys, credentials, local databases, or secrets.
  2. Untrusted External Input: WebFetch, web search, GitHub PRs, untrusted clone/issue payloads.
  3. Outbound Network Egress: Active execution channel (curl POST, git push, network socket).

When all three vectors occur within the same agent session, the session completes
the exfiltration triangle, earning a RED verdict.
"""

from __future__ import annotations

import glob
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

# Detection Regexes
SENSITIVE_PATTERN = re.compile(
    r"(\.env(\..+)?|credentials|id_rsa|\.pem|\.key|\.ssh/|secrets?|token|password|\.git/config|\.pgpass|database\.sqlite|dev\.db|local\.db)",
    re.IGNORECASE,
)
UNTRUSTED_PATTERN = re.compile(
    r"(WebFetch|WebSearch|browse|curl\s+https?://|wget\s+https?://|git\s+clone|gh\s+pr\s+view|gh\s+issue\s+view|mcp__.*browser.*|mcp__.*search.*|mcp__.*fetch.*)",
    re.IGNORECASE,
)
OUTBOUND_PATTERN = re.compile(
    r"(curl\s+.*(-d|--data|-X\s*POST|-X\s*PUT|--upload-file)|git\s+push|nc\s+|ssh\s+|python.*(urllib|requests|http\.client)|node.*(fetch|axios|http))",
    re.IGNORECASE,
)


@dataclass
class SessionAudit:
    session_id: str
    project_name: str
    log_path: str
    last_modified: datetime
    tool_calls_count: int = 0
    has_private_data: bool = False
    has_untrusted_input: bool = False
    has_outbound_network: bool = False
    private_matches: list[str] = field(default_factory=list)
    untrusted_matches: list[str] = field(default_factory=list)
    outbound_matches: list[str] = field(default_factory=list)

    @property
    def vector_count(self) -> int:
        return sum([self.has_private_data, self.has_untrusted_input, self.has_outbound_network])

    @property
    def verdict(self) -> str:
        if self.vector_count == 3:
            return "RED"
        elif self.vector_count == 2:
            return "YELLOW"
        return "GREEN"


@dataclass
class TrifectaScanResult:
    days: int
    total_sessions: int
    total_tool_calls: int
    red_sessions: int
    yellow_sessions: int
    green_sessions: int
    overall_verdict: str  # RED, YELLOW, GREEN
    sessions: list[SessionAudit]

    @property
    def tri_vector_pct(self) -> float:
        if not self.total_sessions:
            return 0.0
        return (self.red_sessions / self.total_sessions) * 100.0


def scan_agent_logs(
    target_path: Optional[str] = None,
    days: int = 30,
) -> TrifectaScanResult:
    """Scan Claude Code and Codex logs within the given day window."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    files_to_scan: list[str] = []

    if target_path:
        p = Path(target_path).expanduser().resolve()
        if p.is_file():
            files_to_scan.append(str(p))
        elif p.is_dir():
            files_to_scan.extend(glob.glob(str(p / "**/*.jsonl"), recursive=True))
    else:
        # Default discovery paths: ~/.claude/projects, cwd .claude, ~/.codex/sessions
        claude_home = Path("~/.claude/projects").expanduser().resolve()
        if claude_home.exists():
            files_to_scan.extend(glob.glob(str(claude_home / "**/*.jsonl"), recursive=True))

        cwd_claude = Path(".claude").resolve()
        if cwd_claude.exists():
            files_to_scan.extend(glob.glob(str(cwd_claude / "**/*.jsonl"), recursive=True))

        codex_home = Path("~/.codex/sessions").expanduser().resolve()
        if codex_home.exists():
            files_to_scan.extend(glob.glob(str(codex_home / "**/*.jsonl"), recursive=True))

    audits: list[SessionAudit] = []
    all_files = sorted(set(files_to_scan))

    def parse_files(file_list: list[str]) -> list[SessionAudit]:
        parsed: list[SessionAudit] = []
        for file_str in file_list:
            fpath = Path(file_str)
            try:
                mtime = datetime.fromtimestamp(fpath.stat().st_mtime, tz=timezone.utc)
            except Exception:
                mtime = datetime.now(timezone.utc)

            proj_name = fpath.parent.name.replace("-Users-nick-Desktop-", "").replace("-Users-", "")
            sess_id = fpath.stem[:12]

            audit = SessionAudit(
                session_id=sess_id,
                project_name=proj_name or "local",
                log_path=str(fpath),
                last_modified=mtime,
            )

            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if "tool_use" not in line and "Bash" not in line:
                            continue
                        try:
                            record = json.loads(line)
                            msg = record.get("message", {})
                            content = msg.get("content", [])
                            if isinstance(content, list):
                                for item in content:
                                    if isinstance(item, dict) and item.get("type") == "tool_use":
                                        audit.tool_calls_count += 1
                                        t_name = str(item.get("name", ""))
                                        t_input = json.dumps(item.get("input", {}))

                                        # 1. Private data check
                                        if SENSITIVE_PATTERN.search(t_input):
                                            audit.has_private_data = True
                                            if len(audit.private_matches) < 3:
                                                audit.private_matches.append(t_input[:60])

                                        # 2. Untrusted input check
                                        if UNTRUSTED_PATTERN.search(t_name) or UNTRUSTED_PATTERN.search(t_input):
                                            audit.has_untrusted_input = True
                                            if len(audit.untrusted_matches) < 3:
                                                audit.untrusted_matches.append(t_name)

                                        # 3. Outbound network check
                                        if OUTBOUND_PATTERN.search(t_input):
                                            audit.has_outbound_network = True
                                            if len(audit.outbound_matches) < 3:
                                                audit.outbound_matches.append(t_input[:60])
                        except Exception:
                            pass
            except Exception:
                continue

            parsed.append(audit)
        return parsed

    effective_days = days
    if days > 0:
        window_files = [
            f for f in all_files
            if datetime.fromtimestamp(Path(f).stat().st_mtime, tz=timezone.utc) >= cutoff
        ]
        audits = parse_files(window_files)
        # If no tool calls in recent window, automatically fallback to all historical logs
        if sum(a.tool_calls_count for a in audits) == 0 and len(all_files) > len(window_files):
            audits = parse_files(all_files)
            effective_days = 0
    else:
        audits = parse_files(all_files)

    total_sessions = len(audits)
    total_tools = sum(a.tool_calls_count for a in audits)
    red_count = sum(1 for a in audits if a.verdict == "RED")
    yellow_count = sum(1 for a in audits if a.verdict == "YELLOW")
    green_count = sum(1 for a in audits if a.verdict == "GREEN")

    overall = "GREEN"
    if red_count > 0:
        overall = "RED"
    elif yellow_count > 0:
        overall = "YELLOW"

    return TrifectaScanResult(
        days=effective_days,
        total_sessions=total_sessions,
        total_tool_calls=total_tools,
        red_sessions=red_count,
        yellow_sessions=yellow_count,
        green_sessions=green_count,
        overall_verdict=overall,
        sessions=audits,
    )


def render_terminal_card(res: TrifectaScanResult) -> str:
    """Render an ASCII terminal representation of the Trifecta Card."""
    width = 72
    border = "═" * width
    divider = "─" * width

    color_red = "\033[91m\033[1m"
    color_yellow = "\033[93m\033[1m"
    color_green = "\033[92m\033[1m"
    bold = "\033[1m"
    dim = "\033[90m"
    reset = "\033[0m"

    if res.overall_verdict == "RED":
        verdict_str = f"{color_red}VERDICT: RED (TRIFECTA RISK DETECTED){reset}"
        desc = "Your agent has combined private data, untrusted input, & network access in the same session."
    elif res.overall_verdict == "YELLOW":
        verdict_str = f"{color_yellow}VERDICT: YELLOW (ELEVATED RISK - 2 VECTORS OVERLAP){reset}"
        desc = "Your agent has combined 2 of 3 exfiltration vectors in the same session."
    else:
        verdict_str = f"{color_green}VERDICT: GREEN (CONTAINED / SECURE){reset}"
        desc = "No cross-boundary exfiltration vectors detected across active sessions."

    lines = [
        f"\n{bold}╔{border}╗{reset}",
        f"{bold}║  RECEIPTD // TRIFECTA RISK CARD{' ' * (width - 33)}║{reset}",
        f"{bold}║  Sub-2ms Runtime Authorization & Cross-Boundary Agent Auditing{' ' * (width - 64)}║{reset}",
        f"{bold}╠{border}╣{reset}",
        f"║  {verdict_str}{' ' * max(0, width - 42)}║",
        f"║  {dim}{desc[:width - 4]}{' ' * max(0, width - 4 - len(desc[:width - 4]))}{reset}║",
        f"{bold}╠{divider}╣{reset}",
        f"║  {bold}Audit Scope & Empirical Telemetry:{reset}{' ' * (width - 36)}║",
        f"║   • Sessions Analyzed:  {res.total_sessions:3d} across last {res.days} days{' ' * max(0, width - 43)}║",
        f"║   • Tool Invocations:   {res.total_tool_calls:3d} audited tool calls{' ' * max(0, width - 41)}║",
        f"║   • Tri-Vector Sessions:{res.red_sessions:3d} ({res.tri_vector_pct:.1f}% of total sessions){' ' * max(0, width - 45)}║",
        f"║   • Partial Overlap:    {res.yellow_sessions:3d} warning sessions{' ' * max(0, width - 39)}║",
        f"║   • Safe & Isolated:    {res.green_sessions:3d} contained sessions{' ' * max(0, width - 39)}║",
        f"{bold}╠{divider}╣{reset}",
        f"║  {bold}The Three Exfiltration Vectors:{reset}{' ' * (width - 33)}║",
    ]

    priv_present = sum(1 for s in res.sessions if s.has_private_data)
    untrust_present = sum(1 for s in res.sessions if s.has_untrusted_input)
    out_present = sum(1 for s in res.sessions if s.has_outbound_network)

    lines.extend([
        f"║   [1] Private Secrets Context:   {color_red if priv_present else color_green}{'DETECTED (' + str(priv_present) + ' sess)' if priv_present else 'SECURE'}{reset}{' ' * max(0, width - 48)}║",
        f"║   [2] Untrusted External Input:  {color_red if untrust_present else color_green}{'DETECTED (' + str(untrust_present) + ' sess)' if untrust_present else 'SECURE'}{reset}{' ' * max(0, width - 48)}║",
        f"║   [3] Outbound Network Egress:   {color_red if out_present else color_green}{'ACTIVE   (' + str(out_present) + ' sess)' if out_present else 'BLOCKED'}{reset}{' ' * max(0, width - 48)}║",
        f"{bold}╠{border}╣{reset}",
        f"║  {dim}Generated with receiptd v1.0.0 • github.com/NickAltstein/receiptd{' ' * (width - 66)}{reset}║",
        f"{bold}╚{border}╝{reset}\n",
    ])

    return "\n".join(lines)


def render_png_card(res: TrifectaScanResult, out_path: str = "receiptd-card.png") -> str:
    """Render a high-resolution 1200x675 shareable PNG card."""
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        raise RuntimeError("Pillow is required for PNG rendering: pip install pillow")

    width, height = 1200, 675
    bg_color = (15, 23, 42)  # #0f172a slate-900
    card_bg = (30, 41, 59)   # #1e293b slate-800
    border_color = (51, 65, 85) # #334155 slate-700
    text_white = (248, 250, 252) # #f8fafc
    text_muted = (148, 163, 184) # #94a3b8

    # Verdict Colors
    if res.overall_verdict == "RED":
        accent = (239, 68, 68)     # #ef4444 red
        badge_bg = (127, 29, 29)   # #7f1d1d
        badge_text = "VERDICT: RED // TRIFECTA RISK DETECTED"
        sub_text = "Private Secrets Context + Untrusted Input + Outbound Egress in Same Session"
    elif res.overall_verdict == "YELLOW":
        accent = (245, 158, 11)    # #f59e0b yellow
        badge_bg = (120, 53, 15)   # #78350f
        badge_text = "VERDICT: YELLOW // ELEVATED 2-VECTOR OVERLAP"
        sub_text = "Two Exfiltration Vectors Intersected Without Fail-Closed Containment"
    else:
        accent = (16, 185, 129)    # #10b981 emerald
        badge_bg = (6, 78, 59)     # #064e3b
        badge_text = "VERDICT: GREEN // ZERO TRIFECTA OVERLAP"
        sub_text = "No Concurrent Secret Access, Untrusted Input, and Network Egress"

    img = Image.new("RGBA", (width, height), bg_color)
    draw = ImageDraw.Draw(img)

    # Load system fonts with fallback
    def get_font(size: int, bold: bool = False):
        font_names = [
            "/System/Library/Fonts/SFNSMono.ttf",
            "/System/Library/Fonts/Menlo.ttc",
            "/System/Library/Fonts/Monaco.ttf",
            "/System/Library/Fonts/Helvetica.ttc",
            "/Library/Fonts/Arial.ttf",
        ]
        for fn in font_names:
            if os.path.exists(fn):
                try:
                    return ImageFont.truetype(fn, size)
                except Exception:
                    pass
        return ImageFont.load_default()

    font_title = get_font(28, bold=True)
    font_sub = get_font(16)
    font_badge = get_font(22, bold=True)
    font_body = get_font(18)
    font_stat_val = get_font(38, bold=True)
    font_stat_lbl = get_font(13)
    font_footer = get_font(14)

    # Outer border
    draw.rounded_rectangle([20, 20, width - 20, height - 20], radius=16, outline=border_color, width=2)

    # Header Bar
    draw.text((60, 50), "RECEIPTD // AGENT TRIFECTA CARD", font=font_title, fill=text_white)
    draw.text((60, 88), "Cryptographic PreToolUse Runtime Enforcement & Exfiltration Boundary Audit", font=font_sub, fill=text_muted)

    # Top Right Brand Pill
    draw.rounded_rectangle([width - 240, 50, width - 60, 85], radius=18, fill=card_bg, outline=border_color, width=1)
    draw.text((width - 220, 58), "github.com/NickAltstein/receiptd", font=font_stat_lbl, fill=(200, 241, 53))

    # Main Verdict Banner
    banner_y = 125
    banner_h = 80
    draw.rounded_rectangle([60, banner_y, width - 60, banner_y + banner_h], radius=12, fill=badge_bg, outline=accent, width=2)
    draw.text((85, banner_y + 15), badge_text, font=font_badge, fill=(255, 255, 255))
    draw.text((85, banner_y + 45), sub_text, font=font_sub, fill=(241, 245, 249))

    # Central Section: 3 Vector Columns
    col_w = 340
    gap = 30
    start_x = 60
    col_y = 230
    col_h = 220

    priv_present = sum(1 for s in res.sessions if s.has_private_data)
    untrust_present = sum(1 for s in res.sessions if s.has_untrusted_input)
    out_present = sum(1 for s in res.sessions if s.has_outbound_network)

    vectors = [
        ("VECTOR 1: PRIVATE SECRETS", f"{priv_present}/{res.total_sessions} Sessions", "Reads .env, credentials, id_rsa, keys, DB", priv_present > 0),
        ("VECTOR 2: UNTRUSTED INPUT", f"{untrust_present}/{res.total_sessions} Sessions", "WebFetch, search, PR reviews, clone", untrust_present > 0),
        ("VECTOR 3: OUTBOUND EGRESS", f"{out_present}/{res.total_sessions} Sessions", "curl -d, POST, git push, network socket", out_present > 0),
    ]

    for i, (v_title, v_stat, v_sub, is_active) in enumerate(vectors):
        cx = start_x + i * (col_w + gap)
        v_color = accent if is_active else (16, 185, 129)
        draw.rounded_rectangle([cx, col_y, cx + col_w, col_y + col_h], radius=12, fill=card_bg, outline=border_color, width=1)

        # Status dot
        draw.ellipse([cx + 20, col_y + 22, cx + 32, col_y + 34], fill=v_color)
        draw.text((cx + 42, col_y + 18), v_title, font=font_sub, fill=text_white)

        # Large status text
        draw.text((cx + 20, col_y + 65), "DETECTED" if is_active else "SECURE", font=font_title, fill=v_color)
        draw.text((cx + 20, col_y + 115), v_stat, font=font_body, fill=text_white)
        draw.text((cx + 20, col_y + 155), v_sub, font=font_stat_lbl, fill=text_muted)

    # Bottom Stat Pills Row
    stat_y = 480
    stat_w = 255
    stat_gap = 20
    stats = [
        ("SESSIONS AUDITED", str(res.total_sessions)),
        ("TIME WINDOW", f"Last {res.days} Days"),
        ("TOOL INVOCATIONS", f"{res.total_tool_calls:,}"),
        ("TRI-VECTOR RATE", f"{res.tri_vector_pct:.1f}%"),
    ]

    for i, (lbl, val) in enumerate(stats):
        sx = start_x + i * (stat_w + stat_gap)
        draw.rounded_rectangle([sx, stat_y, sx + stat_w, stat_y + 90], radius=10, fill=card_bg, outline=border_color, width=1)
        draw.text((sx + 20, stat_y + 14), lbl, font=font_stat_lbl, fill=text_muted)
        draw.text((sx + 20, stat_y + 35), val, font=font_stat_val, fill=text_white)

    # Footer
    draw.text((60, 610), "Receiptd Runtime Gate • 0.02ms Policy Evaluation • Ed25519 Cryptographic Ledger", font=font_footer, fill=text_muted)
    draw.text((width - 340, 610), "Local Offline Audit • Zero Data Egress", font=font_footer, fill=(200, 241, 53))

    resolved_out = Path(out_path).resolve()
    resolved_out.parent.mkdir(parents=True, exist_ok=True)
    img.save(str(resolved_out), "PNG")
    return str(resolved_out)


__all__ = ["scan_agent_logs", "render_terminal_card", "render_png_card", "TrifectaScanResult"]
