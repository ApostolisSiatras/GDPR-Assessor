from __future__ import annotations

import html
import re
from datetime import UTC, datetime
from io import BytesIO
from typing import List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
from reportlab.lib.pdfencrypt import StandardEncryption

from .config import PANDOC_PATH


def _format_inline(raw: str) -> str:
    escaped = html.escape(raw, quote=True)

    def link_repl(match: re.Match[str]) -> str:
        text = match.group(1)
        href = match.group(2)
        return f'<a href="{href}" target="_blank" rel="noopener">{text}</a>'

    escaped = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", link_repl, escaped)
    escaped = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped)
    escaped = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"<em>\1</em>", escaped)
    return escaped


def markdown_to_html(md_text: str) -> str:
    lines = (md_text or "").splitlines()
    html_lines: List[str] = []
    in_ul = False
    in_ol = False
    for raw_line in lines:
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            if in_ul:
                html_lines.append("</ul>")
                in_ul = False
            if in_ol:
                html_lines.append("</ol>")
                in_ol = False
            continue
        if stripped.startswith("#"):
            if in_ul:
                html_lines.append("</ul>")
                in_ul = False
            if in_ol:
                html_lines.append("</ol>")
                in_ol = False
            level = len(stripped) - len(stripped.lstrip("#"))
            content = stripped[level:].strip()
            level = max(1, min(level, 6))
            html_lines.append(f"<h{level}>{_format_inline(content)}</h{level}>")
            continue
        if stripped.startswith("- ") or stripped.startswith("* "):
            if not in_ul:
                html_lines.append("<ul>")
                in_ul = True
            html_lines.append(f"<li>{_format_inline(stripped[2:].strip())}</li>")
            continue
        ordered_match = re.match(r"^(\d+)\.\s+(.*)", stripped)
        if ordered_match:
            if not in_ol:
                html_lines.append("<ol>")
                in_ol = True
            html_lines.append(f"<li>{_format_inline(ordered_match.group(2).strip())}</li>")
            continue
        html_lines.append(f"<p>{_format_inline(stripped)}</p>")
    if in_ul:
        html_lines.append("</ul>")
    if in_ol:
        html_lines.append("</ol>")
    body = "\n".join(html_lines)
    html_doc = (
        "<!doctype html><html><head><meta charset='utf-8'><style>"
        "body{font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#0f172a;line-height:1.6;padding:2rem;background:#f9fafb;}"
        "h1,h2,h3,h4{color:#0f172a;} ul,ol{padding-left:1.4rem;} pre{background:#0f172a;color:#e2e8f0;padding:1rem;border-radius:12px;}"
        "p{margin-bottom:1rem;} a{color:#2563eb;text-decoration:none;} a:hover{text-decoration:underline;}"
        "</style></head><body>"
        f"{body}"
        "</body></html>"
    )
    return html_doc


def markdown_to_pdf_bytes(markdown_text: str, policy_number: str, signature: str) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=60,
        rightMargin=60,
        topMargin=80,
        bottomMargin=72,
    )

    styles = getSampleStyleSheet()
    heading1 = ParagraphStyle(
        "Heading1",
        parent=styles["Heading1"],
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=12,
    )
    heading2 = ParagraphStyle(
        "Heading2",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#1d4ed8"),
        spaceAfter=10,
    )
    body = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#1f2937"),
        spaceAfter=8,
    )
    bullet = ParagraphStyle(
        "Bullet",
        parent=body,
        bulletIndent=12,
        leftIndent=18,
    )
    small = ParagraphStyle(
        "Small",
        parent=body,
        fontSize=9,
        textColor=colors.HexColor("#475467"),
    )

    elements = []
    lines = markdown_text.splitlines()
    for raw in lines:
        line = raw.rstrip()
        if not line:
            elements.append(Spacer(1, 6))
            continue
        if line.startswith("## "):
            elements.append(Paragraph(line[3:].strip(), heading2))
        elif line.startswith("# "):
            elements.append(Paragraph(line[2:].strip(), heading1))
        elif line.startswith("- ") or line.startswith("* "):
            elements.append(Paragraph(f"• {html.escape(line[2:].strip())}", bullet))
        else:
            elements.append(Paragraph(html.escape(line), body))

    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Verification hash: {signature}", small))

    watermark_text = f"{policy_number} — Confidential"

    def _header(canvas_obj, doc_obj):
        canvas_obj.saveState()
        canvas_obj.setFillColor(colors.HexColor("#e0ecff"))
        canvas_obj.rect(0, letter[1] - 60, letter[0], 60, fill=1, stroke=0)
        canvas_obj.setFillColor(colors.HexColor("#0f172a"))
        canvas_obj.setFont("Helvetica-Bold", 12)
        canvas_obj.drawString(65, letter[1] - 40, f"Official GDPR Compliance Policy · {policy_number}")
        canvas_obj.setFont("Helvetica", 9)
        canvas_obj.setFillColor(colors.HexColor("#475467"))
        canvas_obj.drawRightString(letter[0] - 65, letter[1] - 40, f"Generated {datetime.now(UTC).strftime('%Y-%m-%d')}")

        canvas_obj.saveState()
        canvas_obj.translate(letter[0] / 2, letter[1] / 2)
        canvas_obj.rotate(45)
        canvas_obj.setFillColorRGB(0.8, 0.88, 1, alpha=0.35)
        canvas_obj.setFont("Helvetica-Bold", 42)
        canvas_obj.drawCentredString(0, 0, watermark_text)
        canvas_obj.restoreState()
        canvas_obj.restoreState()

    class SecureCanvas(canvas.Canvas):
        def __init__(self, *args, **kwargs):
            password = kwargs.pop("password", None)
            if password:
                kwargs["encrypt"] = StandardEncryption(password, ownerPassword=password)
            super().__init__(*args, **kwargs)

    doc.build(
        elements,
        onFirstPage=_header,
        onLaterPages=_header,
        canvasmaker=lambda *args, **kwargs: SecureCanvas(*args, password=policy_number, **kwargs),
    )
    buffer.seek(0)
    return buffer.read()


def markdown_to_pdf_report(markdown_text: str, title: str, subtitle: Optional[str] = None) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=64,
        rightMargin=64,
        topMargin=72,
        bottomMargin=72,
    )
    styles = getSampleStyleSheet()
    hero = ParagraphStyle(
        "Hero",
        parent=styles["Heading1"],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#102a43"),
        spaceAfter=12,
    )
    subhead = ParagraphStyle(
        "Subhead",
        parent=styles["Heading2"],
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#475467"),
        spaceAfter=16,
    )
    heading = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=10,
    )
    body = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontSize=11,
        leading=16,
        textColor=colors.HexColor("#1f2937"),
        spaceAfter=8,
    )
    bullet = ParagraphStyle(
        "Bullet",
        parent=body,
        leftIndent=18,
        bulletIndent=9,
    )
    small = ParagraphStyle(
        "Small",
        parent=body,
        fontSize=9,
        textColor=colors.HexColor("#475467"),
    )

    elements = [Paragraph(title, hero)]
    if subtitle:
        elements.append(Paragraph(html.escape(subtitle), subhead))
    elements.append(Spacer(1, 6))

    lines = markdown_text.splitlines()
    for raw in lines:
        line = raw.rstrip()
        if not line:
            elements.append(Spacer(1, 6))
            continue
        stripped = line.strip()
        if stripped.startswith("### "):
            elements.append(Paragraph(html.escape(stripped[4:].strip()), heading))
        elif stripped.startswith("## "):
            elements.append(Paragraph(html.escape(stripped[3:].strip()), heading))
        elif stripped.startswith("# "):
            elements.append(Paragraph(html.escape(stripped[2:].strip()), heading))
        elif stripped.startswith("- ") or stripped.startswith("* "):
            elements.append(Paragraph(f"• {html.escape(stripped[2:].strip())}", bullet))
        else:
            ordered = re.match(r"^(\d+)\.\s+(.*)", stripped)
            if ordered:
                elements.append(Paragraph(f"{ordered.group(1)}. {html.escape(ordered.group(2).strip())}", body))
            else:
                elements.append(Paragraph(html.escape(stripped), body))

    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Generated {datetime.now(UTC).strftime('%Y-%m-%d %H:%M %Z')}", small))

    def _footer(canvas_obj, doc_obj):
        canvas_obj.saveState()
        canvas_obj.setFont("Helvetica", 9)
        canvas_obj.setFillColor(colors.HexColor("#475467"))
        canvas_obj.drawString(64, 40, title)
        canvas_obj.drawRightString(letter[0] - 64, 40, f"Page {doc_obj.page}")
        canvas_obj.restoreState()

    doc.build(elements, onFirstPage=_footer, onLaterPages=_footer)
    buffer.seek(0)
    return buffer.read()


def convert_markdown_with_pandoc(markdown_text: str, target_format: str) -> bytes:
    if not PANDOC_PATH:
        raise RuntimeError("Pandoc is not installed; conversion unavailable.")
    import tempfile
    from pathlib import Path
    import subprocess

    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "input.md"
        src.write_text(markdown_text, encoding="utf-8")
        output = Path(tmpdir) / f"output.{target_format}"
        try:
            subprocess.run(
                [PANDOC_PATH, str(src), "-o", str(output)],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as exc:  # pragma: no cover
            raise RuntimeError(
                f"Pandoc conversion failed: {exc.stderr.decode('utf-8', errors='ignore')}"
            ) from exc
        return output.read_bytes()
