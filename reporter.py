"""
Engagement Reporter — generates structured reports from an Engagement object.

Outputs:
  - Markdown  (.md)  — readable in GitHub, Obsidian, any editor
  - HTML      (.html)— self-contained report with basic styling
  - JSON      (.json)— machine-readable for CI/CD integrations

Report structure:
  1. Executive Summary
  2. Scope & Methodology
  3. Findings (sorted by severity)
  4. Attack Chains
  5. Recommendations
  6. Appendix (raw evidence)
"""

from __future__ import annotations

import json
import textwrap
from datetime import datetime
from html import escape
from pathlib import Path

from webxploit.core.models import Engagement, Finding, Severity, VulnChain


# ---------------------------------------------------------------------------
# Severity → CVSS reference scores
# ---------------------------------------------------------------------------

_CVSS_REFERENCE = {
    Severity.CRITICAL: "9.0-10.0",
    Severity.HIGH: "7.0-8.9",
    Severity.MEDIUM: "4.0-6.9",
    Severity.LOW: "0.1-3.9",
    Severity.INFO: "0.0",
}

_CVSS_ESTIMATE = {
    Severity.CRITICAL: 9.4,
    Severity.HIGH: 8.1,
    Severity.MEDIUM: 5.4,
    Severity.LOW: 2.7,
    Severity.INFO: 0.0,
}

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "[CRITICAL]",
    Severity.HIGH: "[HIGH]",
    Severity.MEDIUM: "[MEDIUM]",
    Severity.LOW: "[LOW]",
    Severity.INFO: "[INFO]",
}

_REMEDIATION_HINTS: dict[str, str] = {
    "xss": "Encode all user-supplied output using context-aware escaping (HTML, JS, CSS, URL). Implement a strict Content Security Policy.",
    "sqli": "Use parameterised queries or prepared statements exclusively. Apply the principle of least privilege to database accounts.",
    "csrf": "Implement synchronised CSRF tokens or SameSite=Strict cookies for all state-changing operations.",
    "ssrf": "Validate and allowlist destination URLs server-side. Disable unnecessary URL-fetching functionality. Segment internal networks.",
    "idor": "Implement object-level access control checks on every request. Avoid exposing internal sequential IDs; use UUIDs.",
    "lfi": "Never pass user input to file-system functions. If unavoidable, whitelist allowed paths strictly.",
    "rce": "Eliminate any user-controlled input in OS command calls. Use language-level APIs instead of shell calls.",
    "auth_bypass": "Enforce authentication checks server-side for every sensitive endpoint. Review token/session validation logic.",
    "info_disclosure": "Remove debug endpoints, stack traces, and verbose error messages from production. Rotate any exposed credentials immediately.",
    "ssti": "Use sandboxed template engines. Avoid passing user input into template rendering functions.",
    "open_redirect": "Validate redirect URLs against a strict allowlist. Reject relative or external redirect targets.",
    "privilege_escalation": "Enforce server-side role checks on every privileged action. Do not rely on client-supplied role parameters.",
    "deserialisation": "Avoid deserialising untrusted data. If unavoidable, sign serialised payloads and use a type allowlist.",
    "xxe": "Disable XML external entity processing in all XML parsers. Use less complex data formats (JSON) where possible.",
}


# ---------------------------------------------------------------------------
# Markdown report generator
# ---------------------------------------------------------------------------


class MarkdownReporter:
    def generate(self, engagement: Engagement) -> str:
        sections = [
            self._header(engagement),
            self._executive_summary(engagement),
            self._scope_section(engagement),
            self._findings_section(engagement),
            self._chains_section(engagement),
            self._recommendations_section(engagement),
            self._appendix(engagement),
        ]
        return "\n\n".join(s for s in sections if s)

    # ------------------------------------------------------------------ #

    def _header(self, e: Engagement) -> str:
        now = datetime.utcnow().strftime("%Y-%m-%d")
        return textwrap.dedent(f"""\
            # {e.name} - Penetration Test Report

            | Field       | Value                   |
            |-------------|-------------------------|
            | Operator    | {e.operator}             |
            | Date        | {now}                   |
            | Engagement  | `{e.id}`                |
            | Findings    | {len(e.findings)}        |
            | Chains      | {len(e.chains)}          |

            ---
        """)

    def _executive_summary(self, e: Engagement) -> str:
        by_sev = e.findings_by_severity
        rows = "\n".join(
            f"| {_SEVERITY_EMOJI[Severity(sev)]} {sev.capitalize()} | {len(findings)} |"
            for sev, findings in by_sev.items()
            if findings
        )
        return textwrap.dedent(f"""\
            ## Executive Summary

            This report documents the findings of a web application penetration test
            conducted against **{e.name}**.
            {"A total of **" + str(len(e.findings)) + " vulnerabilities** were identified." if e.findings else "No findings were recorded."}
            {"**" + str(len(e.chains)) + " multi-step attack chains** were identified." if e.chains else ""}

            ### Finding Distribution

            | Severity | Count |
            |----------|-------|
            {rows}
        """)

    def _scope_section(self, e: Engagement) -> str:
        scope_list = "\n".join(f"- `{s}`" for s in e.scope) or "_No scope defined._"
        excl_list = "\n".join(f"- `{s}`" for s in e.exclusions) or "_None._"
        return textwrap.dedent(f"""\
            ## Scope & Methodology

            ### In Scope
            {scope_list}

            ### Exclusions
            {excl_list}

            ### Notes
            {e.notes or "_No additional notes._"}
        """)

    def _findings_section(self, e: Engagement) -> str:
        if not e.findings:
            return "## Findings\n\n_No findings recorded._"

        sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        sorted_findings = sorted(e.findings, key=lambda f: sev_order.index(f.severity))

        blocks = ["## Findings\n"]
        for i, f in enumerate(sorted_findings, 1):
            blocks.append(self._finding_block(i, f))
        return "\n".join(blocks)

    def _finding_block(self, idx: int, f: Finding) -> str:
        if f.cvss_score:
            cvss_key, cvss_val = "CVSS", str(f.cvss_score)
        else:
            cvss_key = "CVSS Estimate"
            cvss_val = f"{_CVSS_ESTIMATE[f.severity]:.1f} ({_CVSS_REFERENCE[f.severity]})"
        remediation = _REMEDIATION_HINTS.get(f.vuln_type.value, "_Review vendor guidance._")
        payload_block = f"\n```\n{f.payload}\n```" if f.payload else ""
        evidence_block = f"\n**Evidence:**\n```\n{f.evidence}\n```" if f.evidence else ""
        return textwrap.dedent(f"""\
            ### [{f.id}] {_SEVERITY_EMOJI[f.severity]} {f.vuln_type.value.upper()} - {f.severity.value.capitalize()}

            | Field     | Value              |
            |-----------|--------------------|
            | URL       | `{f.url}`          |
            | Parameter | `{f.parameter or "N/A"}` |
            | Status    | {f.status.value}   |
            | {cvss_key} | {cvss_val} |

            **Description:** {f.notes or f"A {f.vuln_type.value} vulnerability was identified."}
            {evidence_block}
            **Payload used:**{payload_block}

            **Remediation:** {remediation}

            ---
        """)

    def _chains_section(self, e: Engagement) -> str:
        if not e.chains:
            return ""
        blocks = [
            "## Attack Chains\n",
            "_The following multi-step attack paths were identified, ordered by severity._\n",
        ]
        for i, chain in enumerate(e.chains, 1):
            blocks.append(self._chain_block(i, chain))
        return "\n".join(blocks)

    def _chain_block(self, idx: int, chain: VulnChain) -> str:
        steps = "\n".join(
            f"{link.step_number}. **{link.finding.vuln_type.value.upper()}** @ `{link.finding.url}`  \n"
            f"   _{link.action}_"
            for link in chain.links
        )
        return textwrap.dedent(f"""\
            ### Chain {idx}: {chain.chain_label}

            **Severity:** {_SEVERITY_EMOJI[chain.severity]} {chain.severity.value.capitalize()}  
            **Impact:** {chain.impact}

            **Description:** {chain.description}

            **Steps:**

            {steps}

            ---
        """)

    def _recommendations_section(self, e: Engagement) -> str:
        if not e.findings:
            return ""
        seen: set[str] = set()
        recs: list[str] = []
        for f in e.findings:
            key = f.vuln_type.value
            if key not in seen:
                seen.add(key)
                hint = _REMEDIATION_HINTS.get(key, "Review vendor documentation.")
                recs.append(f"- **{key.upper()}:** {hint}")
        return "## Recommendations\n\n" + "\n".join(recs)

    def _appendix(self, e: Engagement) -> str:
        if not any(f.request or f.response for f in e.findings):
            return ""
        blocks = ["## Appendix - Raw Evidence\n"]
        for f in e.findings:
            if f.request or f.response:
                blocks.append(f"### Finding {f.id}\n")
                if f.request:
                    blocks.append(f"**Request:**\n```http\n{f.request}\n```\n")
                if f.response:
                    blocks.append(f"**Response (excerpt):**\n```\n{f.response}\n```\n")
        return "\n".join(blocks)


def _inline_markdown(text: str) -> str:
    """Render the small subset of inline Markdown produced by this reporter."""
    escaped = escape(text)
    while "**" in escaped:
        start = escaped.find("**")
        end = escaped.find("**", start + 2)
        if end == -1:
            break
        escaped = (
            escaped[:start]
            + "<strong>"
            + escaped[start + 2 : end]
            + "</strong>"
            + escaped[end + 2 :]
        )
    while "`" in escaped:
        start = escaped.find("`")
        end = escaped.find("`", start + 1)
        if end == -1:
            break
        escaped = (
            escaped[:start] + "<code>" + escaped[start + 1 : end] + "</code>" + escaped[end + 1 :]
        )
    return escaped


def _markdown_to_html(markdown: str) -> str:
    """Convert the project-generated Markdown report to self-contained HTML."""
    html: list[str] = []
    lines = markdown.splitlines()
    in_code = False
    code_lines: list[str] = []
    in_list = False
    in_table = False
    table_row_count = 0

    def close_list() -> None:
        nonlocal in_list
        if in_list:
            html.append("</ul>")
            in_list = False

    def close_table() -> None:
        nonlocal in_table, table_row_count
        if in_table:
            html.append("</tbody></table>")
            in_table = False
            table_row_count = 0

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("```"):
            if in_code:
                html.append("<pre><code>" + escape("\n".join(code_lines)) + "</code></pre>")
                code_lines = []
                in_code = False
            else:
                close_list()
                close_table()
                in_code = True
            continue

        if in_code:
            code_lines.append(line)
            continue

        if not stripped:
            close_list()
            close_table()
            continue

        if stripped == "---":
            close_list()
            close_table()
            html.append("<hr>")
            continue

        if stripped.startswith("|") and stripped.endswith("|"):
            cells = [cell.strip() for cell in stripped.strip("|").split("|")]
            if all(set(cell) <= {"-"} for cell in cells):
                continue
            if not in_table:
                close_list()
                html.append("<table><tbody>")
                in_table = True
                table_row_count = 0
            tag = "th" if table_row_count == 0 else "td"
            html.append(
                "<tr>"
                + "".join(f"<{tag}>{_inline_markdown(cell)}</{tag}>" for cell in cells)
                + "</tr>"
            )
            table_row_count += 1
            continue

        close_table()

        if stripped.startswith("# "):
            close_list()
            html.append(f"<h1>{_inline_markdown(stripped[2:])}</h1>")
        elif stripped.startswith("## "):
            close_list()
            html.append(f"<h2>{_inline_markdown(stripped[3:])}</h2>")
        elif stripped.startswith("### "):
            close_list()
            html.append(f"<h3>{_inline_markdown(stripped[4:])}</h3>")
        elif stripped.startswith("- "):
            if not in_list:
                html.append("<ul>")
                in_list = True
            html.append(f"<li>{_inline_markdown(stripped[2:])}</li>")
        else:
            close_list()
            html.append(f"<p>{_inline_markdown(stripped)}</p>")

    close_list()
    close_table()
    if in_code:
        html.append("<pre><code>" + escape("\n".join(code_lines)) + "</code></pre>")
    return "\n".join(html)


# ---------------------------------------------------------------------------
# HTML report generator (wraps the Markdown output)
# ---------------------------------------------------------------------------


class HTMLReporter:
    """Generates a self-contained HTML report with inline CSS."""

    def generate(self, engagement: Engagement) -> str:
        md_content = MarkdownReporter().generate(engagement)
        body = _markdown_to_html(md_content)
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{escape(engagement.name)} - Report</title>
<style>
  :root {{ color-scheme: light; }}
  body {{ font-family: "Segoe UI", system-ui, sans-serif; max-width: 980px; margin: 2rem auto; padding: 0 1.25rem; color: #172033; line-height: 1.6; background: #ffffff; }}
  h1 {{ border-bottom: 3px solid #b91c1c; padding-bottom: .55rem; margin-bottom: 1.25rem; }}
  h2 {{ border-bottom: 1px solid #cbd5e1; padding-bottom: .3rem; margin-top: 2.25rem; }}
  h3 {{ color: #1f2937; margin-top: 1.5rem; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
  th, td {{ border: 1px solid #d7dde8; padding: .55rem .75rem; text-align: left; vertical-align: top; }}
  th {{ background: #f1f5f9; }}
  code {{ background: #eef2f7; padding: .1em .35em; border-radius: 4px; font-size: .92em; }}
  pre {{ background: #111827; color: #e5e7eb; padding: 1rem; border-radius: 6px; overflow-x: auto; }}
  pre code {{ background: none; color: inherit; padding: 0; }}
  hr {{ border: none; border-top: 1px solid #e5e7eb; margin: 2rem 0; }}
  ul, ol {{ padding-left: 1.4rem; }}
  footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #e5e7eb; font-size: .85em; color: #64748b; }}
</style>
</head>
<body>
{body}
<footer>
  Generated by WebXploit Chain - {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}
</footer>
</body>
</html>"""


# ---------------------------------------------------------------------------
# JSON reporter
# ---------------------------------------------------------------------------


class JSONReporter:
    def generate(self, engagement: Engagement) -> str:
        data = {
            "engagement": engagement.summary(),
            "scope": engagement.scope,
            "findings": [f.to_dict() for f in engagement.findings],
            "chains": [c.to_dict() for c in engagement.chains],
            "generated": datetime.utcnow().isoformat(),
        }
        return json.dumps(data, indent=2, default=str)


# ---------------------------------------------------------------------------
# Unified reporter
# ---------------------------------------------------------------------------


class EngagementReporter:
    """
    Convenience wrapper that generates all report formats.

    Usage
    -----
    ::

        reporter = EngagementReporter(engagement)
        reporter.save_all("reports/")
    """

    def __init__(self, engagement: Engagement) -> None:
        self.engagement = engagement
        self._md = MarkdownReporter()
        self._html = HTMLReporter()
        self._json = JSONReporter()

    def to_markdown(self) -> str:
        return self._md.generate(self.engagement)

    def to_html(self) -> str:
        return self._html.generate(self.engagement)

    def to_json(self) -> str:
        return self._json.generate(self.engagement)

    def save_all(self, output_dir: str = "reports") -> dict[str, Path]:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        slug = self.engagement.name.lower().replace(" ", "_")
        paths: dict[str, Path] = {}
        for ext, content in [
            ("md", self.to_markdown()),
            ("html", self.to_html()),
            ("json", self.to_json()),
        ]:
            p = out / f"{slug}_{self.engagement.id}.{ext}"
            p.write_text(content, encoding="utf-8")
            paths[ext] = p
        return paths
