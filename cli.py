"""
WebXploit Chain CLI — command-line interface for the framework.

Commands:
  chain     Analyse findings and suggest attack chains
  report    Generate engagement report (md/html/json)
  scope     Validate a URL against a scope config
  payload   Generate payloads for a vuln type
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _print_banner() -> None:
    banner = r"""
 ____      ____     _____           _       _ _    ____ _           _
\ \  \    / / /__  | ____|_  ___ __| | ___ (_) |_ / ___| |__   __ _(_)_ __
 \ \  \  / / / _ \ |  _| \ \/ / '_ \| |/ _ \| | __| |   | '_ \ / _` | | '_ \
  \ \  \/ / /  __/ | |___ >  <| |_) | | (_) | | |_| |___| | | | (_| | | | | |
   \_\  /_/  \___| |_____/_/\_\ .__/|_|\___/|_|\__|\____|_| |_|\__,_|_|_| |_|
                                |_|
    Web exploitation framework for red team engagements | v0.1.0
    """
    print(banner)


def cmd_chain(args: list[str]) -> None:
    """Load findings from JSON and run the chaining engine."""
    from webxploit.core.chain_engine import ChainEngine
    from webxploit.core.models import Finding, Severity, VulnType, ExploitStatus

    if not args:
        print("Usage: webxploit chain <findings.json>")
        sys.exit(1)

    findings_path = Path(args[0])
    if not findings_path.exists():
        print(f"[!] File not found: {findings_path}")
        sys.exit(1)

    raw = json.loads(findings_path.read_text())
    findings: list[Finding] = []
    for item in raw:
        try:
            f = Finding(
                vuln_type=VulnType(item["vuln_type"]),
                url=item["url"],
                parameter=item.get("parameter"),
                severity=Severity(item.get("severity", "medium")),
                evidence=item.get("evidence", ""),
                payload=item.get("payload", ""),
                notes=item.get("notes", ""),
                status=ExploitStatus(item.get("status", "suspected")),
            )
            findings.append(f)
        except (KeyError, ValueError) as e:
            print(f"[!] Skipping invalid finding entry: {e}")

    if not findings:
        print("[!] No valid findings loaded.")
        sys.exit(1)

    print(f"[*] Loaded {len(findings)} findings. Running chain engine...\n")
    engine = ChainEngine()
    results = engine.analyse(findings)

    if not results:
        print("[~] No chains identified with current findings.")
        return

    print(f"[+] {len(results)} chain(s) identified:\n")
    for i, r in enumerate(results, 1):
        print(f"  {i}. {r.chain.chain_label}")
        print(f"     Score: {r.score:.2f}  |  Confidence: {r.confidence:.0%}  |  Severity: {r.chain.severity.value}")
        print(f"     {r.reasoning[:120]}...")
        print()


def cmd_report(args: list[str]) -> None:
    """Generate a report from an engagement JSON file."""
    from webxploit.core.models import Engagement, Finding, VulnChain, Severity, VulnType, ExploitStatus
    from webxploit.reporting.reporter import EngagementReporter

    if not args:
        print("Usage: webxploit report <engagement.json> [output_dir]")
        sys.exit(1)

    eng_path = Path(args[0])
    out_dir  = args[1] if len(args) > 1 else "reports"

    raw = json.loads(eng_path.read_text())
    engagement = Engagement(
        name=raw.get("name", "Unnamed Engagement"),
        scope=raw.get("scope", []),
        exclusions=raw.get("exclusions", []),
        operator=raw.get("operator", "unknown"),
        notes=raw.get("notes", ""),
    )
    for item in raw.get("findings", []):
        try:
            engagement.add_finding(Finding(
                vuln_type=VulnType(item["vuln_type"]),
                url=item["url"],
                parameter=item.get("parameter"),
                severity=Severity(item.get("severity", "medium")),
                evidence=item.get("evidence", ""),
                payload=item.get("payload", ""),
                notes=item.get("notes", ""),
                status=ExploitStatus(item.get("status", "suspected")),
            ))
        except (KeyError, ValueError) as e:
            print(f"[!] Skipping finding: {e}")

    reporter = EngagementReporter(engagement)
    paths = reporter.save_all(out_dir)
    print(f"[+] Reports saved:")
    for fmt, p in paths.items():
        print(f"    {fmt.upper():5s} → {p}")


def cmd_scope(args: list[str]) -> None:
    """Check if a URL is in scope."""
    from webxploit.core.scope import ScopeEnforcer, ScopeViolation

    if len(args) < 2:
        print("Usage: webxploit scope <scope.yaml> <url>")
        sys.exit(1)

    enforcer = ScopeEnforcer.from_yaml(args[0])
    url = args[1]
    try:
        enforcer.check(url)
        print(f"[+] IN SCOPE: {url}")
    except ScopeViolation as e:
        print(f"[-] OUT OF SCOPE: {e}")


def cmd_payload(args: list[str]) -> None:
    """Generate payloads for a vulnerability type."""
    from webxploit.core.models import VulnType
    from webxploit.payloads.builder import PayloadBuilder, WAFType

    if not args:
        types = ", ".join(v.value for v in VulnType)
        print(f"Usage: webxploit payload <vuln_type> [waf_type]\nTypes: {types}")
        sys.exit(1)

    try:
        vuln = VulnType(args[0].lower())
    except ValueError:
        print(f"[!] Unknown vuln type: {args[0]}")
        sys.exit(1)

    waf = WAFType.NONE
    if len(args) > 1:
        try:
            waf = WAFType(args[1].lower())
        except ValueError:
            print(f"[!] Unknown WAF type: {args[1]} — using NONE")

    builder = PayloadBuilder()
    result = builder.build(vuln)
    print(f"\n[*] Payloads for {vuln.value.upper()} (WAF: {waf.value}):\n")
    for i, p in enumerate(result.payloads, 1):
        print(f"  {i:2d}. {p}")
    print()


def main() -> None:
    _print_banner()
    if len(sys.argv) < 2:
        print("Commands: chain | report | scope | payload\n")
        print("  chain   <findings.json>              — analyse findings for chains")
        print("  report  <engagement.json> [out_dir]  — generate MD/HTML/JSON report")
        print("  scope   <scope.yaml> <url>           — check if URL is in scope")
        print("  payload <vuln_type> [waf_type]       — generate payloads\n")
        sys.exit(0)

    command = sys.argv[1].lower()
    rest    = sys.argv[2:]

    dispatch = {
        "chain":   cmd_chain,
        "report":  cmd_report,
        "scope":   cmd_scope,
        "payload": cmd_payload,
    }

    fn = dispatch.get(command)
    if fn is None:
        print(f"[!] Unknown command: {command!r}")
        sys.exit(1)
    fn(rest)


if __name__ == "__main__":
    main()
