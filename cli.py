"""Command-line interface for WebXploit Chain."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Optional

from builder import Fingerprinter, FingerprintResult, PayloadBuilder, TechStack, WAFType
from chain_engine import ChainEngine, ChainGraph
from http_automation import HTTPTester, PayloadTestResult
from models import Engagement, ExploitStatus, Finding, Severity, VulnType
from reporter import EngagementReporter
from scope import ScopeEnforcer, ScopeViolation

logger = logging.getLogger(__name__)


def _print_banner() -> None:
    print(
        "WebXploit Chain v0.1.0\n"
        "Authorised web exploitation workflow: fingerprint -> payloads -> chains -> report"
    )


def _parse_header(values: Optional[list[str]]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for value in values or []:
        if ":" not in value:
            raise argparse.ArgumentTypeError(f"Invalid header {value!r}; use 'Name: value'")
        name, header_value = value.split(":", 1)
        headers[name.strip()] = header_value.strip()
    return headers


def _load_scope(path: Optional[str]) -> Optional[ScopeEnforcer]:
    return ScopeEnforcer.from_yaml(path) if path else None


def _json_default(value: object) -> str:
    return str(getattr(value, "value", value))


def _print_json(data: object) -> None:
    print(json.dumps(data, indent=2, default=_json_default))


def _console_text(value: object) -> str:
    return str(value).replace("→", "->").replace("—", "-")


def _parse_finding(item: dict[str, Any]) -> Finding:
    return Finding(
        vuln_type=VulnType(item["vuln_type"]),
        url=item["url"],
        parameter=item.get("parameter"),
        severity=Severity(item.get("severity", "medium")),
        status=ExploitStatus(item.get("status", "suspected")),
        evidence=item.get("evidence", ""),
        payload=item.get("payload", ""),
        notes=item.get("notes", ""),
        cvss_score=item.get("cvss_score"),
        tags=item.get("tags", []),
    )


def _load_findings(path: Path) -> list[Finding]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    entries = raw.get("findings", []) if isinstance(raw, dict) else raw
    findings: list[Finding] = []
    for item in entries:
        try:
            findings.append(_parse_finding(item))
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning("Skipping invalid finding entry: %s", exc)
    return findings


def _fingerprint_to_dict(result: FingerprintResult, url: str) -> dict[str, object]:
    return {
        "url": url,
        "stack": result.stack.value,
        "waf": result.waf.value,
        "confidence": result.confidence,
        "indicators": result.indicators,
    }


def cmd_fingerprint(args: argparse.Namespace) -> int:
    tester = HTTPTester(
        scope_enforcer=_load_scope(args.scope),
        timeout=args.timeout,
    )
    try:
        response = tester.fetch(
            args.url,
            method=args.method,
            body=args.body,
            headers=_parse_header(args.header),
        )
    except ScopeViolation as exc:
        print(f"[-] OUT OF SCOPE: {_console_text(exc)}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"[!] Request failed: {exc}", file=sys.stderr)
        return 1

    result = Fingerprinter().fingerprint(
        url=response.url,
        headers=response.headers,
        body=response.body,
        status_code=str(response.status_code),
    )
    if args.json:
        data = _fingerprint_to_dict(result, response.url)
        data["status_code"] = response.status_code
        data["elapsed"] = round(response.elapsed, 3)
        _print_json(data)
        return 0

    print(f"[+] {response.url}")
    print(f"    Status: {response.status_code} ({response.elapsed:.2f}s)")
    print(f"    Stack: {result.stack.value}")
    print(f"    WAF: {result.waf.value}")
    print(f"    Confidence: {result.confidence:.0%}")
    for indicator in result.indicators:
        print(f"    - {indicator}")
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    vuln_value = args.vuln or (args.legacy[0] if args.legacy else None)
    waf_value = args.waf or (args.legacy[1] if len(args.legacy) > 1 else None)
    if not vuln_value:
        print("[!] Missing vuln type. Use: webxploit generate --vuln xss", file=sys.stderr)
        return 1

    try:
        vuln = VulnType(vuln_value.lower())
        fingerprint = FingerprintResult(
            stack=TechStack(args.stack) if args.stack else TechStack.UNKNOWN,
            waf=WAFType(waf_value) if waf_value else WAFType.UNKNOWN,
        )
    except ValueError as exc:
        print(f"[!] Invalid generate option: {exc}", file=sys.stderr)
        return 1

    result = PayloadBuilder().build(
        vuln,
        fingerprint=fingerprint,
        include_encodings=not args.no_encodings,
        max_payloads=args.max_payloads,
    )
    if args.json:
        _print_json(
            {
                "vuln_type": result.vuln_type.value,
                "stack": result.stack.value,
                "waf": result.waf.value,
                "payloads": result.payloads,
                "encoded": result.encoded,
            }
        )
        return 0

    print(
        f"[*] Payloads for {vuln.value.upper()} (stack={result.stack.value}, waf={result.waf.value})"
    )
    if not result.payloads:
        print("[~] No payloads available for this vulnerability type.")
        return 0
    for index, payload in enumerate(result.payloads, 1):
        print(f"{index:2d}. {payload}")
    if args.show_encodings:
        for encoding, payloads in result.encoded.items():
            print(f"\n[{encoding}]")
            for payload in payloads:
                print(f"  {payload}")
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    tester = HTTPTester(scope_enforcer=_load_scope(args.scope), timeout=args.timeout)
    try:
        result = tester.test_payload(
            url=args.url,
            payload=args.payload,
            parameter=args.param,
            method=args.method,
            expected=args.expect,
            headers=_parse_header(args.header),
        )
    except ScopeViolation as exc:
        print(f"[-] OUT OF SCOPE: {_console_text(exc)}", file=sys.stderr)
        return 2

    if args.json:
        _print_json(result.to_dict())
        return 0 if not result.error else 1

    _print_test_result(result)
    return 0 if not result.error else 1


def _print_test_result(result: PayloadTestResult) -> None:
    if result.error:
        print(f"[!] Test failed: {result.error}")
        return
    print(f"[*] {result.method} {result.url}")
    print(f"    Status: {result.status_code} ({result.elapsed:.2f}s)")
    print(f"    Result: {'POTENTIAL HIT' if result.success else 'no clear signal'}")
    for indicator in result.indicators:
        print(f"    - {indicator}")
    if result.response_excerpt:
        print("    Response excerpt:")
        print(result.response_excerpt.replace("\n", "\\n")[:300])


def cmd_chain(args: argparse.Namespace) -> int:
    path = Path(args.findings)
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        return 1
    findings = _load_findings(path)
    if not findings:
        print("[!] No valid findings loaded.", file=sys.stderr)
        return 1
    if args.top is not None and args.top < 1:
        print("[!] --top must be greater than zero.", file=sys.stderr)
        return 1

    try:
        graph = ChainGraph(custom_rules_path=args.rules) if args.rules else None
        results = ChainEngine(graph=graph, max_depth=args.max_depth).analyse(
            findings,
            min_confidence=args.min_confidence,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    if args.top:
        results = results[: args.top]
    if args.json:
        _print_json(
            [
                {
                    "chain": result.chain.to_dict(),
                    "score": result.score,
                    "confidence": result.confidence,
                    "reasoning": result.reasoning,
                }
                for result in results
            ]
        )
        return 0

    print(f"[*] Loaded {len(findings)} findings. Running chain engine...")
    if not results:
        print("[~] No chains identified with current findings.")
        return 0
    print(f"[+] {len(results)} chain(s) identified:\n")
    for index, result in enumerate(results, 1):
        print(f"{index}. {_console_text(result.chain.chain_label)}")
        print(
            f"   Score: {result.score:.2f} | Confidence: {result.confidence:.0%} | "
            f"Severity: {result.chain.severity.value}"
        )
        print(f"   {_console_text(result.reasoning)}\n")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    path = Path(args.engagement)
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        return 1
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        raw = {"name": path.stem, "findings": raw}

    engagement = Engagement(
        name=raw.get("name", "Unnamed Engagement"),
        scope=raw.get("scope", []),
        exclusions=raw.get("exclusions", []),
        operator=raw.get("operator", "unknown"),
        notes=raw.get("notes", ""),
    )
    for finding in _load_findings(path):
        engagement.add_finding(finding)
    if args.include_chains:
        try:
            graph = ChainGraph(custom_rules_path=args.rules) if args.rules else None
            results = ChainEngine(graph=graph).analyse(engagement.findings)
        except (FileNotFoundError, ValueError) as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 1
        for result in results:
            engagement.add_chain(result.chain)

    paths = EngagementReporter(engagement).save_all(args.output_dir)
    print("[+] Reports saved:")
    for fmt, report_path in paths.items():
        print(f"    {fmt.upper():5s} -> {report_path}")
    return 0


def cmd_scope(args: argparse.Namespace) -> int:
    try:
        ScopeEnforcer.from_yaml(args.scope).check(args.url)
    except ScopeViolation as exc:
        print(f"[-] OUT OF SCOPE: {_console_text(exc)}")
        return 2
    print(f"[+] IN SCOPE: {args.url}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="webxploit")
    parser.add_argument("--debug", action="store_true", help="enable debug logging")
    subparsers = parser.add_subparsers(dest="command", required=True)

    fp = subparsers.add_parser("fingerprint", help="fetch URL and detect stack/WAF")
    fp.add_argument("url")
    fp.add_argument("--method", default="GET", choices=["GET", "POST"])
    fp.add_argument("--body")
    fp.add_argument("--header", action="append", help="HTTP header as 'Name: value'")
    fp.add_argument("--scope")
    fp.add_argument("--timeout", type=float, default=10.0)
    fp.add_argument("--json", action="store_true")
    fp.set_defaults(func=cmd_fingerprint)

    gen = subparsers.add_parser("generate", aliases=["payload"], help="generate payloads")
    gen.add_argument("legacy", nargs="*", help=argparse.SUPPRESS)
    gen.add_argument("--vuln")
    gen.add_argument("--waf", choices=[w.value for w in WAFType])
    gen.add_argument("--stack", choices=[s.value for s in TechStack])
    gen.add_argument("--max-payloads", type=int, default=10)
    gen.add_argument("--no-encodings", action="store_true")
    gen.add_argument("--show-encodings", action="store_true")
    gen.add_argument("--json", action="store_true")
    gen.set_defaults(func=cmd_generate)

    tst = subparsers.add_parser("test", help="send one payload and inspect response")
    tst.add_argument("--url", required=True)
    tst.add_argument("--payload", required=True)
    tst.add_argument("--param")
    tst.add_argument("--method", default="GET", choices=["GET", "POST"])
    tst.add_argument("--expect")
    tst.add_argument("--header", action="append")
    tst.add_argument("--scope")
    tst.add_argument("--timeout", type=float, default=10.0)
    tst.add_argument("--json", action="store_true")
    tst.set_defaults(func=cmd_test)

    chain = subparsers.add_parser("chain", help="analyse findings and suggest chains")
    chain.add_argument("findings")
    chain.add_argument("--min-confidence", type=float, default=0.5)
    chain.add_argument("--max-depth", type=int, default=4)
    chain.add_argument("--top", type=int, help="show only the top N ranked chains")
    chain.add_argument("--rules", help="load additional chain rules from YAML or JSON")
    chain.add_argument("--json", action="store_true")
    chain.set_defaults(func=cmd_chain)

    report = subparsers.add_parser("report", help="generate engagement reports")
    report.add_argument("engagement")
    report.add_argument("output_dir", nargs="?", default="reports")
    report.add_argument("--include-chains", action="store_true")
    report.add_argument("--rules", help="load additional chain rules from YAML or JSON")
    report.set_defaults(func=cmd_report)

    scope = subparsers.add_parser("scope", help="validate URL against scope.yaml")
    scope.add_argument("scope")
    scope.add_argument("url")
    scope.set_defaults(func=cmd_scope)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.ERROR,
        format="%(levelname)s: %(message)s",
    )
    return int(args.func(args))


if __name__ == "__main__":
    _print_banner()
    raise SystemExit(main())
