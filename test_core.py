"""
Tests for the WebXploit Chain engine.

Run with: pytest tests/ -v
"""

import pytest
from webxploit.core.models import (
    Engagement,
    Finding,
    Severity,
    VulnType,
    ExploitStatus,
)
from webxploit.core.chain_engine import ChainEngine, ChainGraph, analyse_findings
from webxploit.core.scope import ScopeEnforcer, ScopeViolation
from webxploit.payloads.builder import PayloadBuilder, Fingerprinter, WAFType, TechStack
from webxploit.reporting.reporter import EngagementReporter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def xss_finding():
    return Finding(
        vuln_type=VulnType.XSS,
        url="https://app.target.org/search",
        parameter="q",
        severity=Severity.MEDIUM,
        status=ExploitStatus.CONFIRMED,
        payload="<script>alert(1)</script>",
        evidence="Reflected XSS confirmed.",
    )

@pytest.fixture
def csrf_finding():
    return Finding(
        vuln_type=VulnType.CSRF,
        url="https://app.target.org/admin/delete",
        parameter=None,
        severity=Severity.HIGH,
        status=ExploitStatus.CONFIRMED,
        evidence="No CSRF token on state-changing endpoint.",
    )

@pytest.fixture
def sqli_finding():
    return Finding(
        vuln_type=VulnType.SQLI,
        url="https://app.target.org/api/products",
        parameter="id",
        severity=Severity.HIGH,
        status=ExploitStatus.CONFIRMED,
        payload="1' AND SLEEP(5)--",
        evidence="Time-based blind SQLi confirmed.",
    )

@pytest.fixture
def info_disc_finding():
    return Finding(
        vuln_type=VulnType.INFO_DISCLOSURE,
        url="https://app.target.org/.env",
        parameter=None,
        severity=Severity.CRITICAL,
        status=ExploitStatus.CONFIRMED,
        evidence="DB_PASSWORD exposed.",
    )

@pytest.fixture
def sample_engagement(xss_finding, csrf_finding, sqli_finding):
    e = Engagement(name="Test Engagement", scope=["app.target.org"], operator="tester")
    e.add_finding(xss_finding)
    e.add_finding(csrf_finding)
    e.add_finding(sqli_finding)
    return e


# ---------------------------------------------------------------------------
# Chain engine tests
# ---------------------------------------------------------------------------

class TestChainEngine:

    def test_xss_to_csrf_chain_detected(self, xss_finding, csrf_finding):
        engine = ChainEngine()
        results = engine.analyse([xss_finding, csrf_finding])
        labels = [r.chain.chain_label for r in results]
        assert any("XSS" in label and "CSRF" in label for label in labels), \
            f"Expected XSS→CSRF chain, got: {labels}"

    def test_sqli_auth_bypass_chain(self, sqli_finding):
        engine = ChainEngine()
        results = engine.analyse([sqli_finding])
        labels = [r.chain.chain_label for r in results]
        assert any("SQLI" in label for label in labels)

    def test_results_sorted_by_score(self, xss_finding, csrf_finding, sqli_finding):
        engine = ChainEngine()
        results = engine.analyse([xss_finding, csrf_finding, sqli_finding])
        if len(results) > 1:
            assert results[0].score >= results[-1].score

    def test_empty_findings_returns_empty(self):
        engine = ChainEngine()
        assert engine.analyse([]) == []

    def test_single_finding_produces_chains(self, xss_finding):
        engine = ChainEngine()
        results = engine.analyse([xss_finding])
        # XSS should produce chains to CSRF, AUTH_BYPASS, RCE
        assert len(results) >= 1

    def test_min_confidence_filter(self, xss_finding):
        engine = ChainEngine()
        # Very high confidence threshold should return fewer/no results
        high = engine.analyse([xss_finding], min_confidence=0.99)
        low  = engine.analyse([xss_finding], min_confidence=0.0)
        assert len(high) <= len(low)

    def test_chain_has_links(self, xss_finding, csrf_finding):
        engine = ChainEngine()
        results = engine.analyse([xss_finding, csrf_finding])
        for r in results:
            assert len(r.chain.links) >= 2

    def test_suggest_next(self, xss_finding):
        engine = ChainEngine()
        suggestions = engine.suggest_next([VulnType.XSS])
        targets = [s.target for s in suggestions]
        assert VulnType.CSRF in targets or VulnType.AUTH_BYPASS in targets

    def test_info_disc_leads_to_auth_bypass(self, info_disc_finding):
        engine = ChainEngine()
        results = engine.analyse([info_disc_finding])
        labels = [r.chain.chain_label for r in results]
        assert any("INFO_DISCLOSURE" in label for label in labels)

    def test_convenience_function(self, xss_finding, csrf_finding):
        results = analyse_findings([xss_finding, csrf_finding])
        assert isinstance(results, list)

    def test_custom_edge(self):
        from webxploit.core.chain_engine import ChainEdge
        graph = ChainGraph()
        custom = ChainEdge(
            source=VulnType.IDOR,
            target=VulnType.RCE,
            description="Custom: IDOR to RCE via admin file upload",
            confidence=0.6,
        )
        graph.add_custom_edge(custom)
        edges = graph.edges_from(VulnType.IDOR)
        assert any(e.target == VulnType.RCE for e in edges)


# ---------------------------------------------------------------------------
# Scope enforcer tests
# ---------------------------------------------------------------------------

class TestScopeEnforcer:

    def test_in_scope_url(self):
        enforcer = ScopeEnforcer.from_list(["app.target.org"])
        assert enforcer.check("https://app.target.org/login") is True

    def test_wildcard_scope(self):
        enforcer = ScopeEnforcer.from_list(["*.target.org"])
        assert enforcer.is_in_scope("https://app.target.org/api")
        assert enforcer.is_in_scope("https://other.target.org/")

    def test_out_of_scope_raises(self):
        enforcer = ScopeEnforcer.from_list(["app.target.org"])
        with pytest.raises(ScopeViolation):
            enforcer.check("https://evil.com/steal")

    def test_exclusion_blocks_allowed(self):
        from webxploit.core.scope import ScopeConfig
        config = ScopeConfig(
            allowed=["*.target.org"],
            excluded=["admin.target.org"],
            strict=True,
        )
        enforcer = ScopeEnforcer(config)
        assert enforcer.is_in_scope("https://app.target.org")
        assert not enforcer.is_in_scope("https://admin.target.org")

    def test_filter_list(self):
        enforcer = ScopeEnforcer.from_list(["app.target.org"])
        urls = ["https://app.target.org/", "https://out.com/", "https://app.target.org/api"]
        result = enforcer.filter(urls)
        assert len(result) == 2
        assert all("app.target.org" in u for u in result)

    def test_violations_logged(self):
        from webxploit.core.scope import ScopeConfig
        config = ScopeConfig(allowed=["app.target.org"], strict=True, log_violations=True)
        enforcer = ScopeEnforcer(config)
        try:
            enforcer.check("https://evil.com")
        except ScopeViolation:
            pass
        assert len(enforcer.violations) == 1


# ---------------------------------------------------------------------------
# Payload builder tests
# ---------------------------------------------------------------------------

class TestPayloadBuilder:

    def test_xss_payloads_returned(self):
        builder = PayloadBuilder()
        result = builder.build(VulnType.XSS)
        assert len(result.payloads) >= 1
        assert result.best() != ""

    def test_waf_bypass_payloads_prioritised(self):
        builder = PayloadBuilder()
        from webxploit.payloads.builder import FingerprintResult
        fp = FingerprintResult(stack=TechStack.UNKNOWN, waf=WAFType.CLOUDFLARE, confidence=0.9)
        result = builder.build(VulnType.XSS, fingerprint=fp)
        # Should have WAF-specific payloads first
        assert result.waf == WAFType.CLOUDFLARE
        assert len(result.payloads) >= 1

    def test_encodings_generated(self):
        builder = PayloadBuilder()
        result = builder.build(VulnType.XSS, include_encodings=True)
        assert "url" in result.encoded
        assert "base64" in result.encoded

    def test_quick_payload(self):
        builder = PayloadBuilder()
        p = builder.quick(VulnType.SQLI)
        assert p != ""

    def test_unknown_vuln_returns_empty(self):
        builder = PayloadBuilder()
        # CSRF has no payload bank entry
        result = builder.build(VulnType.CSRF)
        assert result.payloads == []

    def test_fingerprinter_detects_php(self):
        fp = Fingerprinter()
        result = fp.fingerprint(
            headers={"X-Powered-By": "PHP/8.2", "Set-Cookie": "PHPSESSID=abc123"},
            url="https://example.com/page.php",
        )
        assert result.stack == TechStack.PHP

    def test_fingerprinter_detects_cloudflare(self):
        fp = Fingerprinter()
        result = fp.fingerprint(
            headers={"Server": "cloudflare", "CF-RAY": "abc123"},
        )
        assert result.waf == WAFType.CLOUDFLARE


# ---------------------------------------------------------------------------
# Reporter tests
# ---------------------------------------------------------------------------

class TestEngagementReporter:

    def test_markdown_contains_finding(self, sample_engagement):
        reporter = EngagementReporter(sample_engagement)
        md = reporter.to_markdown()
        assert "XSS" in md or "xss" in md
        assert "Test Engagement" in md

    def test_json_parseable(self, sample_engagement):
        import json
        reporter = EngagementReporter(sample_engagement)
        data = json.loads(reporter.to_json())
        assert "findings" in data
        assert len(data["findings"]) == 3

    def test_html_contains_title(self, sample_engagement):
        reporter = EngagementReporter(sample_engagement)
        html = reporter.to_html()
        assert "<html" in html
        assert "Test Engagement" in html

    def test_findings_by_severity(self, sample_engagement):
        by_sev = sample_engagement.findings_by_severity
        assert "medium" in by_sev
        assert "high" in by_sev

    def test_engagement_summary(self, sample_engagement):
        s = sample_engagement.summary()
        assert s["finding_count"] == 3
        assert s["name"] == "Test Engagement"
