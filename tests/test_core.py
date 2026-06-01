"""Basic smoke tests for WebXploit Chain."""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


def test_imports():
    """Test that core modules can be imported."""
    from webxploit.core.models import Finding, VulnType, Severity
    from webxploit.core.chain_engine import ChainEngine
    from webxploit.payloads.builder import PayloadBuilder

    assert Finding is not None
    assert VulnType is not None
    assert ChainEngine is not None
    assert PayloadBuilder is not None


def test_vuln_type_enum():
    """Test VulnType enumeration."""
    from webxploit.core.models import VulnType

    assert VulnType.XSS.value == "xss"
    assert VulnType.SQLI.value == "sqli"
    assert VulnType.SSTI.value == "ssti"


def test_severity_enum():
    """Test Severity enumeration."""
    from webxploit.core.models import Severity

    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"


def test_finding_creation():
    """Test that a Finding can be created."""
    from webxploit.core.models import Finding, VulnType, Severity, ExploitStatus

    finding = Finding(
        vuln_type=VulnType.XSS,
        url="https://example.com/search",
        parameter="q",
        severity=Severity.HIGH,
        status=ExploitStatus.CONFIRMED,
        evidence="Test evidence",
        payload="<script>alert(1)</script>",
    )

    assert finding.vuln_type == VulnType.XSS
    assert finding.url == "https://example.com/search"
    assert finding.severity == Severity.HIGH


if __name__ == "__main__":
    test_imports()
    test_vuln_type_enum()
    test_severity_enum()
    test_finding_creation()
    print("All tests passed!")
