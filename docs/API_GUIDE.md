# Python API Guide

WebXploit Chain can be used as a Python library for programmatic access to all features.

## Installation

```python
pip install webxploit-chain
```

For development:
```python
pip install -e ".[dev]"
```

## Basic Usage

### Payload Generation

```python
from webxploit.payloads.builder import PayloadBuilder, TechStack, WAFType
from webxploit.core.models import VulnType, FingerprintResult

# Create builder
builder = PayloadBuilder()

# Generate basic payloads
result = builder.build(VulnType.XSS, max_payloads=5)
for payload in result.payloads:
    print(payload)

# With target detection
fingerprint = FingerprintResult(
    stack=TechStack.PHP,
    waf=WAFType.CLOUDFLARE,
)

result = builder.build(
    VulnType.XSS,
    fingerprint=fingerprint,
    include_encodings=True,
    max_payloads=10
)

print(f"Stack-specific payloads: {result.payloads}")
print(f"URL-encoded variants: {result.encoded.get('url_encode', [])}")
```

### Scope Enforcement

```python
from webxploit.core.scope import ScopeEnforcer, ScopeViolation

# From YAML file
enforcer = ScopeEnforcer.from_yaml("scope.yaml")

# From list
enforcer = ScopeEnforcer.from_list(["target.com", "*.target.com"])

# Check URLs
try:
    enforcer.check("https://target.com/api")
    print("[+] In scope")
except ScopeViolation as e:
    print(f"[-] Out of scope: {e}")
```

### Vulnerability Chaining

```python
from webxploit.core.chain_engine import ChainEngine
from webxploit.core.models import Finding, VulnType, Severity

# Create findings
findings = [
    Finding(
        vuln_type=VulnType.XSS,
        url="https://target.com/search",
        parameter="q",
        severity=Severity.HIGH,
    ),
    Finding(
        vuln_type=VulnType.CSRF,
        url="https://target.com/settings",
        severity=Severity.MEDIUM,
    ),
    Finding(
        vuln_type=VulnType.INFO_DISCLOSURE,
        url="https://target.com/api/users",
        severity=Severity.LOW,
    ),
]

# Analyze chains
engine = ChainEngine(max_depth=4)
chains = engine.analyse(findings, min_confidence=0.6)

for result in chains:
    print(f"Chain: {result.chain.chain_label}")
    print(f"Score: {result.score}")
    print(f"Confidence: {result.confidence:.0%}")
    print(f"Reasoning: {result.reasoning}")
    print()
```

### HTTP Testing

```python
from webxploit.http_automation import HTTPTester

tester = HTTPTester(timeout=10.0)

# Fetch URL
response = tester.fetch("https://target.com/api", headers={"Authorization": "Bearer token"})
print(f"Status: {response.status_code}")
print(f"Body: {response.body[:200]}")

# Test payload
result = tester.test_payload(
    url="https://target.com/search?q=payload",
    payload="<script>alert(1)</script>",
    parameter="q",
    expected="<script>alert(1)</script>"
)

if result.success:
    print("[+] Payload likely successful")
    print(f"Indicators: {result.indicators}")
```

### Fingerprinting

```python
from webxploit.payloads.builder import Fingerprinter

fingerprinter = Fingerprinter()

result = fingerprinter.fingerprint(
    url="https://target.com",
    status_code="200",
    headers={"Server": "Apache/2.4.52 (Ubuntu)", "X-Powered-By": "PHP/8.1"},
    body="<meta name='generator' content='WordPress 6.1'>"
)

print(f"Stack: {result.stack.value}")
print(f"WAF: {result.waf.value}")
print(f"Confidence: {result.confidence:.0%}")
print(f"Indicators: {result.indicators}")
```

### Engagement Management

```python
from webxploit.core.models import Engagement, Finding, VulnType, Severity
from webxploit.reporting.reporter import EngagementReporter

# Create engagement
engagement = Engagement(
    name="ACME Corp Assessment",
    scope=["app.acme.com", "api.acme.com"],
    operator="pentester",
    notes="Q2 2026 assessment"
)

# Add findings
engagement.add_finding(Finding(
    vuln_type=VulnType.XSS,
    url="https://app.acme.com/search",
    parameter="q",
    severity=Severity.HIGH,
))

# Generate reports
reporter = EngagementReporter(engagement)
paths = reporter.save_all("reports/")

for fmt, path in paths.items():
    print(f"{fmt.upper()}: {path}")
```

## Advanced Topics

### Custom Fingerprint Detection

```python
from webxploit.payloads.builder import Fingerprinter

fingerprinter = Fingerprinter()

# Add custom indicators
result = fingerprinter.fingerprint(
    url="https://target.com",
    status_code="200",
    headers={
        "Server": "IIS/10.0",
        "X-AspNet-Version": "4.0.30319",
        "X-Powered-By": "ASP.NET"
    },
    body=""
)

# Detects ASP.NET / IIS stack
```

### Chain Analysis with Confidence Filtering

```python
chains = engine.analyse(
    findings,
    min_confidence=0.8  # Only high-confidence chains
)

# Results sorted by score
for result in sorted(chains, key=lambda x: x.score, reverse=True):
    print(f"{result.chain.chain_label}: {result.score:.2f}")
```

### Batch Payload Testing

```python
from concurrent.futures import ThreadPoolExecutor

payloads = builder.build(VulnType.XSS).payloads
url = "https://target.com/search?q={}"

def test_payload(payload):
    try:
        result = tester.test_payload(
            url=url.format(payload),
            payload=payload,
            parameter="q"
        )
        return (payload, result.success)
    except Exception:
        return (payload, False)

# Test in parallel
with ThreadPoolExecutor(max_workers=5) as executor:
    results = executor.map(test_payload, payloads)
    
for payload, success in results:
    status = "[+]" if success else "[-]"
    print(f"{status} {payload}")
```

## Error Handling

```python
from webxploit.core.scope import ScopeViolation
from webxploit.http_automation import HTTPError

try:
    enforcer.check("https://out-of-scope.com")
except ScopeViolation as e:
    print(f"Scope violation: {e}")
    exit(1)

try:
    response = tester.fetch("https://target.com")
except HTTPError as e:
    print(f"HTTP error: {e.status_code} {e.reason}")
except TimeoutError:
    print("Request timed out")
```

---

See [CLI_REFERENCE.md](CLI_REFERENCE.md) for command-line usage.
