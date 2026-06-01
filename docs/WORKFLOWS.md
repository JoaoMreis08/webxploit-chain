# WebXploit Chain Workflows

Common workflows for using WebXploit Chain.

## Workflow 1: Complete Red Team Engagement

This is the standard workflow for a security engagement.

```bash
# Step 1: Create scope file
cat > scope.yaml << EOF
allowed:
  - "target.com"
  - "*.target.com"
excluded:
  - "internal.target.com"
EOF

# Step 2: Fingerprint all target domains
webxploit fingerprint https://target.com --scope scope.yaml --json > fingerprints.json
webxploit fingerprint https://api.target.com --scope scope.yaml --json >> fingerprints.json

# Step 3: Generate payloads for detected stacks
webxploit generate --vuln xss --stack php --waf cloudflare > xss_payloads.txt
webxploit generate --vuln sqli --stack php > sqli_payloads.txt

# Step 4: Test payloads manually or with scripts
for payload in $(cat xss_payloads.txt); do
  webxploit test \
    --url "https://target.com/search?q=$payload" \
    --payload "$payload" \
    --param q \
    --scope scope.yaml
done

# Step 5: Compile findings into JSON
cat > findings.json << 'EOF'
{
  "findings": [
    {
      "vuln_type": "xss",
      "url": "https://target.com/search",
      "parameter": "q",
      "severity": "high",
      "status": "confirmed"
    }
  ]
}
EOF

# Step 6: Analyze vulnerability chains
webxploit chain findings.json --min-confidence 0.7

# Step 7: Generate comprehensive report
webxploit report findings.json reports/ --include-chains
```

## Workflow 2: API-Based Testing

Using WebXploit Chain as a Python library.

```python
from webxploit.core.models import Finding, VulnType, Severity, Engagement
from webxploit.core.chain_engine import ChainEngine
from webxploit.payloads.builder import PayloadBuilder
from webxploit.core.scope import ScopeEnforcer

# Set up scope enforcement
scope = ScopeEnforcer.from_list(["api.target.com"])

# Generate payloads programmatically
builder = PayloadBuilder()
xss_payloads = builder.build(
    VulnType.XSS,
    include_encodings=True,
    max_payloads=5
)

print(f"Generated {len(xss_payloads.payloads)} XSS payloads")

# Analyze findings
findings = [
    Finding(
        vuln_type=VulnType.XSS,
        url="https://api.target.com/search",
        parameter="q",
        severity=Severity.HIGH,
        payload=xss_payloads.payloads[0]
    ),
    Finding(
        vuln_type=VulnType.CSRF,
        url="https://api.target.com/settings",
        severity=Severity.MEDIUM,
    )
]

# Chain analysis
engine = ChainEngine(max_depth=4)
chains = engine.analyse(findings)

for chain_result in chains:
    print(f"Chain: {chain_result.chain.chain_label}")
    print(f"Severity: {chain_result.chain.severity.value}")
    print(f"Confidence: {chain_result.confidence:.0%}")
```

## Workflow 3: Automated Scope Validation

Check multiple URLs against scope.

```bash
#!/bin/bash

SCOPE="scope.yaml"
URLS=(
  "https://app.target.com/login"
  "https://api.target.com/users"
  "https://admin.target.com/panel"
  "https://evil.com/phish"
)

for url in "${URLS[@]}"; do
  webxploit scope "$SCOPE" "$url" || echo "BLOCKED: $url"
done
```

## Workflow 4: Continuous Integration

Run WebXploit in your CI/CD pipeline.

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install WebXploit
        run: pip install -e .
      
      - name: Validate scope
        run: |
          for url in $(cat target_urls.txt); do
            webxploit scope scope.yaml "$url" || exit 1
          done
      
      - name: Generate payloads
        run: webxploit generate --vuln xss --json > payloads.json
      
      - name: Archive results
        uses: actions/upload-artifact@v3
        with:
          name: payloads
          path: payloads.json
```

---

See [CLI_REFERENCE.md](CLI_REFERENCE.md) for detailed command options.
