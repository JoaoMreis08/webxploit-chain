# Getting Started with WebXploit Chain

This guide walks you through the basic workflow of WebXploit Chain.

## Installation

```bash
pip install -e .
```

For development:
```bash
pip install -e ".[dev]"
```

## Your First Engagement

### 1. Create a Scope File

Create `scope.yaml`:

```yaml
allowed:
  - "target.example.com"
  - "api.target.example.com"

excluded:
  - "admin.target.example.com"
  - "internal.target.example.com"
```

### 2. Fingerprint a Target

```bash
webxploit fingerprint https://target.example.com --scope scope.yaml
```

Output:
```
[+] https://target.example.com
    Status: 200 (0.45s)
    Stack: php
    WAF: cloudflare
    Confidence: 82%
    - PHP Version 8.1
    - Cloudflare protection detected
    - jQuery 3.6.0
```

### 3. Generate Payloads

```bash
webxploit generate --vuln xss --waf cloudflare
```

### 4. Test a Payload

```bash
webxploit test \
  --url "https://target.example.com/search?q=<payload>" \
  --payload "<img src=x onerror=alert(1)>" \
  --param q \
  --scope scope.yaml
```

### 5. Analyze Chains

Create a `findings.json`:

```json
{
  "findings": [
    {
      "vuln_type": "xss",
      "url": "https://target.example.com/search",
      "parameter": "q",
      "severity": "medium",
      "status": "confirmed",
      "evidence": "Reflected without encoding"
    },
    {
      "vuln_type": "csrf",
      "url": "https://target.example.com/admin/settings",
      "severity": "high",
      "status": "suspected"
    }
  ]
}
```

```bash
webxploit chain findings.json
```

### 6. Generate Reports

```bash
webxploit report findings.json reports/
```

## CLI Commands Reference

| Command | Purpose |
|---------|---------|
| `fingerprint` | Detect target stack and WAF |
| `generate` | Generate payloads for a vuln type |
| `test` | Test a single payload |
| `chain` | Identify vulnerability chains |
| `report` | Generate HTML/MD/JSON reports |
| `scope` | Validate URL against scope |

## Next Steps

- See [CONTRIBUTING.md](../CONTRIBUTING.md) to contribute
- Check out [examples/](../examples/) for real workflows
- Read [SECURITY.md](../SECURITY.md) for security practices
