# Configuration Files

## scope.yaml

The scope file controls which targets are allowed/forbidden.

### Schema

```yaml
allowed:
  - target.com              # Exact domain
  - "*.target.com"          # Wildcard subdomain
  - "192.168.1.0/24"       # CIDR range

excluded:
  - admin.target.com        # Exclude even if in allowed
  - internal.target.com
```

### Examples

#### Simple Domain

```yaml
allowed:
  - "acme.com"
```

Allows: `acme.com`, `www.acme.com`, `api.acme.com`  
Blocks: `other.com`, `acme.evil.com`

#### Multi-tenant with Exclusions

```yaml
allowed:
  - "*.acme.com"

excluded:
  - "internal.acme.com"
  - "admin.acme.com"
```

Allows: `web.acme.com`, `api.acme.com`  
Blocks: `internal.acme.com`, `admin.acme.com`

#### IP Ranges

```yaml
allowed:
  - "192.168.1.0/24"
  - "10.0.0.0/8"
```

#### Mixed

```yaml
allowed:
  - "target.com"
  - "*.api.target.com"
  - "192.168.1.100"

excluded:
  - "internal.target.com"
  - "192.168.1.1"
```

---

## findings.json

Findings file format for the `chain` and `report` commands.

### Schema

```json
{
  "findings": [
    {
      "vuln_type": "xss|sqli|ssti|csrf|auth_bypass|info_disclosure|rce",
      "url": "https://target.com/page",
      "parameter": "query_param_name",
      "severity": "critical|high|medium|low|info",
      "status": "confirmed|suspected|potential|remediated",
      "evidence": "Description or raw evidence",
      "payload": "The payload used",
      "notes": "Additional context",
      "cvss_score": 7.5,
      "tags": ["tag1", "tag2"]
    }
  ]
}
```

### Minimal Example

```json
{
  "findings": [
    {
      "vuln_type": "xss",
      "url": "https://app.target.com/search",
      "parameter": "q"
    }
  ]
}
```

### Complete Example

```json
{
  "findings": [
    {
      "vuln_type": "xss",
      "url": "https://app.target.com/search",
      "parameter": "q",
      "severity": "high",
      "status": "confirmed",
      "evidence": "Payload reflected in response without encoding: <img src=x onerror=alert(1)>",
      "payload": "<img src=x onerror=alert(1)>",
      "notes": "Can be exploited via social engineering",
      "cvss_score": 6.1,
      "tags": ["xss", "reflection", "user-input"]
    },
    {
      "vuln_type": "sqli",
      "url": "https://app.target.com/users",
      "parameter": "id",
      "severity": "critical",
      "status": "confirmed",
      "payload": "1' OR '1'='1",
      "evidence": "Error message reveals database structure"
    }
  ]
}
```

### Vulnerability Types

| Type | Description |
|------|-------------|
| xss | Cross-Site Scripting |
| sqli | SQL Injection |
| ssti | Server-Side Template Injection |
| csrf | Cross-Site Request Forgery |
| auth_bypass | Authentication Bypass |
| info_disclosure | Information Disclosure |
| rce | Remote Code Execution |
| path_traversal | Path Traversal |
| xxe | XML External Entity |
| bola | Broken Object Level Auth |

### Severity Levels

| Level | CVSS Range |
|-------|-----------|
| critical | 9.0-10.0 |
| high | 7.0-8.9 |
| medium | 4.0-6.9 |
| low | 0.1-3.9 |
| info | 0.0 |

---

## engagement.json

Full engagement definition for detailed reporting.

```json
{
  "name": "ACME Corp Security Assessment",
  "operator": "pentester_handle",
  "scope": ["app.acme.com", "api.acme.com"],
  "exclusions": ["internal.acme.com"],
  "notes": "Q3 2026 engagement",
  "findings": [...]
}
```
