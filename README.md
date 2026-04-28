# WebXploit Chain

> **Web exploitation framework for red team engagements** — vulnerability chaining, context-aware payloads, scope enforcement, and engagement-oriented reporting.

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange.svg)]()

---

## What is WebXploit Chain?

Most web security tools treat vulnerabilities in isolation — a scanner finds XSS, another tool finds SQLi, and you manually figure out how to chain them. WebXploit Chain is built around the reality of red team engagements: vulnerabilities don't exist in isolation, and the real impact comes from chaining them together.

| Feature | Description |
|---|---|
| **Vuln Chaining Engine** | Builds a directed graph of exploit dependencies and automatically proposes multi-step attack paths (XSS → CSRF → RCE, SQLi → Auth Bypass → Priv Esc, etc.) |
| **Payload Context Builder** | Detects target stack (PHP, Java, .NET, Node.js…) and WAF presence, then selects and mutates payloads to maximise success |
| **Scope Enforcer** | YAML-configured scope enforcement — blocks any out-of-scope request before it's sent, with a full violation log |
| **Engagement Reporter** | Generates structured Markdown, HTML, and JSON reports scoped to the engagement, not just raw scan output |
| **Attack Replay & Diff** | *(roadmap)* Record and replay attack sessions; diff findings between engagements to prove remediation |
| **Team Collab Layer** | *(roadmap)* FastAPI WebSocket server for real-time finding sync across operators |

---

## Why not just use Burp Suite / Metasploit?

- **Burp** is great for manual testing but has no concept of an "engagement" — no chaining, no structured reporting, and it's GUI-only and expensive.
- **Metasploit** is powerful for network exploitation but web-app focused chains (XSS→CSRF→Admin takeover) are not its strength.
- **WebXploit Chain** is CLI-first, Python, free, open-source, and built specifically for the workflow of a professional web red team engagement.

---

## Installation

```bash
git clone https://github.com/youruser/webxploit-chain.git
cd webxploit-chain
pip install -e .

# Optional extras
pip install -e ".[collab]"   # for the team collaboration server
pip install -e ".[graph]"    # for networkx-based path analysis
```

**Requirements:** Python 3.10+

---

## Quick Start

### 1. Run the chain engine on your findings

```bash
# Write your findings to a JSON file (see configs/example_findings.json)
webxploit chain configs/example_findings.json
```

Output:
```
 ____      ____     _____           _       _ _    ____ _           _
...

[*] Loaded 5 findings. Running chain engine...

[+] 7 chain(s) identified:

  1. XSS → CSRF chain
     Score: 0.87  |  Confidence: 90%  |  Severity: high
     Starting with XSS as initial access. → Weaponise XSS to forge authenticated requests...

  2. INFO_DISCLOSURE → AUTH_BYPASS chain
     Score: 0.82  |  Confidence: 85%  |  Severity: critical
     ...
```

### 2. Check scope

```bash
# Edit configs/scope.yaml with your engagement targets
webxploit scope configs/scope.yaml https://app.target.org/login
# [+] IN SCOPE: https://app.target.org/login

webxploit scope configs/scope.yaml https://evil.com/steal
# [-] OUT OF SCOPE: 'https://evil.com/steal' — not in allowed scope
```

### 3. Generate payloads

```bash
webxploit payload xss
webxploit payload sqli modsecurity     # with WAF bypass variants
webxploit payload ssti                 # template injection
```

### 4. Generate a full engagement report

```bash
webxploit report configs/example_findings.json reports/
# [+] Reports saved:
#     MD   → reports/my_engagement_a1b2c3.md
#     HTML → reports/my_engagement_a1b2c3.html
#     JSON → reports/my_engagement_a1b2c3.json
```

---

## Python API

```python
from webxploit.core.models import Engagement, Finding, Severity, VulnType
from webxploit.core.chain_engine import ChainEngine
from webxploit.core.scope import ScopeEnforcer
from webxploit.payloads.builder import PayloadBuilder
from webxploit.reporting.reporter import EngagementReporter

# --- Set up engagement ---
engagement = Engagement(
    name="ACME Corp Web Assessment",
    scope=["app.acme.com", "api.acme.com"],
    operator="your_handle",
)

# --- Enforce scope ---
enforcer = ScopeEnforcer.from_list(["app.acme.com", "api.acme.com"])
enforcer.check("https://app.acme.com/login")       # OK
enforcer.check("https://out-of-scope.com/")        # raises ScopeViolation

# --- Add findings ---
xss = Finding(
    vuln_type=VulnType.XSS,
    url="https://app.acme.com/search",
    parameter="q",
    severity=Severity.MEDIUM,
    payload="<img src=x onerror=alert(1)>",
    evidence="Reflected in response without encoding.",
)
engagement.add_finding(xss)

# --- Run chain engine ---
engine = ChainEngine()
results = engine.analyse(engagement.findings)

for r in results:
    print(r.chain.chain_label, "—", r.chain.severity.value)
    engagement.add_chain(r.chain)

# --- Suggest next steps interactively ---
suggestions = engine.suggest_next([VulnType.XSS])
for s in suggestions:
    print(f"  → {s.target.value}: {s.description}")

# --- Build context-aware payload ---
builder = PayloadBuilder()
payload_result = builder.build(VulnType.XSS)
print(payload_result.best())                       # top payload
print(payload_result.encoded["url"])               # URL-encoded variants

# --- Generate reports ---
reporter = EngagementReporter(engagement)
paths = reporter.save_all("reports/")
```

---

## Supported Chain Paths

The engine knows the following exploitation paths out of the box. Add your own via `ChainGraph.add_custom_edge()`.

| From | To | Notes |
|---|---|---|
| XSS | CSRF | Session riding via injected fetch() |
| XSS | Auth Bypass | Session/token theft |
| XSS | RCE | Electron / SSR eval chains |
| SQLi | Auth Bypass | Login bypass via OR injection |
| SQLi | RCE | INTO OUTFILE / xp_cmdshell |
| SQLi | Info Disclosure | Credential/PII dump |
| SSRF | IDOR | Internal API access |
| SSRF | RCE | Gopher → Redis pivot |
| SSRF | Info Disclosure | Cloud metadata (AWS/GCP/Azure) |
| IDOR | Info Disclosure | PII enumeration |
| IDOR | Auth Bypass | Account takeover via reset endpoint |
| LFI | RCE | Log poisoning, PHP session files |
| LFI | Info Disclosure | /etc/passwd, .env, config files |
| SSTI | RCE | Jinja2, Freemarker, Twig |
| XXE | SSRF | OOB-XXE to internal services |
| XXE | Info Disclosure | file:// entity reading |
| Deserialisation | RCE | ysoserial gadget chains |
| Auth Bypass | Priv Esc | Horizontal → vertical escalation |
| Auth Bypass | RCE | Admin file upload / panel RCE |
| Open Redirect | Auth Bypass | OAuth token theft |
| Info Disclosure | Auth Bypass | Leaked credential reuse |

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
pytest tests/ -v --cov=webxploit --cov-report=term-missing
```

---

## Project Structure

```
webxploit-chain/
├── webxploit/
│   ├── core/
│   │   ├── models.py          # Finding, VulnChain, Engagement dataclasses
│   │   ├── chain_engine.py    # Vuln chaining engine (the heart of the project)
│   │   └── scope.py           # Scope enforcer
│   ├── payloads/
│   │   └── builder.py         # Context-aware payload generation
│   ├── reporting/
│   │   └── reporter.py        # MD / HTML / JSON report generation
│   ├── collab/                # (roadmap) Team collaboration server
│   └── cli.py                 # CLI entry point
├── tests/
│   └── test_core.py
├── configs/
│   ├── scope.yaml             # Example scope config
│   └── example_findings.json  # Example findings for testing
├── docs/
├── pyproject.toml
└── README.md
```

---

## Roadmap

- [ ] **Attack Replay** — record requests, replay exact attack sessions, diff between engagements
- [ ] **Team Collab Server** — FastAPI + WebSocket sync for multi-operator engagements
- [ ] **Live HTTP scanner module** — integrate with `httpx` for active scanning within scope
- [ ] **Nuclei template export** — auto-generate Nuclei templates from confirmed findings
- [ ] **CVSS v3.1 scoring** — automatic CVSS scoring based on finding context
- [ ] **Burp Suite import** — parse Burp XML exports as findings input
- [ ] **CI/CD mode** — exit codes and JSON output suitable for pipeline integration

---

## Legal Notice

WebXploit Chain is intended exclusively for authorised penetration testing and red team engagements. Only use this tool against systems you have explicit written permission to test. The authors accept no liability for misuse.

---

## License

MIT — see [LICENSE](LICENSE).
