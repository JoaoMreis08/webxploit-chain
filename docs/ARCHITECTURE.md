# Architecture & Design

WebXploit Chain is designed around a modular, reusable architecture for web exploitation.

## Core Components

### 1. **Models** (`webxploit/core/models.py`)

Defines all data structures:
- `Finding` - A single vulnerability finding
- `Engagement` - A complete engagement with scope and findings
- `ChainResult` - A vulnerability chain analysis result
- `VulnType` - Enumeration of vulnerability types
- `Severity` - Finding severity levels
- `ExploitStatus` - Exploitation status (confirmed, suspected, etc.)

### 2. **Chain Engine** (`webxploit/core/chain_engine.py`)

Analyzes vulnerability relationships and proposes chains.

```
Findings → Graph Construction → Dependency Analysis → Chain Scoring → Results
```

**Algorithm:**
- Builds directed graph of exploit dependencies
- Identifies paths that increase attack surface
- Scores chains by impact and feasibility
- Filters by confidence threshold

**Example Chain:**
```
XSS (reflected) 
  → Steal session cookie
  → CSRF (authenticated)
  → Admin account takeover
```

### 3. **Payload Builder** (`webxploit/payloads/builder.py`)

Generates context-aware payloads.

```
Vuln Type + Stack + WAF → Payload Database → Filtering → Encoding → Output
```

**Features:**
- Tech stack detection (PHP, Java, .NET, Node.js)
- WAF detection (Cloudflare, ModSecurity, Akamai)
- Encoding variants (URL, Base64, HTML, Unicode)
- Payload mutation strategies

### 4. **Fingerprinter** (`webxploit/payloads/builder.py`)

Detects target technology.

```
HTTP Response → Header Analysis → Body Analysis → Confidence Scoring → Detection
```

**Detection Methods:**
- Server header parsing
- Framework signatures in HTML/JS
- Timing analysis
- Error message patterns
- Cookie name analysis

### 5. **HTTP Automation** (`webxploit/http_automation.py`)

Safe HTTP request execution with scope enforcement.

```
Request → Scope Check → HTTP Send → Response Analysis → Result
```

**Features:**
- Timeout handling
- Automatic redirect following
- Response analysis (success indicators)
- Payload reflection detection

### 6. **Scope Enforcer** (`webxploit/core/scope.py`)

Validates requests against YAML scope configuration.

```
URL → Pattern Matching → Allowed/Excluded Check → Scope Violation or OK
```

**Supported Patterns:**
- Exact domains: `target.com`
- Wildcards: `*.target.com`
- CIDR ranges: `192.168.1.0/24`

### 7. **Reporter** (`webxploit/reporting/reporter.py`)

Generates multi-format engagement reports.

```
Engagement Data → HTML Template → HTML Report
              ├→ Markdown Template → Markdown Report
              └→ JSON Serialization → JSON Report
```

**Output Formats:**
- **HTML** - Styled, visual report for stakeholders
- **Markdown** - Version control friendly
- **JSON** - Programmatic consumption

## Data Flow

### Typical Engagement

```
User Input (CLI)
    ↓
Scope Validation
    ↓
Fingerprinting
    ├→ HTTP Request
    ├→ Response Analysis
    └→ Tech Detection
    ↓
Payload Generation
    ├→ Vuln Type Selection
    ├→ Stack-Specific Variants
    └→ Encoding Options
    ↓
Manual/Automated Testing
    ├→ Scope Enforcement
    ├→ HTTP Request
    └→ Result Analysis
    ↓
Finding Collection
    ↓
Chain Analysis
    ├→ Dependency Graph
    ├→ Path Finding
    └→ Scoring
    ↓
Report Generation
    ├→ HTML Report
    ├→ Markdown Report
    └→ JSON Report
```

## Module Organization

```
webxploit/
├── core/
│   ├── __init__.py
│   ├── models.py          # Data structures
│   ├── chain_engine.py    # Chain analysis
│   ├── scope.py           # Scope enforcement
│   └── models.py          # Models
├── payloads/
│   ├── __init__.py
│   └── builder.py         # Payloads + fingerprinting
├── reporting/
│   ├── __init__.py
│   └── reporter.py        # Report generation
└── __init__.py
```

## Extension Points

### Custom Payload Sources

Extend `PayloadBuilder` to add custom payload databases:

```python
class CustomPayloadBuilder(PayloadBuilder):
    def _get_payloads(self, vuln_type):
        if vuln_type == VulnType.XSS:
            return MyCustomXSSPayloads.get_all()
        return super()._get_payloads(vuln_type)
```

### Custom Chain Analyzers

Extend `ChainEngine` for domain-specific logic:

```python
class CustomChainEngine(ChainEngine):
    def _score_chain(self, chain):
        score = super()._score_chain(chain)
        # Custom scoring logic
        return score
```

### Custom Reporters

Create domain-specific report templates:

```python
class PDFReporter(EngagementReporter):
    def save_pdf(self, path):
        # Generate PDF from engagement data
        pass
```

## Performance Considerations

- **Fingerprinting**: ~1 request per target
- **Payload Generation**: O(1) - database lookup + filtering
- **Chain Analysis**: O(n²) where n = number of findings
- **Parallel Testing**: Supports concurrent payload testing (configurable workers)

## Security Model

- **Scope Validation**: All HTTP requests are scope-checked before sending
- **Payload Sandboxing**: Payloads are not executed locally
- **Credential Handling**: API keys/tokens passed as-is (user responsibility)
- **Report Sanitization**: User input sanitized in reports

## Future Roadmap

- **Persistent Storage**: Database backend for findings
- **Collaboration Server**: Real-time sync across operators
- **Graph Visualization**: D3.js/networkx visualization of chains
- **Machine Learning**: Automated finding classification
- **Plugin System**: Community-contributed payloads/analyzers
- **Automation Framework**: Orchestration of multi-step engagements

---

See [API_GUIDE.md](API_GUIDE.md) for usage examples.
