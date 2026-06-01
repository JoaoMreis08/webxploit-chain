# CLI Reference

## Commands

### fingerprint

Detect target stack and WAF presence.

```bash
webxploit fingerprint <URL> [OPTIONS]
```

**Options:**
- `--method` - HTTP method (GET, POST). Default: GET
- `--body` - Request body for POST
- `--header` - Add header (can use multiple times): `--header "X-Custom: value"`
- `--scope` - Scope file for validation
- `--timeout` - Request timeout in seconds. Default: 10
- `--json` - Output as JSON

**Example:**
```bash
webxploit fingerprint https://app.target.com \
  --header "Authorization: Bearer token" \
  --scope scope.yaml \
  --json
```

---

### generate

Generate payloads for a vulnerability type.

```bash
webxploit generate --vuln <TYPE> [OPTIONS]
```

**Options:**
- `--vuln` - Vulnerability type (xss, sqli, ssti, csrf, auth_bypass, etc.)
- `--waf` - WAF type (cloudflare, modsecurity, akamai, etc.)
- `--stack` - Tech stack (php, java, dotnet, nodejs, etc.)
- `--max-payloads` - Max payloads to generate. Default: 10
- `--no-encodings` - Skip encoding variants
- `--show-encodings` - Display URL-encoded and base64 variants
- `--json` - Output as JSON

**Examples:**
```bash
# Basic XSS payloads
webxploit generate --vuln xss

# XSS with WAF bypass (Cloudflare-specific)
webxploit generate --vuln xss --waf cloudflare

# SQLi for PHP with ModSecurity bypass
webxploit generate --vuln sqli --stack php --waf modsecurity

# Show all encoding variants
webxploit generate --vuln xss --show-encodings
```

---

### test

Test a single payload against a target.

```bash
webxploit test --url <URL> --payload <PAYLOAD> [OPTIONS]
```

**Options:**
- `--url` - Target URL (required)
- `--payload` - Payload to test (required)
- `--param` - Parameter name containing payload
- `--method` - HTTP method (GET, POST). Default: GET
- `--expect` - Expected response indicator (e.g., "window.alert" for XSS)
- `--header` - Add header (multiple allowed)
- `--scope` - Scope file for validation
- `--timeout` - Request timeout. Default: 10
- `--json` - Output as JSON

**Example:**
```bash
webxploit test \
  --url "https://app.target.com/search?q=payload" \
  --payload "<img src=x onerror=alert(1)>" \
  --param q \
  --expect "onerror" \
  --scope scope.yaml
```

---

### chain

Analyze findings and identify vulnerability chains.

```bash
webxploit chain <FINDINGS_FILE> [OPTIONS]
```

**Options:**
- `--min-confidence` - Minimum confidence threshold (0.0-1.0). Default: 0.5
- `--max-depth` - Maximum chain depth. Default: 4
- `--json` - Output as JSON

**Example:**
```bash
webxploit chain findings.json --min-confidence 0.7 --max-depth 3
```

---

### report

Generate engagement reports in multiple formats.

```bash
webxploit report <ENGAGEMENT_FILE> [OUTPUT_DIR] [OPTIONS]
```

**Options:**
- `--include-chains` - Analyze and include vulnerability chains
- `OUTPUT_DIR` - Directory to save reports. Default: reports/

**Example:**
```bash
webxploit report engagement.json reports/ --include-chains
```

Reports are generated in:
- `{hash}.html` - Styled HTML report
- `{hash}.md` - Markdown report
- `{hash}.json` - Raw JSON data

---

### scope

Validate a URL against scope configuration.

```bash
webxploit scope <SCOPE_FILE> <URL>
```

**Example:**
```bash
webxploit scope scope.yaml https://app.target.com/login
# [+] IN SCOPE: https://app.target.com/login

webxploit scope scope.yaml https://evil.com
# [-] OUT OF SCOPE: 'https://evil.com' — not in allowed scope
```

---

## Global Options

- `--debug` - Enable debug logging (for all commands)

**Example:**
```bash
webxploit --debug chain findings.json
```

---

## Exit Codes

- `0` - Success
- `1` - General error
- `2` - Scope violation
