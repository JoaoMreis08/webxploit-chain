# Troubleshooting

Common issues and solutions.

## Installation Issues

### `ModuleNotFoundError: No module named 'webxploit'`

**Cause**: Package not installed in editable mode.

**Solution**:
```bash
cd webxploit-chain
pip install -e .
```

### `No module named 'yaml'`

**Cause**: Missing PyYAML dependency.

**Solution**:
```bash
pip install pyyaml
```

## Runtime Issues

### `ScopeViolation: URL not in scope`

**Cause**: Target URL doesn't match `scope.yaml` configuration.

**Solution**:
1. Check your `scope.yaml` file:
   ```bash
   cat scope.yaml
   ```

2. Verify the URL matches allowed patterns:
   ```bash
   webxploit scope scope.yaml https://your.target.com
   ```

3. Update `scope.yaml` if needed:
   ```yaml
   allowed:
     - your.target.com
     - api.your.target.com
   ```

### `requests.ConnectTimeout`

**Cause**: Target is not responding or network issue.

**Solution**:
```bash
# Increase timeout
webxploit fingerprint https://target.com --timeout 30

# Check network connectivity
ping target.com
curl -I https://target.com
```

### `JSONDecodeError` when loading findings

**Cause**: `findings.json` has invalid JSON syntax.

**Solution**:
```bash
# Validate JSON syntax
python -m json.tool findings.json

# Fix manually or regenerate
```

## Fingerprinting Issues

### Low confidence in detection

**Cause**: Target doesn't expose technology signatures.

**Solution**:
- Add custom headers:
  ```bash
  webxploit fingerprint https://target.com \
    --header "User-Agent: Mozilla/5.0"
  ```

- Check HTTP methods:
  ```bash
  curl -X OPTIONS -I https://target.com
  webxploit fingerprint https://target.com --method POST
  ```

### False positives in WAF detection

**Cause**: Heuristic detection may have false positives.

**Solution**:
- Manually verify WAF presence
- Override in payload generation:
  ```bash
  webxploit generate --vuln xss --waf none
  ```

## Payload Generation Issues

### No payloads generated

**Cause**: Vulnerability type not supported.

**Solution**:
```bash
# List supported vuln types
webxploit generate --help | grep vuln

# Use standard types: xss, sqli, ssti, csrf, auth_bypass, etc.
```

### Payloads not working

**Cause**: Stack mismatch or WAF blocking.

**Solution**:
1. Verify target stack:
   ```bash
   webxploit fingerprint https://target.com --json
   ```

2. Generate with correct stack:
   ```bash
   webxploit generate --vuln xss --stack php
   ```

3. Try WAF bypass variants:
   ```bash
   webxploit generate --vuln xss --waf cloudflare --show-encodings
   ```

## Chain Analysis Issues

### No chains identified

**Cause**: Findings too isolated or low confidence.

**Solution**:
```bash
# Lower confidence threshold
webxploit chain findings.json --min-confidence 0.3

# Increase chain depth
webxploit chain findings.json --max-depth 5

# Verify findings quality
cat findings.json | python -m json.tool
```

### Chain reasoning unclear

**Cause**: Limited dependency rules.

**Solution**:
- Review chain output for reasoning
- Add more related findings to enable detection
- Check [ARCHITECTURE.md](ARCHITECTURE.md) for chain logic

## Report Generation Issues

### Reports not created

**Cause**: Output directory doesn't exist or permission issue.

**Solution**:
```bash
# Create directory
mkdir -p reports/

# Check permissions
ls -la reports/

# Run with explicit path
webxploit report findings.json $(pwd)/reports/
```

### Report is empty

**Cause**: No findings in engagement.

**Solution**:
```bash
# Verify findings.json structure
cat findings.json

# Ensure findings array is not empty:
# "findings": [ { ... }, { ... } ]
```

## Performance Issues

### Chain analysis is slow

**Cause**: Large number of findings.

**Solution**:
```bash
# Reduce findings
webxploit chain findings.json --max-depth 2

# Filter by severity
# (Manually edit findings.json to keep only high/critical)
```

### Timeout during requests

**Cause**: Slow target or network issues.

**Solution**:
```bash
# Increase timeout
webxploit test \
  --url https://target.com \
  --payload "<payload>" \
  --timeout 30
```

## Debug Mode

Enable debug logging to troubleshoot:

```bash
webxploit --debug fingerprint https://target.com 2>&1 | head -50
webxploit --debug chain findings.json 2>&1 | head -50
```

## Getting Help

- Check [CLI_REFERENCE.md](CLI_REFERENCE.md) for command options
- See [CONFIGURATION.md](CONFIGURATION.md) for file formats
- Review [API_GUIDE.md](API_GUIDE.md) for Python API usage
- Open an [issue](https://github.com/webxploit-chain/webxploit-chain/issues) with:
  - Python version: `python --version`
  - WebXploit version (from pyproject.toml)
  - Full error message with `--debug` flag
  - Sanitized configuration files (scope.yaml, findings.json)

---

**Still stuck?** Email: opensource@webxploit-chain.local
