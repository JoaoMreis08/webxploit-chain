# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in WebXploit Chain, **please do not open a public issue**. Instead:

1. **Email** the vulnerability details to: `08.joao.r.04@gmail.com`
2. **Include**:
   - Description of the vulnerability
   - Affected versions
   - Steps to reproduce (if possible)
   - Potential impact
   - Suggested fix (if you have one)

3. **Wait** for our response before public disclosure (typically within 48 hours)

We will:
- Acknowledge receipt of your report
- Assess the severity and impact
- Work on a fix
- Coordinate a responsible disclosure timeline
- Credit you in the advisory (unless you prefer anonymity)

## Vulnerability Disclosure Timeline

- **Day 0**: Vulnerability reported
- **Day 1**: Initial assessment and acknowledgment
- **Day 7-30**: Fix development and testing (depending on severity)
- **Day 30+**: Coordinated public disclosure

## Security Best Practices for Users

### Scope Enforcement

Always configure `scope.yaml` carefully:
```yaml
allowed:
  - "target.com"
  - "api.target.com"
excluded:
  - "*.admin-panel.target.com"
```

### API Key Handling

- Never commit API keys or credentials
- Use environment variables: `export WX_API_KEY=...`
- Rotate keys regularly

### Output Reports

- Reports may contain sensitive findings — store securely
- Don't commit reports to public repositories
- Use `.gitignore` for `reports/` directory

### Known Limitations

- **No authentication** - WebXploit Chain sends requests as-is; add auth headers manually
- **No encryption** - HTTP traffic is unencrypted; use HTTPS-only targets
- **Payload safety** - Test payloads in controlled environments first
- **WAF detection** - WAF detection is heuristic-based and may have false positives/negatives

## Dependency Security

We maintain up-to-date dependencies. Check for security advisories:

```bash
pip install pip-audit
pip-audit
```

Report dependency vulnerabilities via standard GitHub security advisory process.

## Version Support

| Version | Status | Security Updates Until |
|---------|--------|------------------------|
| 0.1.x   | Alpha  | Ongoing (TBD)          |
| 0.2.x   | TBD    | TBD                    |

---

Thank you for helping keep WebXploit Chain secure.
