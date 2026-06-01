# Changelog

All notable changes to WebXploit Chain are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

## [0.1.0] - 2026-06-01

### Added

- **Chain Engine** - Analyzes findings and identifies multi-step attack paths
- **Payload Builder** - Generates context-aware payloads based on target stack and WAF
- **Fingerprinting** - Detects technology stack and WAF presence
- **Scope Enforcer** - YAML-based scope validation to prevent out-of-scope requests
- **Engagement Reporter** - Generates HTML, Markdown, and JSON reports
- **HTTP Automation** - Payload testing with response analysis
- **CLI Interface** - Commands for fingerprint, generate, test, chain, report, scope
- **Python API** - Programmatic access to all core functionality

### Current Status

- **Alpha Release** - Core features functional but API and CLI may change
- Suitable for testing and development
- Not recommended for production without careful review

---

## Planned Features

- **Attack Replay** - Record and replay exploitation sessions
- **Engagement Diffing** - Compare findings between engagements
- **Team Collaboration** - FastAPI WebSocket server for real-time sync
- **Advanced Path Analysis** - networkx-based graph visualization
- **Plugin System** - Custom payload builders and chain analyzers
- **CI/CD Integration** - GitHub/GitLab Actions templates
