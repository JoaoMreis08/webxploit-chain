# Contributing to WebXploit Chain

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing to WebXploit Chain.

## Code of Conduct

Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## Ways to Contribute

- **Report bugs** — open a [bug report](https://github.com/webxploit-chain/webxploit-chain/issues/new?template=bug_report.md)
- **Suggest features** — open a [feature request](https://github.com/webxploit-chain/webxploit-chain/issues/new?template=feature_request.md)
- **Submit pull requests** — fix bugs, add features, improve documentation
- **Improve documentation** — clarify docs, add examples, fix typos

## Development Setup

### Prerequisites

- Python 3.10+
- Git

### Local Setup

```bash
# Clone the repository
git clone https://github.com/webxploit-chain/webxploit-chain.git
cd webxploit-chain

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run type checking
mypy webxploit/

# Run linting
ruff check .
```

## Coding Standards

- **Language**: Python 3.10+
- **Style**: Follow [PEP 8](https://pep8.org/) — use `ruff` for linting
- **Type hints**: All functions must have type annotations
- **Docstrings**: Add docstrings to modules, classes, and public functions
- **Testing**: Write tests for new code (pytest)

### Example Function

```python
def analyse_findings(
    findings: list[Finding],
    min_confidence: float = 0.5,
) -> list[ChainResult]:
    """
    Analyse findings and identify vulnerability chains.

    Args:
        findings: List of findings to analyse
        min_confidence: Minimum confidence threshold (0.0-1.0)

    Returns:
        List of identified chains ranked by score

    Raises:
        ValueError: If min_confidence is outside valid range
    """
    if not 0.0 <= min_confidence <= 1.0:
        raise ValueError(f"min_confidence must be 0.0-1.0, got {min_confidence}")
    # ... implementation
```

## Pull Request Process

1. **Fork the repository** and create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**:
   - Keep commits atomic and descriptive
   - Update tests and documentation
   - Run checks locally before pushing

3. **Run checks**:
   ```bash
   pytest tests/ -v
   mypy webxploit/
   ruff check .
   ruff format .
   ```

4. **Push to your fork** and **open a pull request**:
   - Link related issues: `Closes #123`
   - Describe your changes clearly
   - Explain why this change is needed

5. **Address review feedback** and push updates (no force push)

## Testing Guidelines

- Write tests for all new features
- Maintain >80% code coverage
- Tests should be in `tests/` directory with `test_*.py` naming
- Use descriptive test names: `test_chain_engine_identifies_xss_csrf_chains()`

```bash
# Run tests with coverage
pytest tests/ --cov=webxploit --cov-report=html
```

## Documentation

- Add docstrings to all public functions/classes
- Update README.md if adding user-facing features
- Add examples to `examples/` for new workflows
- Update CHANGELOG.md with your changes

## Commit Message Guidelines

Use clear, descriptive commit messages:

```
fix: prevent scope bypass with wildcard URLs

- Add stricter regex validation for URL patterns
- Add test case for subdomain wildcard matching
- Closes #42
```

Prefix with: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `ci:`, `chore:`

## Reporting Security Issues

**Do not** open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md) for disclosure process.

## Questions?

- Check existing [issues](https://github.com/webxploit-chain/webxploit-chain/issues)
- Open a [discussion](https://github.com/webxploit-chain/webxploit-chain/discussions)
- Email: 08.joao.r.04@gmail.com

---

**Thank you for contributing!**
