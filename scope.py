"""
Scope enforcer — prevents any request from leaving the defined engagement scope.
Configured via YAML; raises ScopeViolation before a request is sent.
"""

from __future__ import annotations

import fnmatch
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

logger = logging.getLogger(__name__)


class ScopeViolation(Exception):
    """Raised when a target URL falls outside the defined engagement scope."""


@dataclass
class ScopeConfig:
    """
    Parsed scope configuration.

    allowed  — list of glob/wildcard patterns that ARE in scope.
               e.g. ["*.example.com", "10.0.0.*", "app.target.org/api/*"]
    excluded — patterns that are explicitly OUT of scope even if they match allowed.
               e.g. ["admin.example.com", "*.cdn.example.com"]
    """
    allowed:   list[str] = field(default_factory=list)
    excluded:  list[str] = field(default_factory=list)
    strict:    bool      = True    # if True, anything not explicitly allowed is blocked
    log_violations: bool = True

    # ------------------------------------------------------------------ #
    # Factory methods
    # ------------------------------------------------------------------ #

    @classmethod
    def from_yaml(cls, path: str | Path) -> "ScopeConfig":
        """Load scope config from a YAML file."""
        if not HAS_YAML:
            raise ImportError("PyYAML is required for YAML scope config: pip install pyyaml")
        with open(path) as fh:
            data = yaml.safe_load(fh)
        scope = data.get("scope", {})
        return cls(
            allowed=scope.get("allowed", []),
            excluded=scope.get("excluded", []),
            strict=scope.get("strict", True),
            log_violations=scope.get("log_violations", True),
        )

    @classmethod
    def from_dict(cls, data: dict) -> "ScopeConfig":
        scope = data.get("scope", data)
        return cls(
            allowed=scope.get("allowed", []),
            excluded=scope.get("excluded", []),
            strict=scope.get("strict", True),
            log_violations=scope.get("log_violations", True),
        )

    @classmethod
    def permissive(cls, targets: list[str]) -> "ScopeConfig":
        """Quick helper: create a scope from a plain list of targets."""
        return cls(allowed=targets, strict=True)


class ScopeEnforcer:
    """
    Checks every URL against the engagement scope before it is used.

    Usage
    -----
    ::

        enforcer = ScopeEnforcer.from_yaml("configs/scope.yaml")
        enforcer.check("https://app.target.org/login")   # OK
        enforcer.check("https://other.com/anything")     # raises ScopeViolation
    """

    def __init__(self, config: ScopeConfig) -> None:
        self.config = config
        self._violation_log: list[str] = []

    # ------------------------------------------------------------------ #
    # Factory helpers
    # ------------------------------------------------------------------ #

    @classmethod
    def from_yaml(cls, path: str | Path) -> "ScopeEnforcer":
        return cls(ScopeConfig.from_yaml(path))

    @classmethod
    def from_list(cls, targets: list[str], exclusions: Optional[list[str]] = None) -> "ScopeEnforcer":
        return cls(ScopeConfig(allowed=targets, excluded=exclusions or []))

    # ------------------------------------------------------------------ #
    # Core API
    # ------------------------------------------------------------------ #

    def check(self, url: str) -> bool:
        """
        Return True if the URL is in scope.
        Raise ScopeViolation if out of scope and strict mode is enabled.
        """
        target = self._normalize(url)

        if self._is_excluded(target):
            return self._violation(url, "explicitly excluded")

        if self._is_allowed(target):
            return True

        if self.config.strict:
            return self._violation(url, "not in allowed scope")

        return True   # permissive mode: allow by default

    def is_in_scope(self, url: str) -> bool:
        """Non-raising version of check()."""
        try:
            return self.check(url)
        except ScopeViolation:
            return False

    def filter(self, urls: list[str]) -> list[str]:
        """Return only URLs that are in scope."""
        return [u for u in urls if self.is_in_scope(u)]

    @property
    def violations(self) -> list[str]:
        return list(self._violation_log)

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _normalize(self, url: str) -> str:
        """Extract host + path for matching; strip scheme and query."""
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = parsed.netloc or parsed.path.split("/")[0]
        path = parsed.path or "/"
        return f"{host}{path}"

    def _matches_any(self, target: str, patterns: list[str]) -> bool:
        for pattern in patterns:
            # Normalise pattern the same way as the target
            norm_pattern = self._normalize(pattern) if "://" in pattern else pattern
            if fnmatch.fnmatch(target, norm_pattern):
                return True
            # Also try matching just the host portion
            host = target.split("/")[0]
            host_pattern = norm_pattern.split("/")[0]
            if fnmatch.fnmatch(host, host_pattern):
                # If pattern has a path component, check the full match too
                if "/" not in norm_pattern or fnmatch.fnmatch(target, norm_pattern):
                    return True
        return False

    def _is_allowed(self, target: str) -> bool:
        return self._matches_any(target, self.config.allowed)

    def _is_excluded(self, target: str) -> bool:
        return self._matches_any(target, self.config.excluded)

    def _violation(self, url: str, reason: str) -> bool:
        msg = f"[SCOPE VIOLATION] {url!r} - {reason}"
        if self.config.log_violations:
            logger.warning(msg)
            self._violation_log.append(msg)
        raise ScopeViolation(msg)
