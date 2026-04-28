"""
Core data models shared across WebXploit Chain.
All findings, chains, and engagement state are represented as typed dataclasses.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class VulnType(str, Enum):
    XSS             = "xss"
    SQLI            = "sqli"
    CSRF            = "csrf"
    SSRF            = "ssrf"
    IDOR            = "idor"
    LFI             = "lfi"
    RFI             = "rfi"
    RCE             = "rce"
    XXE             = "xxe"
    OPEN_REDIRECT   = "open_redirect"
    AUTH_BYPASS     = "auth_bypass"
    PRIV_ESC        = "privilege_escalation"
    INFO_DISCLOSURE = "info_disclosure"
    SSTI            = "ssti"
    DESERIALISATION = "deserialisation"


class ExploitStatus(str, Enum):
    CONFIRMED  = "confirmed"
    SUSPECTED  = "suspected"
    FALSE_POS  = "false_positive"
    CHAINED    = "chained"


# ---------------------------------------------------------------------------
# Finding — a single discovered vulnerability
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Represents a single discovered vulnerability during an engagement."""

    vuln_type:   VulnType
    url:         str
    parameter:   Optional[str]
    severity:    Severity
    status:      ExploitStatus           = ExploitStatus.SUSPECTED
    evidence:    str                     = ""
    payload:     str                     = ""
    request:     Optional[str]           = None   # raw HTTP request
    response:    Optional[str]           = None   # relevant response snippet
    cvss_score:  Optional[float]         = None
    notes:       str                     = ""
    tags:        list[str]               = field(default_factory=list)
    timestamp:   datetime                = field(default_factory=datetime.utcnow)
    id:          str                     = field(default_factory=lambda: str(uuid.uuid4())[:8])

    def __str__(self) -> str:
        return (
            f"[{self.severity.value.upper()}] {self.vuln_type.value} @ {self.url}"
            + (f" ({self.parameter})" if self.parameter else "")
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id":         self.id,
            "vuln_type":  self.vuln_type.value,
            "url":        self.url,
            "parameter":  self.parameter,
            "severity":   self.severity.value,
            "status":     self.status.value,
            "evidence":   self.evidence,
            "payload":    self.payload,
            "cvss_score": self.cvss_score,
            "notes":      self.notes,
            "tags":       self.tags,
            "timestamp":  self.timestamp.isoformat(),
        }


# ---------------------------------------------------------------------------
# ChainLink — one step inside a vuln chain
# ---------------------------------------------------------------------------

@dataclass
class ChainLink:
    """One exploitation step inside a VulnChain."""

    finding:     Finding
    step_number: int
    action:      str   = ""    # e.g. "steal session cookie via XSS"
    payload:     str   = ""    # step-specific chained payload
    depends_on:  list[str] = field(default_factory=list)   # finding IDs


# ---------------------------------------------------------------------------
# VulnChain — a sequence of linked vulnerabilities forming an attack path
# ---------------------------------------------------------------------------

@dataclass
class VulnChain:
    """
    An ordered sequence of ChainLinks that together constitute a complete
    attack path — e.g. XSS → CSRF → Admin takeover.
    """

    id:          str              = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name:        str              = ""
    description: str              = ""
    links:       list[ChainLink]  = field(default_factory=list)
    impact:      str              = ""
    severity:    Severity         = Severity.HIGH
    timestamp:   datetime         = field(default_factory=datetime.utcnow)

    @property
    def vuln_types(self) -> list[VulnType]:
        return [link.finding.vuln_type for link in self.links]

    @property
    def chain_label(self) -> str:
        return " → ".join(vt.value.upper() for vt in self.vuln_types)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id":          self.id,
            "name":        self.name,
            "description": self.description,
            "chain":       self.chain_label,
            "impact":      self.impact,
            "severity":    self.severity.value,
            "steps":       [
                {
                    "step":    link.step_number,
                    "vuln":    link.finding.vuln_type.value,
                    "url":     link.finding.url,
                    "action":  link.action,
                    "payload": link.payload,
                }
                for link in self.links
            ],
            "timestamp":   self.timestamp.isoformat(),
        }


# ---------------------------------------------------------------------------
# Engagement — top-level container for a red team engagement
# ---------------------------------------------------------------------------

@dataclass
class Engagement:
    """Top-level container for a full red team engagement."""

    name:       str
    scope:      list[str]              = field(default_factory=list)   # domains/IPs in scope
    exclusions: list[str]              = field(default_factory=list)   # out-of-scope patterns
    findings:   list[Finding]          = field(default_factory=list)
    chains:     list[VulnChain]        = field(default_factory=list)
    operator:   str                    = "anonymous"
    start_time: datetime               = field(default_factory=datetime.utcnow)
    end_time:   Optional[datetime]     = None
    notes:      str                    = ""
    id:         str                    = field(default_factory=lambda: str(uuid.uuid4())[:8])

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_chain(self, chain: VulnChain) -> None:
        self.chains.append(chain)

    @property
    def findings_by_severity(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {s.value: [] for s in Severity}
        for f in self.findings:
            result[f.severity.value].append(f)
        return result

    def summary(self) -> dict[str, Any]:
        return {
            "id":            self.id,
            "name":          self.name,
            "operator":      self.operator,
            "scope_count":   len(self.scope),
            "finding_count": len(self.findings),
            "chain_count":   len(self.chains),
            "severities": {
                sev: len(findings)
                for sev, findings in self.findings_by_severity.items()
                if findings
            },
        }
