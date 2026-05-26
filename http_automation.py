"""HTTP automation helpers for live, in-scope payload checks."""

from __future__ import annotations

import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

from scope import ScopeEnforcer

logger = logging.getLogger(__name__)


@dataclass
class HTTPResponseSnapshot:
    url: str
    status_code: int
    headers: dict[str, str]
    body: str
    elapsed: float


@dataclass
class PayloadTestResult:
    url: str
    method: str
    payload: str
    status_code: Optional[int] = None
    elapsed: float = 0.0
    success: bool = False
    indicators: list[str] = field(default_factory=list)
    error: str = ""
    response_excerpt: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "method": self.method,
            "payload": self.payload,
            "status_code": self.status_code,
            "elapsed": round(self.elapsed, 3),
            "success": self.success,
            "indicators": self.indicators,
            "error": self.error,
            "response_excerpt": self.response_excerpt,
        }


class HTTPTester:
    """Small urllib-based HTTP client with optional scope enforcement."""

    def __init__(
        self,
        scope_enforcer: Optional[ScopeEnforcer] = None,
        timeout: float = 10.0,
        user_agent: str = "WebXploit-Chain/0.1",
    ) -> None:
        self.scope_enforcer = scope_enforcer
        self.timeout = timeout
        self.user_agent = user_agent

    def fetch(
        self,
        url: str,
        method: str = "GET",
        body: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> HTTPResponseSnapshot:
        self._check_scope(url)
        request_headers = {"User-Agent": self.user_agent}
        request_headers.update(headers or {})
        data = body.encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            url,
            data=data,
            headers=request_headers,
            method=method.upper(),
        )
        started = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw_body = response.read()
                return HTTPResponseSnapshot(
                    url=response.geturl(),
                    status_code=response.status,
                    headers=dict(response.headers.items()),
                    body=self._decode_body(raw_body),
                    elapsed=time.monotonic() - started,
                )
        except urllib.error.HTTPError as exc:
            raw_body = exc.read()
            return HTTPResponseSnapshot(
                url=url,
                status_code=exc.code,
                headers=dict(exc.headers.items()),
                body=self._decode_body(raw_body),
                elapsed=time.monotonic() - started,
            )

    def test_payload(
        self,
        url: str,
        payload: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        expected: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> PayloadTestResult:
        method = method.upper()
        target_url, body = self._prepare_payload_request(url, payload, parameter, method)
        result = PayloadTestResult(url=target_url, method=method, payload=payload)
        try:
            response = self.fetch(target_url, method=method, body=body, headers=headers)
        except Exception as exc:
            if exc.__class__.__name__ == "ScopeViolation":
                raise
            logger.warning("Payload test failed for %s: %s", target_url, exc)
            result.error = str(exc)
            return result

        result.status_code = response.status_code
        result.elapsed = response.elapsed
        result.response_excerpt = response.body[:500]
        result.indicators = self.detect_indicators(response, payload, expected)
        result.success = bool(result.indicators)
        return result

    def detect_indicators(
        self,
        response: HTTPResponseSnapshot,
        payload: str,
        expected: Optional[str] = None,
    ) -> list[str]:
        indicators: list[str] = []
        if expected and expected in response.body:
            indicators.append(f"expected marker found: {expected}")
        if payload and payload in response.body:
            indicators.append("payload reflected in response")
        if response.status_code >= 500:
            indicators.append(f"server error status: {response.status_code}")
        if response.elapsed >= 5.0:
            indicators.append(f"slow response: {response.elapsed:.2f}s")
        return indicators

    def _prepare_payload_request(
        self,
        url: str,
        payload: str,
        parameter: Optional[str],
        method: str,
    ) -> tuple[str, Optional[str]]:
        if method == "POST":
            return url, urllib.parse.urlencode({parameter or "payload": payload})

        parsed = urllib.parse.urlsplit(url)
        query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        if parameter:
            query[parameter] = payload
        elif query:
            query[next(iter(query))] = payload
        else:
            query["payload"] = payload
        return urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query))), None

    def _check_scope(self, url: str) -> None:
        if self.scope_enforcer is not None:
            self.scope_enforcer.check(url)

    def _decode_body(self, raw_body: bytes) -> str:
        return raw_body.decode("utf-8", errors="replace")
