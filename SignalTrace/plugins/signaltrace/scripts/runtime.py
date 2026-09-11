#!/usr/bin/env python3
"""Bounded robots-aware HTTP runtime and shared evidence cache."""

from __future__ import annotations

import dataclasses
import ipaddress
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
from typing import Any

USER_AGENT = "SignalTrace/1.0 (+read-only-public-audit)"
REDIRECTS = {301, 302, 303, 307, 308}


class LimitError(RuntimeError):
    pass


class UnsafeTarget(ValueError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclasses.dataclass
class Evidence:
    requested_url: str
    final_url: str
    status: int | None
    headers: dict[str, str]
    body: bytes
    redirect_chain: list[dict[str, Any]]
    outcome: str
    detail: str = ""

    def text(self) -> str:
        content_type = self.headers.get("content-type", "")
        charset = "utf-8"
        for part in content_type.split(";")[1:]:
            if part.strip().lower().startswith("charset="):
                charset = part.split("=", 1)[1].strip(" \"'") or "utf-8"
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")


class RequestGovernor:
    def __init__(self, *, max_requests: int, max_concurrency: int,
                 timeout: float, max_body_bytes: int, deadline_seconds: float):
        self.started_at = time.monotonic()
        self.deadline = self.started_at + deadline_seconds
        self.max_requests = max_requests
        self.timeout = timeout
        self.max_body_bytes = max_body_bytes
        self._lock = threading.RLock()
        self._semaphore = threading.BoundedSemaphore(max_concurrency)
        self._started = 0
        self._completed = 0
        self._skipped = 0
        self._cache: dict[str, Evidence] = {}
        self._robots: dict[str, tuple[bool, urllib.robotparser.RobotFileParser | None, str]] = {}
        self._robots_inflight: dict[str, threading.Event] = {}
        self._inflight: dict[str, threading.Event] = {}
        self._opener = urllib.request.build_opener(_NoRedirect())

    def remaining_seconds(self) -> float:
        return max(0.0, self.deadline - time.monotonic())

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "requests_started": self._started,
                "requests_completed": self._completed,
                "requests_skipped": self._skipped,
                "remaining_requests": max(0, self.max_requests - self._started),
                "remaining_deadline_seconds": round(self.remaining_seconds(), 3),
            }

    @staticmethod
    def normalize_url(url: str) -> str:
        raw = str(url).strip()
        parsed = urllib.parse.urlsplit(raw)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or not parsed.hostname:
            raise UnsafeTarget("only absolute public http(s) URLs are supported")
        try:
            host = parsed.hostname.encode("idna").decode("ascii").lower()
            port = parsed.port
        except (UnicodeError, ValueError) as exc:
            raise UnsafeTarget(f"invalid hostname or port: {exc}") from exc
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = None
        netloc = host if port is None else f"{host}:{port}"
        path = parsed.path or "/"
        return urllib.parse.urlunsplit((scheme, netloc, path, parsed.query, ""))

    @staticmethod
    def _assert_public(url: str) -> None:
        host = urllib.parse.urlsplit(url).hostname
        if not host:
            raise UnsafeTarget("URL has no hostname")
        if host.casefold() in {"localhost", "localhost.localdomain"}:
            raise UnsafeTarget("local network targets are not public")
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise UnsafeTarget(f"hostname did not resolve: {exc}") from exc
        for info in infos:
            address = ipaddress.ip_address(info[4][0].split("%", 1)[0])
            if not address.is_global:
                raise UnsafeTarget("private, loopback, link-local, or reserved targets are blocked")

    def _reserve(self) -> float:
        with self._lock:
            remaining = self.remaining_seconds()
            if remaining <= 0:
                self._skipped += 1
                raise LimitError("global deadline exhausted")
            if self._started >= self.max_requests:
                self._skipped += 1
                raise LimitError("request budget exhausted")
            self._started += 1
            return min(self.timeout, remaining)

    def _request_once(self, url: str, *, body_limit: int | None = None) -> Evidence:
        timeout = self._reserve()
        self._assert_public(url)
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/json,text/plain;q=0.8,*/*;q=0.1",
            "Accept-Encoding": "identity",
        })
        limit = body_limit or self.max_body_bytes
        try:
            with self._semaphore:
                try:
                    response = self._opener.open(req, timeout=timeout)
                except urllib.error.HTTPError as exc:
                    response = exc
                status = getattr(response, "status", response.getcode())
                headers = {k.lower(): v for k, v in response.headers.items()}
                body = response.read(limit + 1)
                if len(body) > limit:
                    body = body[:limit]
                    detail = f"body truncated at {limit} bytes"
                else:
                    detail = ""
            outcome = "ok" if 200 <= status < 300 else "http-error"
            return Evidence(url, url, status, headers, body, [], outcome, detail)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return Evidence(url, url, None, {}, b"", [], "network-error", str(exc))
        finally:
            with self._lock:
                self._completed += 1

    @staticmethod
    def _origin(url: str) -> str:
        parts = urllib.parse.urlsplit(url)
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc, "", "", ""))

    def _load_robots(self, url: str) -> tuple[bool, urllib.robotparser.RobotFileParser | None, str]:
        origin = self._origin(url)
        with self._lock:
            known = self._robots.get(origin)
            if known:
                return known
            wait_event = self._robots_inflight.get(origin)
            if wait_event is None:
                wait_event = threading.Event()
                self._robots_inflight[origin] = wait_event
                owner = True
            else:
                owner = False
        if not owner:
            wait_event.wait(timeout=self.remaining_seconds())
            with self._lock:
                return self._robots.get(
                    origin, (False, None, "robots check did not complete before deadline"))
        robots_url = origin + "/robots.txt"
        try:
            result = self._request_once(robots_url, body_limit=min(self.max_body_bytes, 262144))
        except (LimitError, UnsafeTarget) as exc:
            policy = (False, None, f"robots unavailable: {exc}")
        else:
            if result.status in {404, 410}:
                policy = (True, None, "robots.txt not published")
            elif result.status != 200:
                policy = (False, None, f"robots unavailable with status {result.status}")
            elif result.headers.get("location"):
                policy = (False, None, "robots redirect not followed")
            else:
                parser = urllib.robotparser.RobotFileParser()
                try:
                    parser.parse(result.text().splitlines())
                    policy = (True, parser, "robots.txt parsed")
                except Exception as exc:
                    policy = (False, None, f"robots parse failure: {exc}")
        with self._lock:
            self._robots.setdefault(origin, policy)
            self._robots_inflight.pop(origin, None)
            wait_event.set()
            return self._robots[origin]

    def permission(self, url: str) -> tuple[bool, str]:
        normalized = self.normalize_url(url)
        available, parser, reason = self._load_robots(normalized)
        if not available:
            return False, reason
        if parser is not None and not parser.can_fetch(USER_AGENT, normalized):
            return False, "robots.txt disallows this URL"
        return True, reason

    def fetch(self, url: str, *, max_redirects: int = 5) -> Evidence:
        requested = self.normalize_url(url)
        with self._lock:
            cached = self._cache.get(requested)
            if cached:
                return cached
            wait_event = self._inflight.get(requested)
            if wait_event is None:
                wait_event = threading.Event()
                self._inflight[requested] = wait_event
                owner = True
            else:
                owner = False
        if not owner:
            wait_event.wait(timeout=self.remaining_seconds())
            with self._lock:
                cached = self._cache.get(requested)
            if cached:
                return cached
            raise LimitError("deduplicated request did not complete before deadline")
        try:
            current, chain = requested, []
            seen = {requested}
            for _ in range(max_redirects + 1):
                allowed, reason = self.permission(current)
                if not allowed:
                    with self._lock:
                        self._skipped += 1
                    result = Evidence(requested, current, None, {}, b"", chain,
                                      "robots-denied", reason)
                    break
                response = self._request_once(current)
                response.requested_url = requested
                response.redirect_chain = list(chain)
                if response.status not in REDIRECTS:
                    response.final_url = current
                    result = response
                    break
                location = response.headers.get("location")
                if not location:
                    response.outcome = "unresolved-redirect"
                    response.detail = "redirect response had no Location header"
                    result = response
                    break
                target = self.normalize_url(urllib.parse.urljoin(current, location))
                chain.append({"from": current, "status": response.status, "to": target})
                if target in seen:
                    result = Evidence(requested, current, response.status, response.headers,
                                      response.body, chain, "redirect-loop", "redirect loop")
                    break
                seen.add(target)
                current = target
            else:
                result = Evidence(requested, current, None, {}, b"", chain,
                                  "redirect-limit", "redirect limit exceeded")
            with self._lock:
                for alias in seen:
                    self._cache.setdefault(alias, result)
            return result
        finally:
            with self._lock:
                self._inflight.pop(requested, None)
                wait_event.set()
