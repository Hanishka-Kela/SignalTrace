#!/usr/bin/env python3
"""Curl-only, bounded, robots-aware HTTP governor and evidence cache."""

from __future__ import annotations

import dataclasses
import ipaddress
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.robotparser
from typing import Any

from config import DEFAULTS, USER_AGENT

REDIRECTS = {301, 302, 303, 307, 308}


class LimitError(RuntimeError):
    pass


class UnsafeTarget(ValueError):
    pass


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
    curl_exit: int | None = None
    cache_key: str = ""
    policy_observed: bool = False

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


@dataclasses.dataclass(frozen=True)
class RobotsDecision:
    result: str
    allowed_to_crawl: bool
    detail: str
    parser: urllib.robotparser.RobotFileParser | None = None


class RequestGovernor:
    """The only SignalTrace component authorized to execute network requests."""

    def __init__(
        self, *, max_requests: int = DEFAULTS.global_request_maximum,
        target_request_maximum: int = DEFAULTS.target_request_maximum,
        max_concurrency: int = DEFAULTS.cross_origin_concurrency,
        timeout: float = DEFAULTS.request_timeout_seconds,
        connect_timeout: float = DEFAULTS.connection_timeout_seconds,
        max_body_bytes: int = DEFAULTS.response_body_limit_bytes,
        aggregate_body_bytes: int = DEFAULTS.aggregate_body_limit_bytes,
        deadline_seconds: float = DEFAULTS.global_deadline_seconds,
        max_per_origin: int = DEFAULTS.per_origin_maximum,
        spacing_seconds: float = DEFAULTS.same_origin_spacing_seconds,
        retries: int = DEFAULTS.retries,
        max_redirects: int = DEFAULTS.maximum_redirects,
    ):
        self.started_at = time.monotonic()
        self.deadline = self.started_at + deadline_seconds
        self.max_requests = max_requests
        self.target_request_maximum = min(max_requests, target_request_maximum)
        self.max_per_origin = min(max_requests, max_per_origin)
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.max_body_bytes = max_body_bytes
        self.aggregate_body_bytes = aggregate_body_bytes
        self.spacing_seconds = spacing_seconds
        self.retries = retries
        self.max_redirects = max_redirects
        self._lock = threading.RLock()
        self._cross_origin = threading.BoundedSemaphore(min(2, max_concurrency))
        self._started = 0
        self._completed = 0
        self._skipped = 0
        self._target_started = 0
        self._redirects = 0
        self._retries_started = 0
        self._aggregate_bytes = 0
        self._aggregate_reserved = 0
        self._origin_started: dict[str, int] = {}
        self._origin_target_started: dict[str, int] = {}
        self._origin_locks: dict[str, threading.Lock] = {}
        self._origin_last_start: dict[str, float] = {}
        self._origin_server_failures: dict[str, int] = {}
        self._blocked_origins: dict[str, str] = {}
        self._cache: dict[str, Evidence] = {}
        self._response_cache: dict[str, list[Evidence]] = {}
        self._robots: dict[str, RobotsDecision] = {}
        self._robots_inflight: dict[str, threading.Event] = {}
        self._inflight: dict[str, threading.Event] = {}
        self._curl_path = shutil.which("curl")

    def remaining_seconds(self) -> float:
        return max(0.0, self.deadline - time.monotonic())

    def elapsed_seconds(self) -> float:
        return max(0.0, time.monotonic() - self.started_at)

    def snapshot(self, url: str | None = None) -> dict[str, Any]:
        with self._lock:
            result = {
                "requests_started": self._started,
                "requests_completed": self._completed,
                "requests_skipped": self._skipped,
                "target_requests_started": self._target_started,
                "redirects_observed": self._redirects,
                "retries_started": self._retries_started,
                "response_bytes_cached": self._aggregate_bytes,
                "remaining_requests": max(0, self.max_requests - self._started),
                "remaining_target_requests": max(0, self.target_request_maximum - self._target_started),
                "remaining_deadline_seconds": round(self.remaining_seconds(), 3),
                "elapsed_seconds": round(self.elapsed_seconds(), 3),
                "origins_stopped": [
                    {"origin": origin, "reason": reason}
                    for origin, reason in sorted(self._blocked_origins.items())
                ],
            }
            if url:
                origin = self._origin(self.normalize_url(url))
                result["remaining_origin_requests"] = max(
                    0, self.max_per_origin - self._origin_started.get(origin, 0))
            return result

    def delegation_context(self, task_identifier: str, url: str,
                           cached_refs: list[str], maximum_additional_requests: int = 0) -> dict[str, Any]:
        normalized = self.normalize_url(url)
        snapshot = self.snapshot(normalized)
        decision = self._robots.get(self._origin(normalized))
        return {
            "task_identifier": task_identifier,
            "cached_evidence_references": list(cached_refs),
            "permission_status": decision.result if decision else "not-checked",
            "remaining_global_request_budget": snapshot["remaining_requests"],
            "remaining_per_origin_budget": snapshot["remaining_origin_requests"],
            "remaining_time": snapshot["remaining_deadline_seconds"],
            "maximum_additional_requests": min(1, max(0, maximum_additional_requests)),
            "cancellation_deadline": self.deadline,
        }

    @staticmethod
    def normalize_url(url: str) -> str:
        parsed = urllib.parse.urlsplit(str(url).strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise UnsafeTarget("only absolute public http(s) URLs are supported")
        if parsed.username or parsed.password:
            raise UnsafeTarget("credentials in URLs are not supported")
        try:
            host = parsed.hostname.encode("idna").decode("ascii").lower()
            port = parsed.port
        except (UnicodeError, ValueError) as exc:
            raise UnsafeTarget(f"invalid hostname or port: {exc}") from exc
        if (parsed.scheme.lower() == "http" and port == 80) or (parsed.scheme.lower() == "https" and port == 443):
            port = None
        netloc = host if port is None else f"{host}:{port}"
        return urllib.parse.urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))

    @staticmethod
    def _assert_public(url: str) -> None:
        host = urllib.parse.urlsplit(url).hostname
        if not host or host.casefold() in {"localhost", "localhost.localdomain"}:
            raise UnsafeTarget("local network targets are not public")
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise UnsafeTarget(f"hostname did not resolve: {exc}") from exc
        for info in infos:
            address = ipaddress.ip_address(info[4][0].split("%", 1)[0])
            if not address.is_global:
                raise UnsafeTarget("private, loopback, link-local, or reserved targets are blocked")

    @staticmethod
    def _origin(url: str) -> str:
        parts = urllib.parse.urlsplit(url)
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc, "", "", ""))

    def _reserve(self, url: str, kind: str, requested_body_bytes: int) -> tuple[float, int]:
        with self._lock:
            remaining = self.remaining_seconds()
            if remaining <= 0:
                self._skipped += 1
                raise LimitError("global deadline exhausted")
            if self._started >= self.max_requests:
                self._skipped += 1
                raise LimitError("global request ceiling reached")
            origin = self._origin(url)
            if self._origin_started.get(origin, 0) >= self.max_per_origin:
                self._skipped += 1
                raise LimitError("per-origin request ceiling reached")
            decision = self._robots.get(origin)
            is_robots_request = kind.startswith("robots")
            if (not is_robots_request and decision is not None and decision.result == "unavailable"
                    and self._origin_target_started.get(origin, 0) >=
                    DEFAULTS.unavailable_robots_origin_target_maximum):
                self._skipped += 1
                raise LimitError("unavailable robots policy conservative origin ceiling reached")
            if not is_robots_request and self._target_started >= self.target_request_maximum:
                self._skipped += 1
                raise LimitError("target request ceiling reached")
            aggregate_remaining = self.aggregate_body_bytes - self._aggregate_bytes - self._aggregate_reserved
            if aggregate_remaining <= 0:
                self._skipped += 1
                raise LimitError("aggregate response body ceiling reached")
            self._started += 1
            self._origin_started[origin] = self._origin_started.get(origin, 0) + 1
            if not is_robots_request:
                self._target_started += 1
                self._origin_target_started[origin] = self._origin_target_started.get(origin, 0) + 1
            if kind in {"retry", "robots-retry"}:
                self._retries_started += 1
            reserved = max(1, min(requested_body_bytes, aggregate_remaining))
            self._aggregate_reserved += reserved
            return min(self.timeout, remaining), reserved

    def _spacing_wait(self, origin: str) -> None:
        with self._lock:
            wait = max(0.0, self.spacing_seconds - (time.monotonic() - self._origin_last_start.get(origin, 0.0)))
        if wait:
            if wait >= self.remaining_seconds():
                raise LimitError("global deadline would expire during same-origin spacing")
            time.sleep(wait)

    @staticmethod
    def _parse_headers(raw: bytes) -> tuple[int | None, dict[str, str]]:
        text = raw.decode("latin-1", errors="replace")
        starts = list(re.finditer(r"(?m)^HTTP/\S+\s+(\d{3})(?:\s+.*)?\r?$", text))
        if not starts:
            return None, {}
        start = starts[-1]
        headers: dict[str, str] = {}
        for line in text[start.end():].replace("\r\n", "\n").split("\n"):
            if not line.strip():
                if headers:
                    break
                continue
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().casefold()] = value.strip()
        return int(start.group(1)), headers

    @staticmethod
    def _read(path: str) -> bytes:
        try:
            with open(path, "rb") as handle:
                return handle.read()
        except FileNotFoundError:
            return b""

    def _remember_response(self, url: str, result: Evidence) -> Evidence:
        with self._lock:
            attempt = len(self._response_cache.get(url, [])) + 1
            result.cache_key = f"response:{url}#attempt-{attempt}"
            self._response_cache.setdefault(url, []).append(result)
        return result

    def _blocked_evidence(self, url: str, reason: str) -> Evidence:
        with self._lock:
            self._skipped += 1
        return Evidence(url, url, None, {}, b"", [], "origin-blocked", reason,
                        policy_observed=True)

    def _observe_origin_response(self, url: str, evidence: Evidence, kind: str) -> None:
        """Stop an origin after explicit access controls or repeated server failures."""
        if kind.startswith("robots") or evidence.policy_observed:
            return
        evidence.policy_observed = True
        origin = self._origin(url)
        body = evidence.body[:16384].decode("utf-8", errors="ignore")
        anti_bot = bool(re.search(
            r"\b(?:verify you are human|checking your browser|automated (?:access|requests?) "
            r"(?:is |are )?(?:blocked|denied)|request blocked by security policy)\b",
            body, re.I)) or evidence.headers.get("cf-mitigated", "").casefold() == "challenge"
        anti_bot = anti_bot or bool(len(evidence.body) <= 65536 and re.search(
            r"<title[^>]*>[^<]*(?:captcha|human verification)[^<]*</title>|\bcaptcha challenge\b",
            body, re.I))
        reason = ""
        with self._lock:
            if evidence.status in {403, 429}:
                reason = f"origin stopped after HTTP {evidence.status} access response"
            elif anti_bot:
                reason = "origin stopped after an explicit anti-bot response"
            elif evidence.status is not None and 500 <= evidence.status <= 599:
                failures = self._origin_server_failures.get(origin, 0) + 1
                self._origin_server_failures[origin] = failures
                if failures >= 2:
                    reason = f"origin stopped after repeated 5xx responses (latest HTTP {evidence.status})"
            elif evidence.status is not None:
                self._origin_server_failures[origin] = 0
            if reason:
                self._blocked_origins[origin] = reason
        if reason:
            evidence.outcome = "blocked"
            evidence.detail = reason

    def _curl_once(self, url: str, *, kind: str, body_limit: int) -> Evidence:
        if not self._curl_path:
            return Evidence(url, url, None, {}, b"", [], "network-error", "curl executable not found")
        origin = self._origin(url)
        with self._lock:
            origin_lock = self._origin_locks.setdefault(origin, threading.Lock())
        with origin_lock:
            with self._lock:
                blocked_reason = self._blocked_origins.get(origin)
            if not kind.startswith("robots") and blocked_reason:
                return self._blocked_evidence(url, blocked_reason)
            self._spacing_wait(origin)
            timeout, effective_limit = self._reserve(url, kind, body_limit)
            with self._lock:
                self._origin_last_start[origin] = time.monotonic()
            with self._cross_origin:
                try:
                    self._assert_public(url)
                except UnsafeTarget as exc:
                    with self._lock:
                        self._completed += 1
                        self._aggregate_reserved -= effective_limit
                    return self._remember_response(
                        url, Evidence(url, url, None, {}, b"", [], "network-error", str(exc)))
                with tempfile.TemporaryDirectory(prefix="signaltrace-curl-") as temporary:
                    headers_path = os.path.join(temporary, "headers")
                    body_path = os.path.join(temporary, "body")
                    command = [
                        self._curl_path,
                        "--silent", "--show-error", "--location", "--max-redirs", "0",
                        "--max-time", f"{timeout:g}",
                        "--connect-timeout", f"{min(self.connect_timeout, timeout):g}",
                        "--user-agent", USER_AGENT,
                        "--compressed", "--retry", "0",
                        "--max-filesize", str(effective_limit),
                        "--dump-header", headers_path, "--output", body_path,
                        "--write-out", "%{http_code}\n%{url_effective}", url,
                    ]
                    try:
                        process = subprocess.run(
                            command, capture_output=True, text=True,
                            timeout=max(1.0, self.remaining_seconds() + 0.25), check=False)
                    except subprocess.TimeoutExpired:
                        process = None
                    except OSError as exc:
                        process = exc
                    header_bytes = self._read(headers_path)
                    body = self._read(body_path)[:effective_limit]
            status, headers = self._parse_headers(header_bytes)
            with self._lock:
                self._completed += 1
                self._aggregate_bytes += len(body)
                self._aggregate_reserved -= effective_limit
            if process is None:
                result = Evidence(url, url, status, headers, body, [], "timeout", "governor subprocess deadline")
            elif isinstance(process, OSError):
                result = Evidence(url, url, status, headers, body, [], "network-error", str(process))
            else:
                lines = process.stdout.splitlines()
                if status is None and lines and lines[0].isdigit():
                    status = int(lines[0]) or None
                effective_url = lines[1] if len(lines) > 1 and lines[1] else url
                error = process.stderr.strip()
                if process.returncode == 28:
                    outcome, detail = "timeout", error or "curl timed out"
                elif status in REDIRECTS:
                    outcome, detail = "redirect", error
                elif process.returncode == 63:
                    outcome, detail = "body-limit", f"response truncated at {effective_limit} bytes"
                elif process.returncode != 0:
                    outcome, detail = "network-error", error or f"curl exit {process.returncode}"
                elif status is None:
                    outcome, detail = "network-error", error or "curl returned no HTTP status"
                elif 200 <= status < 300:
                    outcome, detail = "ok", ""
                else:
                    outcome, detail = "http-error", f"HTTP {status}"
                result = Evidence(url, effective_url, status, headers, body, [], outcome, detail, process.returncode)
            self._observe_origin_response(url, result, kind)
            return self._remember_response(url, result)

    def _request_with_retries(self, url: str, *, kind: str, body_limit: int) -> Evidence:
        result = self._curl_once(url, kind=kind, body_limit=body_limit)
        for _ in range(self.retries):
            retryable = result.outcome in {"timeout", "network-error"} or (
                result.status is not None and result.status >= 500)
            if not retryable or self.remaining_seconds() <= 0:
                break
            retry_kind = "robots-retry" if kind.startswith("robots") else "retry"
            result = self._curl_once(url, kind=retry_kind, body_limit=body_limit)
        return result

    def _load_robots(self, url: str) -> RobotsDecision:
        origin = self._origin(url)
        with self._lock:
            known = self._robots.get(origin)
            if known:
                return known
            event = self._robots_inflight.get(origin)
            if event is None:
                event = threading.Event()
                self._robots_inflight[origin] = event
                owner = True
            else:
                owner = False
        if not owner:
            event.wait(timeout=self.remaining_seconds())
            with self._lock:
                return self._robots.get(origin, RobotsDecision(
                    "unavailable", False, "robots check did not complete before deadline"))
        robots_url = origin + "/robots.txt"
        try:
            evidence = self._request_with_retries(
                robots_url, kind="robots", body_limit=DEFAULTS.robots_body_limit_bytes)
            if evidence.status in {404, 410}:
                decision = RobotsDecision("missing", True, f"robots.txt returned HTTP {evidence.status}")
            elif evidence.outcome == "timeout":
                decision = RobotsDecision(
                    "unavailable", True,
                    f"robots.txt timed out ({evidence.detail}); conservative bounded audit only")
            elif evidence.status is None or evidence.outcome == "network-error":
                decision = RobotsDecision(
                    "unavailable", True,
                    f"robots.txt could not be fetched ({evidence.detail}); conservative bounded audit only")
            elif evidence.status != 200:
                decision = RobotsDecision(
                    "unavailable", True,
                    f"robots.txt returned HTTP {evidence.status}; conservative bounded audit only")
            elif evidence.outcome == "body-limit" or b"\x00" in evidence.body:
                decision = RobotsDecision(
                    "unavailable", True,
                    "robots.txt could not be parsed (truncated or invalid bytes); conservative bounded audit only")
            else:
                try:
                    text = evidence.body.decode("utf-8", errors="strict")
                    parser = urllib.robotparser.RobotFileParser()
                    parser.set_url(robots_url)
                    parser.parse(text.splitlines())
                    decision = RobotsDecision("allowed", True, "robots.txt parsed", parser)
                except (UnicodeDecodeError, ValueError) as exc:
                    decision = RobotsDecision(
                        "unavailable", True,
                        f"robots.txt could not be parsed ({exc}); conservative bounded audit only")
        except (LimitError, UnsafeTarget) as exc:
            decision = RobotsDecision("unavailable", False, str(exc))
        finally:
            with self._lock:
                if "decision" not in locals():
                    decision = RobotsDecision("unavailable", False, "robots check failed")
                self._robots.setdefault(origin, decision)
                self._robots_inflight.pop(origin, None)
                event.set()
        return decision

    def permission(self, url: str) -> tuple[bool, str]:
        normalized = self.normalize_url(url)
        decision = self._load_robots(normalized)
        if not decision.allowed_to_crawl:
            return False, f"{decision.result}: {decision.detail}"
        if decision.parser is not None and not decision.parser.can_fetch(USER_AGENT, normalized):
            return False, "denied: robots.txt disallows this URL"
        return True, f"{decision.result}: {decision.detail}"

    def robots_result(self, url: str) -> dict[str, str]:
        normalized = self.normalize_url(url)
        decision = self._robots.get(self._origin(normalized))
        if not decision:
            return {"result": "not-checked", "detail": "robots policy not evaluated"}
        allowed, reason = self.permission(normalized)
        result = decision.result if allowed else ("denied" if reason.startswith("denied:") else decision.result)
        return {"result": result, "detail": reason}

    def crawl_policy(self, url: str) -> dict[str, Any]:
        """Describe the bounded scheduling policy without implying authorization."""
        robots = self.robots_result(url)
        if robots["result"] == "missing":
            return {
                "name": "bounded_missing-policy_audit",
                "unrestricted": False,
                "reason": "No published robots policy was found; existing safety ceilings remain active",
            }
        if robots["result"] == "unavailable":
            return {
                "name": "conservative_unavailable-policy_audit",
                "unrestricted": False,
                "reason": "No usable robots policy could be obtained; a reduced sample and all safety ceilings remain active",
            }
        if robots["result"] == "denied":
            return {
                "name": "robots-denied",
                "unrestricted": False,
                "reason": "robots.txt denied this URL; it is not assessed",
            }
        return {
            "name": "bounded_published-policy_audit",
            "unrestricted": False,
            "reason": "Published robots rules and all existing safety ceilings remain active",
        }

    def fetch(self, url: str) -> Evidence:
        requested = self.normalize_url(url)
        with self._lock:
            cached = self._cache.get(requested)
            if cached:
                return cached
            event = self._inflight.get(requested)
            if event is None:
                event = threading.Event()
                self._inflight[requested] = event
                owner = True
            else:
                owner = False
        if not owner:
            event.wait(timeout=self.remaining_seconds())
            with self._lock:
                cached = self._cache.get(requested)
            if cached:
                return cached
            raise LimitError("deduplicated request did not complete before deadline")
        try:
            current, chain, seen = requested, [], {requested}
            for hop in range(self.max_redirects + 1):
                allowed, reason = self.permission(current)
                if not allowed:
                    with self._lock:
                        self._skipped += 1
                    outcome = "robots-denied" if reason.startswith("denied:") else "unavailable"
                    result = Evidence(requested, current, None, {}, b"", chain, outcome, reason)
                    break
                with self._lock:
                    blocked_reason = self._blocked_origins.get(self._origin(current))
                if blocked_reason:
                    result = self._blocked_evidence(current, blocked_reason)
                    result.requested_url = requested
                    result.redirect_chain = list(chain)
                    break
                evidence = self._request_with_retries(
                    current, kind="target" if hop == 0 else "redirect", body_limit=self.max_body_bytes)
                self._observe_origin_response(
                    current, evidence, "target" if hop == 0 else "redirect")
                evidence.requested_url = requested
                evidence.redirect_chain = list(chain)
                if evidence.status not in REDIRECTS:
                    evidence.final_url = current
                    result = evidence
                    break
                location = evidence.headers.get("location")
                if not location:
                    evidence.outcome = "unresolved-redirect"
                    evidence.detail = "redirect response had no Location header"
                    result = evidence
                    break
                target = self.normalize_url(urllib.parse.urljoin(current, location))
                chain.append({"from": current, "status": evidence.status, "to": target,
                              "cache_key": evidence.cache_key})
                with self._lock:
                    self._redirects += 1
                if target in seen:
                    result = Evidence(requested, current, evidence.status, evidence.headers,
                                      evidence.body, chain, "redirect-loop", "redirect loop")
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
                event.set()
