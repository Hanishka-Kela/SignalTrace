#!/usr/bin/env python3
"""SignalTrace: bounded public-web evidence audit with one JSON result."""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import re
import sys
import urllib.parse
from typing import Any

from analyzers import (
    bot_directives_audit, content_engagement_audit, deduplicate_findings,
    classify_link, deduplicate_opportunities, destination_observation, finding,
    improvement_opportunity_audit, opportunity, parse_page, source_verification, structured_data_audit,
    same_as_declarations, same_as_destination_observation, visitor_journey_audit,
    _canonicalize_url_fields, canonicalize_url,
)
from runtime import Evidence, LimitError, RequestGovernor, UnsafeTarget
from config import DEFAULTS

CHECKS = [
    "robots-policy", "target-fetch", "bot-directives", "structured-data",
    "content-engagement", "citation-destination", "source-verification",
    "sameAs-identity", "visitor-journey", "improvement-opportunities",
]

BEHAVIORAL_EVIDENCE_LIMIT = (
    "Actual user behavior, analytics outcomes, visual quality, and sales impact were not measured; "
    "they require browser testing, user testing, analytics, or controlled experiments."
)

_STATIC_RISK_OPPORTUNITIES = {
    "image-only-evidence": {
        "id": "opportunity-media-text-equivalent", "priority": "high",
        "category": "content-clarity",
        "action": "Provide equivalent readable text for factual content carried by images or media.",
        "reason": "The fetched HTML did not expose a readable equivalent for the observed image evidence. "
                  "Behavioral impact was not measured.",
    },
    "oos-no-route": {
        "id": "opportunity-recovery-path", "priority": "high", "category": "availability",
        "action": "Consider exposing a relevant alternative, notification path, or contact route.",
        "reason": "The fetched page did not expose an observable recovery path for its unavailable state. "
                  "Behavioral impact was not measured.",
    },
}


def _separate_static_risks(findings: list[dict[str, Any]],
                           opportunities: list[dict[str, Any]]) -> tuple[list[dict[str, Any]],
                                                                          list[dict[str, Any]]]:
    """Keep observable-but-unverified usability risks out of confirmed findings."""
    confirmed: list[dict[str, Any]] = []
    known = {(item["id"], item["evidence"]["url"]) for item in opportunities}
    for item in findings:
        rule = _STATIC_RISK_OPPORTUNITIES.get(item.get("_code", ""))
        if rule is None:
            confirmed.append(item)
            continue
        key = (rule["id"], item["affected_url"])
        if key not in known:
            opportunities.append(opportunity(
                rule_id=rule["id"], priority=rule["priority"], category=rule["category"],
                action=rule["action"], reason=rule["reason"], url=item["affected_url"],
                source="initial HTML", observed=item["evidence"], confidence="likely"))
            known.add(key)
    return confirmed, opportunities


def _annotate_result_evidence(items: list[dict[str, Any]]) -> None:
    """Record the performed check and the shared interpretation boundary."""
    for item in items:
        check = item.get("_code") or item.get("id") or item.get("title")
        role = str(item.get("page_role") or "")
        if role and isinstance(check, str) and check.endswith(f"-{role}"):
            check = check[:-(len(role) + 1)]
        evidence = item.get("evidence")
        blocks = evidence if isinstance(evidence, list) else [evidence]
        for block in blocks:
            if isinstance(block, dict):
                block.setdefault("check_performed", check)
                block.setdefault("not_verified", BEHAVIORAL_EVIDENCE_LIMIT)


def _consolidate_opportunities(items: list[dict[str, Any]], site: str) -> list[dict[str, Any]]:
    """Merge the same check and root cause across pages into systemic evidence."""
    grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for item in items:
        evidence = item.get("evidence", {})
        family = str(evidence.get("check_performed") or item.get("id") or "")
        key = (family, item.get("category", ""), item.get("action", ""), item.get("reason", ""))
        grouped.setdefault(key, []).append(item)

    consolidated: list[dict[str, Any]] = []
    priority_order = {"high": 0, "medium": 1, "low": 2}
    for key in sorted(grouped):
        group = grouped[key]
        urls = {canonicalize_url(item.get("evidence", {}).get("url", "")) for item in group}
        if len(group) < 2:
            consolidated.extend(group)
            continue
        family = key[0]
        representative = min(group, key=lambda item: json.dumps(
            item, sort_keys=True, separators=(",", ":")))
        merged = dict(representative)
        merged["id"] = family
        merged.pop("page_role", None)
        pages_by_url: dict[str, dict[str, Any]] = {}
        for item in sorted(group, key=lambda value: (
                canonicalize_url(value.get("evidence", {}).get("url", "")),
                value.get("id", ""))):
            evidence = item["evidence"]
            page_url = canonicalize_url(evidence.get("url", ""))
            observed = evidence.get("observed")
            page = pages_by_url.setdefault(page_url, {
                "url": page_url, "source": evidence.get("source", ""),
                "observed": [], "occurrence_count": 0,
            })
            observations = observed if isinstance(observed, list) else [observed]
            def observation_key(value: Any) -> str:
                if isinstance(value, dict):
                    value = {key: item for key, item in value.items()
                             if key != "occurrence_count"}
                return json.dumps(value, sort_keys=True, separators=(",", ":"))
            by_observation = {
                observation_key(value): value
                for value in page["observed"]
            }
            for value in observations:
                if value is None:
                    continue
                marker = observation_key(value)
                prior = by_observation.get(marker)
                if isinstance(value, dict) and isinstance(prior, dict):
                    prior_count = int(prior.get("occurrence_count", 1))
                    value_count = int(value.get("occurrence_count", 1))
                    prior["occurrence_count"] = max(prior_count, value_count)
                elif prior is None:
                    by_observation[marker] = value
            page["observed"] = [by_observation[key] for key in sorted(by_observation)]
            page["occurrence_count"] = max(
                page["occurrence_count"],
                sum(int(value.get("occurrence_count", 1)) if isinstance(value, dict) else 1
                    for value in observations if value is not None))
        pages = list(pages_by_url.values())
        merged["evidence"] = {
            "url": canonicalize_url(site),
            "source": representative["evidence"].get("source", ""),
            "observed": pages,
            "check_performed": family,
            "not_verified": representative["evidence"].get(
                "not_verified", BEHAVIORAL_EVIDENCE_LIMIT),
        }
        merged["priority"] = min(
            (item["priority"] for item in group), key=lambda value: priority_order[value])
        merged["confidence"] = "certain" if all(
            item.get("confidence") == "certain" for item in group) else "likely"
        consolidated.append(merged)
    return consolidated


_PROHIBITED_GENERATED_LANGUAGE = re.compile(
    r"\b(?:users? are confused|visitors? will abandon|this causes? bounce|"
    r"the ui is boring|this reduces? conversions?|customers? cannot use (?:the|this) site|"
    r"visitors? dislike the design|(?:will |guaranteed to )?increase sales)\b", re.I)


def _enforce_evidence_bounded_language(items: list[dict[str, Any]]) -> None:
    """Fail closed to cautious language without altering quoted evidence."""
    for item in items:
        for field in ("title", "reason", "action", "impact"):
            value = item.get(field)
            if isinstance(value, str) and _PROHIBITED_GENERATED_LANGUAGE.search(value):
                item[field] = (
                    "The fetched evidence establishes the reported condition; behavioral impact was not measured."
                    if item.get("is_finding") else
                    "Consider addressing the observed condition; behavioral impact was not measured."
                )
        action = item.get("suggested_action")
        if isinstance(action, dict) and isinstance(action.get("summary"), str):
            if _PROHIBITED_GENERATED_LANGUAGE.search(action["summary"]):
                action["summary"] = (
                    "The fetched evidence establishes the reported condition; behavioral impact was not measured."
                    if item.get("is_finding") else
                    "Consider addressing the observed condition; behavioral impact was not measured."
                )


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one read-only SignalTrace audit")
    parser.add_argument("site", nargs="?", help="public HTTP(S) target")
    parser.add_argument(
        "--input-stdin", action="store_true",
        help="read one JSON audit envelope from stdin; stdin is otherwise ignored")
    parser.add_argument(
        "--pretty", action="store_true",
        help="format the JSON report with two-space indentation")
    parser.add_argument("--max-requests", type=int, default=DEFAULTS.global_request_maximum)
    parser.add_argument("--target-request-maximum", type=int, default=DEFAULTS.target_request_maximum)
    parser.add_argument("--max-concurrency", type=int, default=DEFAULTS.cross_origin_concurrency)
    parser.add_argument("--max-per-origin", type=int, default=DEFAULTS.per_origin_maximum)
    parser.add_argument("--deadline", type=float, default=DEFAULTS.global_deadline_seconds)
    parser.add_argument("--timeout", type=float, default=DEFAULTS.request_timeout_seconds)
    parser.add_argument("--connect-timeout", type=float, default=DEFAULTS.connection_timeout_seconds)
    parser.add_argument("--max-body-bytes", type=int, default=DEFAULTS.response_body_limit_bytes)
    parser.add_argument("--aggregate-body-bytes", type=int, default=DEFAULTS.aggregate_body_limit_bytes)
    parser.add_argument("--spacing", type=float, default=DEFAULTS.same_origin_spacing_seconds)
    parser.add_argument("--retries", type=int, default=DEFAULTS.retries)
    parser.add_argument("--max-redirects", type=int, default=DEFAULTS.maximum_redirects)
    parser.add_argument("--max-link-checks", type=int, default=DEFAULTS.selected_link_maximum)
    return parser.parse_args()


def _input(args: argparse.Namespace) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if args.input_stdin:
        raw = sys.stdin.read().strip()
        if not raw:
            raise ValueError("--input-stdin requires one JSON object on stdin")
        decoded = json.loads(raw)
        if not isinstance(decoded, dict):
            raise ValueError("stdin JSON must be an object")
        payload = decoded
    if args.site:
        payload["site"] = args.site
    if not payload.get("site"):
        raise ValueError("a site URL is required as an argument or stdin JSON field")
    for key in ("sources", "claims", "citations"):
        if key in payload and not isinstance(payload[key], list):
            raise ValueError(f"{key} must be an array")
    return payload


def _source_verification_state(payload: dict[str, Any]) -> tuple[str, str]:
    if not payload.get("claims") and not payload.get("sources"):
        return ("not executed: optional claims/sources envelope absent",
                "source-verification: did not execute; no external claims or sources were supplied for this run")
    return "supplied evidence not independently verified", ""


def _is_html(evidence: Evidence) -> bool:
    media_type = evidence.headers.get("content-type", "").split(";", 1)[0].strip().casefold()
    return bool(evidence.body) and (media_type in {"", "text/html", "application/xhtml+xml"})


_AUTH_GATED_PATHS = {
    "/account", "/login", "/signin", "/cart", "/checkout", "/wishlist",
}


def _is_auth_gated_url(url: str) -> bool:
    path = urllib.parse.urlsplit(url).path.rstrip("/").casefold() or "/"
    return path in _AUTH_GATED_PATHS or path.startswith("/account/")


def _select_journey_links(page, target_url: str, limit: int) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Choose at most one same-origin target-page link per journey role."""
    origin = urllib.parse.urlsplit(target_url).netloc.casefold()
    target_without_fragment = urllib.parse.urldefrag(target_url)[0]
    candidates: dict[str, list[dict[str, str]]] = {
        role: [] for role in ("navigation", "detail", "search", "support", "policy", "other")}
    skipped: list[dict[str, str]] = []
    seen: set[str] = set()
    for link in page.links:
        try:
            parts = urllib.parse.urlsplit(link["url"])
        except ValueError:
            skipped.append({"url": link.get("url", ""), "reason": "invalid URL"})
            continue
        if parts.scheme not in {"http", "https"}:
            skipped.append({"url": link.get("url", ""), "reason": "unsupported scheme"})
            continue
        url = canonicalize_url(urllib.parse.urldefrag(link["url"])[0])
        if url == target_without_fragment:
            skipped.append({"url": url, "reason": "same-page or target URL"})
            continue
        if url in seen:
            skipped.append({"url": url, "reason": "duplicate URL"})
            continue
        seen.add(url)
        if parts.netloc.casefold() != origin:
            skipped.append({"url": url, "reason": "cross-origin link outside journey sample"})
            continue
        if _is_auth_gated_url(url):
            skipped.append({"url": url, "reason": "auth-gated URL excluded from content journey sample"})
            continue
        candidate = dict(link)
        candidate["url"] = url
        candidate["responsible_party"] = "site-published link"
        role = classify_link(candidate)
        target_path = urllib.parse.urlsplit(target_url).path.rstrip("/")
        relative = parts.path[len(target_path):].strip("/") if parts.path.startswith(target_path + "/") else ""
        if (role == "detail" and relative and "/" not in relative
                and not any(token in parts.path.casefold() for token in ("/product/", "/item/", "/detail/"))):
            role = "navigation"
        candidate["role"] = role
        candidates[role].append(candidate)

    # A static GET form action is an inspectable search/action route too.
    for form in page.forms:
        action = urllib.parse.urldefrag(form.get("action", ""))[0]
        parts = urllib.parse.urlsplit(action)
        search_control = any(control.get("type") == "search" or
                             control.get("name", "").casefold() in {"q", "query", "search"}
                             for control in form.get("controls", []))
        if form.get("method") == "get" and search_control and parts.netloc.casefold() == origin and action not in seen:
            candidates["search"].append({
                "url": action, "text": "Search form action", "rel": "", "section": "form",
                "responsible_party": "site-published link", "role": "search",
            })
            seen.add(action)

    selected: list[dict[str, str]] = []
    target_path = urllib.parse.urlsplit(target_url).path.rstrip("/")
    candidates["navigation"].sort(key=lambda item: (
        0 if "/category/" in urllib.parse.urlsplit(item["url"]).path.casefold()
        else 1 if target_path and urllib.parse.urlsplit(item["url"]).path.startswith(target_path + "/")
        else 2 if item.get("section") in {"nav", "header"} else 3,))
    candidates["detail"].sort(key=lambda item: (
        0 if any(token in urllib.parse.urlsplit(item["url"]).path.casefold()
                 for token in ("/product/", "/item/", "/detail/")) else 1,))
    for item in candidates["other"]:
        skipped.append({"url": item["url"], "role": "other",
                        "reason": "link does not match a bounded journey role"})
    for role in ("navigation", "detail", "search", "support", "policy"):
        if candidates[role] and len(selected) < max(0, limit):
            selected.append(candidates[role][0])
            for item in candidates[role][1:]:
                skipped.append({"url": item["url"], "role": role,
                                "reason": "role already represented in bounded sample"})
        else:
            for item in candidates[role]:
                skipped.append({"url": item["url"], "role": role,
                                "reason": "journey sample limit reached"})
    return selected, skipped[:DEFAULTS.skipped_link_evidence_maximum]


def _journey_sample_limit(robots_result: dict[str, str], requested_limit: int) -> int:
    """Reduce, never expand, the sample when no usable robots policy was fetched."""
    requested_limit = max(0, requested_limit)
    return min(1, requested_limit) if robots_result.get("result") == "unavailable" else requested_limit


def _explicit_citations(payload: dict[str, Any], base: str) -> list[dict[str, str]]:
    results = []
    for item in payload.get("citations", []):
        if isinstance(item, str):
            item = {"url": item}
        if not isinstance(item, dict) or not item.get("url"):
            continue
        url = canonicalize_url(urllib.parse.urljoin(base, str(item["url"])))
        party = item.get("responsible_party", "assistant-generated citation")
        if party not in {"site-published link", "external publisher", "assistant-generated citation", "unresolved"}:
            party = "unresolved"
        results.append({
            "url": url,
            "text": str(item.get("claim") or item.get("text") or ""),
            "rel": "",
            "responsible_party": party,
        })
    return results


def _audit_destination(governor: RequestGovernor, source_url: str,
                       link: dict[str, str]) -> tuple[list[dict], list[str]]:
    try:
        evidence = governor.fetch(link["url"])
    except (LimitError, UnsafeTarget) as exc:
        return [], [f"citation-destination: {link['url']} not assessed: {exc}"]
    if evidence.outcome == "body-limit":
        return [], [f"citation-destination: {link['url']} exceeded the response body limit; not assessed"]
    page = parse_page(evidence.text(), evidence.final_url) if _is_html(evidence) else None
    found, unresolved = destination_observation(link, source_url, evidence, page)
    for item in found:
        item["responsible_party"] = link.get("responsible_party", "unresolved")
    return found, unresolved


def _audit_same_as(governor: RequestGovernor, source_url: str,
                   declaration: dict[str, Any]) -> tuple[list[dict], list[str], dict[str, Any]]:
    try:
        evidence = governor.fetch(declaration["url"])
    except (LimitError, UnsafeTarget) as exc:
        return [], [f"sameAs-identity: {declaration['url']} not assessed: {exc}"], {
            "declared_url": declaration["url"], "brand": declaration.get("brand", ""),
            "node_type": declaration.get("node_type"), "block": declaration.get("block"),
            "classification": "not-assessed", "identity_verdict": "not assessed",
            "detail": str(exc),
        }
    if evidence.outcome == "body-limit":
        return [], [f"sameAs-identity: {declaration['url']} exceeded the body limit; not assessed"], {
            "declared_url": declaration["url"], "brand": declaration.get("brand", ""),
            "node_type": declaration.get("node_type"), "block": declaration.get("block"),
            "classification": "inconclusive", "identity_verdict": "not assessed",
            "status": evidence.status, "final_url": evidence.final_url,
            "redirect_chain": evidence.redirect_chain, "detail": evidence.detail,
        }
    page = parse_page(evidence.text(), evidence.final_url) if _is_html(evidence) else None
    return same_as_destination_observation(declaration, source_url, evidence, page)


def _fetch_journey(governor: RequestGovernor, source_url: str,
                   link: dict[str, str]) -> dict[str, Any]:
    """Fetch one entrypoint-selected route; never selects or follows child links."""
    record: dict[str, Any] = {
        "url": link["url"], "role": link.get("role", "other"), "link": link,
        "page": None, "findings": [], "unresolved": [], "skipped": None,
    }
    try:
        evidence = governor.fetch(link["url"])
    except (LimitError, UnsafeTarget) as exc:
        record["skipped"] = str(exc)
        record["unresolved"].append(f"visitor-journey: {link['url']} not assessed: {exc}")
        return record
    record["evidence"] = evidence
    if evidence.outcome == "robots-denied":
        record["skipped"] = "robots.txt denied this link"
        record["unresolved"].append(
            f"visitor-journey: {link['url']} restricted by robots.txt; not fetched")
        return record
    if evidence.outcome in {"blocked", "origin-blocked"} or evidence.status in {403, 429}:
        record["skipped"] = evidence.detail or "origin blocked or unavailable"
        record["unresolved"].append(
            f"visitor-journey: {link['url']} blocked or unavailable; not assessed")
        return record
    if evidence.outcome == "body-limit":
        record["unresolved"].append(
            f"visitor-journey: {link['url']} exceeded the body limit; partial evidence only")
    page = parse_page(evidence.text(), evidence.final_url) if _is_html(evidence) else None
    record["page"] = page
    record["url"] = canonicalize_url(evidence.final_url)
    found, notes = destination_observation(link, source_url, evidence, page)
    for item in found:
        item["responsible_party"] = "site-published link"
    record["findings"].extend(found)
    record["unresolved"].extend(notes)
    if page is None and not record["skipped"]:
        record["skipped"] = "no usable HTML representation"
    return record


def _fetch_source(governor: RequestGovernor, url: str):
    try:
        evidence = governor.fetch(url)
    except (LimitError, UnsafeTarget) as exc:
        return None, f"source-verification: {url} not assessed: {exc}"
    if evidence.outcome == "robots-denied":
        return None, f"source-verification: {url} restricted by robots; not assessed"
    if evidence.outcome in {"blocked", "origin-blocked"} or evidence.status in {403, 429}:
        return None, f"source-verification: {url} blocked or unavailable; not assessed"
    if evidence.outcome == "body-limit":
        return None, f"source-verification: {url} exceeded the response body limit; not assessed"
    if evidence.status != 200 or not _is_html(evidence):
        return None, f"source-verification: {url} has no usable public HTML evidence"
    page = parse_page(evidence.text(), evidence.final_url)
    words = len(page.visible_text.split())
    if words < 12:
        state = "placeholder, locked, or image-only" if page.images or page.controls else "insufficient"
        return None, f"source-verification: {url} has {state} evidence; not assessed"
    if not (page.title or any(h["level"] == "h1" and h["text"] for h in page.headings)):
        return None, f"source-verification: {url} has ambiguous source identity; not assessed"
    return (evidence.final_url, page), None


def run(payload: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    # Construction starts the deadline before URL normalization, DNS, or any network work.
    governor = RequestGovernor(
        max_requests=max(1, min(args.max_requests, 100)),
        target_request_maximum=max(1, min(args.target_request_maximum, 100)),
        max_concurrency=max(1, min(args.max_concurrency, 2)),
        timeout=max(.1, min(args.timeout, 60.0)),
        connect_timeout=max(.1, min(args.connect_timeout, 30.0)),
        max_body_bytes=max(1024, min(args.max_body_bytes, 10_000_000)),
        aggregate_body_bytes=max(1024, min(args.aggregate_body_bytes, 100_000_000)),
        deadline_seconds=max(.1, min(args.deadline, 300.0)),
        max_per_origin=max(2, min(args.max_per_origin, 50)),
        spacing_seconds=max(0.0, min(args.spacing, 60.0)),
        retries=max(0, min(args.retries, 3)),
        max_redirects=max(0, min(args.max_redirects, 10)),
    )
    requested_site = str(payload["site"])
    findings: list[dict[str, Any]] = []
    opportunities: list[dict[str, Any]] = []
    completed, unresolved = [], []
    source_verification_status, source_note = _source_verification_state(payload)
    if source_note:
        unresolved.append(source_note)
    journey_coverage: dict[str, list[dict[str, Any]]] = {
        "selected_links": [], "crawled_links": [], "skipped_links": []}
    same_as_coverage: dict[str, Any] = {
        "status": "not assessed", "declared": 0, "results": []}
    try:
        site = governor.normalize_url(requested_site)
    except (UnsafeTarget, ValueError) as exc:
        site = requested_site
        unresolved.extend([f"robots-policy: not assessed: {exc}", "target-fetch: invalid target"])
        return _report(site, governor, findings, completed, unresolved,
                   source_verification_status=source_verification_status)

    try:
        target = governor.fetch(site)
    except (LimitError, UnsafeTarget) as exc:
        unresolved.extend([f"robots-policy: not completed: {exc}", f"target-fetch: not completed: {exc}"])
        return _report(site, governor, findings, completed, unresolved,
                   source_verification_status=source_verification_status)

    completed.append("robots-policy")
    if target.outcome == "robots-denied":
        unresolved.extend([
            f"target-fetch: not assessed: {target.detail}",
            "structured-data: not assessed without permitted target evidence",
            "content-engagement: not assessed without permitted target evidence",
            "citation-destination: not assessed without permitted target evidence",
            "sameAs-identity: not assessed without permitted target evidence",
            "source-verification: not assessed because the primary target was unavailable",
        ])
        return _report(site, governor, findings, completed, unresolved,
                   source_verification_status=source_verification_status)
    if target.outcome in {"blocked", "origin-blocked"} or target.status in {403, 429}:
        unresolved.extend([
            f"target-fetch: blocked or unavailable: {target.detail or ('HTTP ' + str(target.status))}",
            "structured-data: not assessed without usable target HTML",
            "content-engagement: not assessed without usable target HTML",
            "citation-destination: not assessed without usable target HTML",
            "sameAs-identity: not assessed without usable target HTML",
            "source-verification: primary target blocked or unavailable",
        ])
        return _report(site, governor, findings, completed, unresolved,
                   source_verification_status=source_verification_status)
    if target.status is None:
        unresolved.extend([
            f"target-fetch: unresolved network state: {target.detail}",
            "structured-data: not assessed without target HTML",
            "content-engagement: not assessed without target HTML",
            "citation-destination: not assessed without target HTML",
            "sameAs-identity: not assessed without target HTML",
            "source-verification: primary target unavailable",
        ])
        return _report(site, governor, findings, completed, unresolved,
                   source_verification_status=source_verification_status)
    completed.append("target-fetch")
    if target.status >= 400:
        if target.status in {404, 410}:
            findings.append(finding(
                code="primary-target-missing", title="Explicitly scoped primary page is missing",
                severity="Critical", confidence=1.0,
                evidence={"requested_url": site, "final_url": target.final_url,
                          "status": target.status, "redirect_chain": target.redirect_chain},
                affected_url=site, evidence_type="http-destination-chain",
                responsible_party="unresolved",
                impact="The complete explicitly scoped audit destination and visitor task are blocked.",
                suggested_action="Restore the page or publish a clear, relevant successor at the cited route.",
                priority=100))
        else:
            unresolved.append(f"target-fetch: HTTP {target.status}; representation checks not assessed")
        return _report(site, governor, findings, completed, unresolved,
                   source_verification_status=source_verification_status)
    if not _is_html(target):
        unresolved.extend([
            "structured-data: target is not an HTML representation",
            "content-engagement: target is not an HTML representation",
            "citation-destination: no HTML links available",
            "sameAs-identity: target is not an HTML representation",
            "source-verification: not assessed for non-HTML primary evidence",
        ])
        return _report(site, governor, findings, completed, unresolved,
                   source_verification_status=source_verification_status)

    if target.outcome == "body-limit":
        unresolved.append("target-fetch: response exceeded the body limit; checks use only cached partial evidence")

    target_url = canonicalize_url(target.final_url)
    page = parse_page(target.text(), target_url)
    same_as_items, same_as_notes, same_as_applicability = same_as_declarations(page, target_url)
    same_as_coverage["declared"] = len(same_as_items)
    same_as_coverage["status"] = same_as_applicability
    unresolved.extend(same_as_notes)
    if not same_as_items:
        completed.append("sameAs-identity")
    robots_result = governor.robots_result(target.final_url)
    if robots_result.get("result") not in {"allowed", "missing"}:
        unresolved.append(
            f"robots-policy: {robots_result.get('result')}: {robots_result.get('detail')}; "
            "only the governor's permitted bounded behavior can continue")
    citations = _explicit_citations(payload, target_url)[:max(0, args.max_link_checks)]
    journey_limit = _journey_sample_limit(robots_result, args.max_link_checks)
    journey_links, skipped_links = _select_journey_links(page, target_url, journey_limit)
    journey_coverage["selected_links"] = [
        {"url": item["url"], "role": item.get("role", "other"),
         "label": item.get("text", "")} for item in journey_links]
    journey_coverage["skipped_links"].extend(skipped_links)
    sources = list(dict.fromkeys(str(item) for item in payload.get("sources", []) if isinstance(item, str)))
    linked_urls = {item["url"] for item in citations + journey_links}
    sources = [item for item in sources if item not in linked_urls]
    source_pages = []
    journey_pages: list[dict[str, Any]] = []

    # Local parsing begins in parallel with independent, bounded network evidence tasks.
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(args.max_concurrency, 10))) as pool:
        local_futures = {
            pool.submit(bot_directives_audit, page, target.headers, target_url, robots_result): "bot-directives",
            pool.submit(structured_data_audit, page, target_url): "structured-data",
            pool.submit(content_engagement_audit, page, target_url): "content-engagement",
        }
        opportunity_future = pool.submit(improvement_opportunity_audit, page, target_url)
        journey_futures = [pool.submit(_fetch_journey, governor, target_url, link)
                           for link in journey_links]
        destination_futures = [pool.submit(_audit_destination, governor, target_url, link)
                               for link in citations if link["url"] not in {item["url"] for item in journey_links}]
        same_as_futures = [pool.submit(_audit_same_as, governor, target_url, item)
                           for item in same_as_items]
        source_futures = [pool.submit(_fetch_source, governor, url) for url in sources]
        for future, name in local_futures.items():
            try:
                found, notes = future.result(timeout=max(.01, governor.remaining_seconds()))
                findings.extend(found)
                unresolved.extend(notes)
                completed.append(name)
            except Exception as exc:
                unresolved.append(f"{name}: analyzer did not complete: {exc}")
        try:
            opportunities.extend(
                opportunity_future.result(timeout=max(.01, governor.remaining_seconds())))
            completed.append("improvement-opportunities")
        except Exception as exc:
            unresolved.append(f"improvement-opportunities: analyzer did not complete: {exc}")
        for future in journey_futures:
            try:
                record = future.result(timeout=max(.01, governor.remaining_seconds()))
                findings.extend(record["findings"])
                unresolved.extend(record["unresolved"])
                if record.get("skipped"):
                    journey_coverage["skipped_links"].append({
                        "url": record["link"]["url"], "role": record["role"],
                        "reason": record["skipped"]})
                else:
                    evidence = record["evidence"]
                    journey_coverage["crawled_links"].append({
                        "url": record["link"]["url"], "role": record["role"],
                        "final_url": evidence.final_url, "status": evidence.status,
                        "outcome": evidence.outcome})
                    journey_pages.append(record)
            except Exception as exc:
                unresolved.append(f"visitor-journey: check did not complete: {exc}")
        try:
            found, suggested, notes = visitor_journey_audit(page, target_url, journey_pages)
            findings.extend(found)
            opportunities.extend(suggested)
            unresolved.extend(notes)
            for record in journey_pages:
                opportunities.extend(improvement_opportunity_audit(
                    record["page"], record["url"], "sampled internal page"))
            completed.append("visitor-journey")
        except Exception as exc:
            unresolved.append(f"visitor-journey: analyzer did not complete: {exc}")
        for future in destination_futures:
            try:
                found, notes = future.result(timeout=max(.01, governor.remaining_seconds()))
                findings.extend(found)
                unresolved.extend(notes)
            except Exception as exc:
                unresolved.append(f"citation-destination: check did not complete: {exc}")
        completed.append("citation-destination")
        same_as_has_finding = False
        same_as_incomplete = bool(same_as_notes)
        for future in same_as_futures:
            try:
                found, notes, result = future.result(timeout=max(.01, governor.remaining_seconds()))
                findings.extend(found)
                unresolved.extend(notes)
                same_as_coverage["results"].append(result)
                same_as_has_finding = same_as_has_finding or bool(found)
                same_as_incomplete = same_as_incomplete or bool(notes)
            except Exception as exc:
                same_as_incomplete = True
                unresolved.append(f"sameAs-identity: check did not complete: {exc}")
        if same_as_items:
            same_as_coverage["status"] = (
                "confirmed finding" if same_as_has_finding else
                "inconclusive" if same_as_incomplete else "passed")
            completed.append("sameAs-identity")
        for future in source_futures:
            try:
                result, note = future.result(timeout=max(.01, governor.remaining_seconds()))
                if result:
                    source_pages.append(result)
                if note:
                    unresolved.append(note)
            except Exception as exc:
                unresolved.append(f"source-verification: fetch did not complete: {exc}")
    supplied_claims = payload.get("claims", [])
    supplied_sources = payload.get("sources", [])
    if supplied_claims or supplied_sources:
        found, notes = source_verification(supplied_claims, source_pages, target_url)
        findings.extend(found)
        unresolved.extend(notes)
        source_verification_status = "assessed" if source_pages else "supplied evidence not independently verified"
    completed.append("source-verification")
    return _report(site, governor, findings, completed, unresolved, opportunities,
                   journey_coverage, same_as_coverage, source_verification_status)


def _report(site: str, governor: RequestGovernor, findings: list[dict[str, Any]],
            completed: list[str], unresolved: list[str],
            opportunities: list[dict[str, Any]] | None = None,
            journey_coverage: dict[str, list[dict[str, Any]]] | None = None,
            same_as_coverage: dict[str, Any] | None = None,
            source_verification_status: str = "not assessed") -> dict[str, Any]:
    opportunities = opportunities or []
    findings, opportunities = _separate_static_risks(findings, opportunities)
    _annotate_result_evidence(findings)
    _annotate_result_evidence(opportunities)
    opportunities = _consolidate_opportunities(opportunities, site)
    _enforce_evidence_bounded_language(findings)
    _enforce_evidence_bounded_language(opportunities)
    findings = deduplicate_findings(findings)
    opportunities = deduplicate_opportunities(opportunities)
    findings = _canonicalize_url_fields(findings)
    opportunities = _canonicalize_url_fields(opportunities)
    counts = {name: sum(1 for item in findings if item["severity"] == name)
              for name in ("critical", "high", "medium")}
    snapshot = governor.snapshot()
    incomplete = snapshot["response_bytes_cached"] == 0
    audit_note = (
        "Primary target produced zero cached response bytes after retries and fallbacks; "
        "coverage is incomplete and no content findings were assessed."
        if incomplete else "")
    try:
        robots_result = governor.robots_result(site)
        crawl_policy = governor.crawl_policy(site)
    except (UnsafeTarget, ValueError):
        robots_result = {"result": "not-checked", "detail": "invalid or unsupported target URL"}
        crawl_policy = {
            "name": "not-checked", "unrestricted": False,
            "reason": "No supported public target was available; no crawling was authorized",
        }
    return {
        "site": site,
        "audited_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "summary": {
            "total_findings": len(findings),
            "critical": counts["critical"], "high": counts["high"], "medium": counts["medium"],
            "audit_note": audit_note,
        },
        "coverage": {
            "requests_started": snapshot["requests_started"],
            "requests_completed": snapshot["requests_completed"],
            "requests_skipped": snapshot["requests_skipped"],
            "target_requests_started": snapshot["target_requests_started"],
            "redirects_observed": snapshot["redirects_observed"],
            "retries_started": snapshot["retries_started"],
            "response_bytes_cached": snapshot["response_bytes_cached"],
            "elapsed_seconds": snapshot["elapsed_seconds"],
            "audit_completeness": "incomplete" if incomplete else "assessed",
            "robots_result": robots_result,
            "crawl_policy": crawl_policy,
            "origins_stopped": snapshot["origins_stopped"],
            "subagent_facility_available": False,
            "execution_mode": "local",
            "behavioral_impact": {
                "status": "not measured",
                "detail": BEHAVIORAL_EVIDENCE_LIMIT,
            },
            "checks_completed": [name for name in CHECKS if name in set(completed)],
            "checks_unresolved": list(dict.fromkeys(unresolved)),
            "journey": journey_coverage or {
                "selected_links": [], "crawled_links": [], "skipped_links": []},
            "sameAs_identity": same_as_coverage or {
                "status": "not assessed", "declared": 0, "results": []},
            "source_verification": {"status": source_verification_status},
        },
        "findings": findings,
        "suggested_actions": opportunities,
    }


def main() -> int:
    args = _arguments()
    try:
        payload = _input(args)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"signaltrace: invalid input: {exc}", file=sys.stderr)
        return 2
    report = run(payload, args)
    if args.pretty:
        json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
    else:
        json.dump(report, sys.stdout, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
