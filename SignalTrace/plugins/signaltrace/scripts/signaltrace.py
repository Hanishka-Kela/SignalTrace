#!/usr/bin/env python3
"""SignalTrace: bounded public-web evidence audit with one JSON result."""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import sys
import urllib.parse
from typing import Any

from analyzers import (
    bot_directives_audit, content_engagement_audit, deduplicate_findings,
    classify_link, deduplicate_opportunities, destination_observation, finding,
    improvement_opportunity_audit, parse_page, source_verification, structured_data_audit,
    visitor_journey_audit,
)
from runtime import Evidence, LimitError, RequestGovernor, UnsafeTarget
from config import DEFAULTS

CHECKS = [
    "robots-policy", "target-fetch", "bot-directives", "structured-data",
    "content-engagement", "citation-destination", "source-verification",
    "visitor-journey", "improvement-opportunities",
]


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one read-only SignalTrace audit")
    parser.add_argument("site", nargs="?", help="public HTTP(S) target")
    parser.add_argument(
        "--input-stdin", action="store_true",
        help="read one JSON audit envelope from stdin; stdin is otherwise ignored")
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


def _is_html(evidence: Evidence) -> bool:
    media_type = evidence.headers.get("content-type", "").split(";", 1)[0].strip().casefold()
    return bool(evidence.body) and (media_type in {"", "text/html", "application/xhtml+xml"})


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
        url = urllib.parse.urldefrag(link["url"])[0]
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


def _explicit_citations(payload: dict[str, Any], base: str) -> list[dict[str, str]]:
    results = []
    for item in payload.get("citations", []):
        if isinstance(item, str):
            item = {"url": item}
        if not isinstance(item, dict) or not item.get("url"):
            continue
        url = urllib.parse.urljoin(base, str(item["url"]))
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
    if evidence.outcome == "body-limit":
        record["unresolved"].append(
            f"visitor-journey: {link['url']} exceeded the body limit; partial evidence only")
    page = parse_page(evidence.text(), evidence.final_url) if _is_html(evidence) else None
    record["page"] = page
    record["url"] = evidence.final_url
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
    journey_coverage: dict[str, list[dict[str, Any]]] = {
        "selected_links": [], "crawled_links": [], "skipped_links": []}
    try:
        site = governor.normalize_url(requested_site)
    except (UnsafeTarget, ValueError) as exc:
        site = requested_site
        unresolved.extend([f"robots-policy: not assessed: {exc}", "target-fetch: invalid target"])
        return _report(site, governor, findings, completed, unresolved)

    try:
        target = governor.fetch(site)
    except (LimitError, UnsafeTarget) as exc:
        unresolved.extend([f"robots-policy: not completed: {exc}", f"target-fetch: not completed: {exc}"])
        return _report(site, governor, findings, completed, unresolved)

    completed.append("robots-policy")
    if target.outcome == "robots-denied":
        unresolved.extend([
            f"target-fetch: not assessed: {target.detail}",
            "structured-data: not assessed without permitted target evidence",
            "content-engagement: not assessed without permitted target evidence",
            "citation-destination: not assessed without permitted target evidence",
            "source-verification: not assessed because the primary target was unavailable",
        ])
        return _report(site, governor, findings, completed, unresolved)
    if target.status is None:
        unresolved.extend([
            f"target-fetch: unresolved network state: {target.detail}",
            "structured-data: not assessed without target HTML",
            "content-engagement: not assessed without target HTML",
            "citation-destination: not assessed without target HTML",
            "source-verification: primary target unavailable",
        ])
        return _report(site, governor, findings, completed, unresolved)
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
        return _report(site, governor, findings, completed, unresolved)
    if not _is_html(target):
        unresolved.extend([
            "structured-data: target is not an HTML representation",
            "content-engagement: target is not an HTML representation",
            "citation-destination: no HTML links available",
            "source-verification: not assessed for non-HTML primary evidence",
        ])
        return _report(site, governor, findings, completed, unresolved)

    if target.outcome == "body-limit":
        unresolved.append("target-fetch: response exceeded the body limit; checks use only cached partial evidence")

    page = parse_page(target.text(), target.final_url)
    robots_result = governor.robots_result(target.final_url)
    if robots_result.get("result") not in {"allowed", "missing"}:
        unresolved.append(
            f"robots-policy: {robots_result.get('result')}: {robots_result.get('detail')}; "
            "only the governor's permitted bounded behavior can continue")
    citations = _explicit_citations(payload, target.final_url)[:max(0, args.max_link_checks)]
    journey_links, skipped_links = _select_journey_links(page, target.final_url, args.max_link_checks)
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
            pool.submit(bot_directives_audit, page, target.headers, target.final_url, robots_result): "bot-directives",
            pool.submit(structured_data_audit, page, target.final_url): "structured-data",
            pool.submit(content_engagement_audit, page, target.final_url): "content-engagement",
        }
        opportunity_future = pool.submit(improvement_opportunity_audit, page, target.final_url)
        journey_futures = [pool.submit(_fetch_journey, governor, target.final_url, link)
                           for link in journey_links]
        destination_futures = [pool.submit(_audit_destination, governor, target.final_url, link)
                               for link in citations if link["url"] not in {item["url"] for item in journey_links}]
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
            found, suggested, notes = visitor_journey_audit(page, target.final_url, journey_pages)
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
        for future in source_futures:
            try:
                result, note = future.result(timeout=max(.01, governor.remaining_seconds()))
                if result:
                    source_pages.append(result)
                if note:
                    unresolved.append(note)
            except Exception as exc:
                unresolved.append(f"source-verification: fetch did not complete: {exc}")
    found, notes = source_verification(payload.get("claims", []), source_pages, target.final_url)
    findings.extend(found)
    unresolved.extend(notes)
    completed.append("source-verification")
    return _report(site, governor, findings, completed, unresolved, opportunities, journey_coverage)


def _report(site: str, governor: RequestGovernor, findings: list[dict[str, Any]],
            completed: list[str], unresolved: list[str],
            opportunities: list[dict[str, Any]] | None = None,
            journey_coverage: dict[str, list[dict[str, Any]]] | None = None) -> dict[str, Any]:
    findings = deduplicate_findings(findings)
    opportunities = deduplicate_opportunities(opportunities or [])
    counts = {name: sum(1 for item in findings if item["severity"] == name)
              for name in ("Critical", "High", "Medium")}
    snapshot = governor.snapshot()
    try:
        robots_result = governor.robots_result(site)
    except (UnsafeTarget, ValueError):
        robots_result = {"result": "not-checked", "detail": "invalid or unsupported target URL"}
    return {
        "site": site,
        "audited_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "summary": {
            "total_findings": len(findings),
            "critical": counts["Critical"], "high": counts["High"], "medium": counts["Medium"],
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
            "robots_result": robots_result,
            "subagent_facility_available": False,
            "execution_mode": "local",
            "checks_completed": [name for name in CHECKS if name in set(completed)],
            "checks_unresolved": list(dict.fromkeys(unresolved)),
            "unresolved_checks": list(dict.fromkeys(unresolved)),
            "journey": journey_coverage or {
                "selected_links": [], "crawled_links": [], "skipped_links": []},
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
    json.dump(report, sys.stdout, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
