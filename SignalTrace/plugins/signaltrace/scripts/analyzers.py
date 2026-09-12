#!/usr/bin/env python3
"""Local SignalTrace specialist analyzers. No network operations live here."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from html.parser import HTMLParser
from typing import Any, Iterable

from scope import compare_scopes, normalize_scope


def compact(value: str, limit: int = 280) -> str:
    value = re.sub(r"\s+", " ", value or "").strip()
    return value if len(value) <= limit else value[:limit - 1] + "…"


def finding(*, code: str, title: str, severity: str, confidence: float,
            evidence: Any, affected_url: str, evidence_type: str,
            responsible_party: str, impact: str, suggested_action: str,
            priority: int, coverage_status: str = "confirmed") -> dict[str, Any]:
    stable = "|".join((code, affected_url, json.dumps(evidence, sort_keys=True)))
    return {
        "id": "ST-" + hashlib.sha256(stable.encode()).hexdigest()[:10].upper(),
        "title": title,
        "severity": severity,
        "confidence": round(max(0.0, min(1.0, confidence)), 2),
        "evidence": evidence,
        "affected_url": affected_url,
        "evidence_type": evidence_type,
        "responsible_party": responsible_party,
        "impact": impact,
        "suggested_action": suggested_action,
        "priority": priority,
        "coverage_status": coverage_status,
        "_code": code,
    }


def opportunity(*, rule_id: str, priority: str, category: str, action: str,
                reason: str, url: str, source: str, observed: str,
                confidence: str) -> dict[str, Any]:
    """Build a non-finding recommendation from a concrete cached observation."""
    return {
        "id": rule_id,
        "priority": priority,
        "category": category,
        "action": action,
        "reason": reason,
        "evidence": {"url": url, "source": source, "observed": compact(observed)},
        "confidence": confidence,
        "is_finding": False,
    }


class PageParser(HTMLParser):
    HIDDEN_ATTRS = {"hidden", "aria-hidden"}

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title = ""
        self.meta: dict[str, str] = {}
        self.links: list[dict[str, str]] = []
        self.headings: list[dict[str, str]] = []
        self.images: list[dict[str, str]] = []
        self.controls: list[dict[str, str]] = []
        self.jsonld: list[str] = []
        self.microdata = 0
        self.rdfa = 0
        self.canonicals: list[str] = []
        self.visible_chunks: list[str] = []
        self.script_chars = 0
        self._stack: list[dict[str, Any]] = []
        self._jsonld_buffer: list[str] | None = None

    def handle_starttag(self, tag: str, attrs_list):
        attrs = {k.lower(): (v or "") for k, v in attrs_list}
        tag = tag.lower()
        hidden = any(item.get("hidden") for item in self._stack)
        hidden = hidden or tag in {"script", "style", "template", "noscript", "svg"}
        hidden = hidden or "hidden" in attrs or attrs.get("aria-hidden", "").lower() == "true"
        node = {"tag": tag, "attrs": attrs, "text": [], "hidden": hidden}
        self._stack.append(node)
        if "itemscope" in attrs or "itemtype" in attrs or "itemprop" in attrs:
            self.microdata += 1
        if any(key in attrs for key in ("typeof", "property", "vocab", "resource")):
            self.rdfa += 1
        if tag == "meta":
            key = attrs.get("name") or attrs.get("property")
            if key:
                self.meta[key.casefold()] = attrs.get("content", "")
        if tag == "link" and "canonical" in attrs.get("rel", "").casefold().split():
            if attrs.get("href"):
                self.canonicals.append(urllib.parse.urljoin(self.base_url, attrs["href"]))
        if tag == "img":
            self.images.append({k: attrs.get(k, "") for k in ("src", "alt", "title")})
        if tag == "script" and attrs.get("type", "").split(";", 1)[0].strip().casefold() == "application/ld+json":
            self._jsonld_buffer = []

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data: str):
        if not self._stack:
            return
        node = self._stack[-1]
        for ancestor in self._stack:
            ancestor["text"].append(data)
        if node["tag"] == "script":
            self.script_chars += len(data)
            if self._jsonld_buffer is not None:
                self._jsonld_buffer.append(data)
        if not node["hidden"] and data.strip():
            self.visible_chunks.append(data)

    def handle_endtag(self, tag: str):
        tag = tag.lower()
        index = next((i for i in range(len(self._stack) - 1, -1, -1)
                      if self._stack[i]["tag"] == tag), None)
        if index is None:
            return
        nodes = self._stack[index:]
        del self._stack[index:]
        node = nodes[0]
        text = compact(" ".join(node["text"]))
        attrs = node["attrs"]
        if tag == "title":
            self.title = text
        elif tag == "a" and attrs.get("href"):
            self.links.append({
                "url": urllib.parse.urljoin(self.base_url, attrs["href"]),
                "text": text,
                "rel": attrs.get("rel", ""),
            })
        elif re.fullmatch(r"h[1-6]", tag):
            self.headings.append({"level": tag, "text": text})
        elif tag in {"button", "input", "select"}:
            self.controls.append({
                "tag": tag, "text": text or attrs.get("value", ""),
                "aria_label": attrs.get("aria-label", ""),
                "disabled": "true" if "disabled" in attrs else "false",
            })
        if tag == "script" and self._jsonld_buffer is not None:
            self.jsonld.append("".join(self._jsonld_buffer).strip())
            self._jsonld_buffer = None

    @property
    def visible_text(self) -> str:
        return compact(" ".join(self.visible_chunks), 200000)


def parse_page(html: str, url: str) -> PageParser:
    parser = PageParser(url)
    parser.feed(html)
    parser.close()
    return parser


def _walk_jsonld(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, list):
        for item in value:
            yield from _walk_jsonld(item)
    elif isinstance(value, dict):
        if "@type" in value or "@id" in value:
            yield value
        graph = value.get("@graph")
        if graph is not None:
            yield from _walk_jsonld(graph)


def _types(node: dict[str, Any]) -> set[str]:
    value = node.get("@type", [])
    if isinstance(value, str):
        value = [value]
    return {str(item).rsplit("/", 1)[-1].casefold() for item in value}


def structured_data_audit(page: PageParser, url: str) -> tuple[list[dict], list[str]]:
    findings, unresolved = [], []
    parsed_nodes: list[tuple[int, dict[str, Any]]] = []
    for index, raw in enumerate(page.jsonld, 1):
        if not raw:
            findings.append(finding(
                code="jsonld-empty", title="JSON-LD block is empty", severity="Medium",
                confidence=1.0, evidence={"block": index, "excerpt": ""}, affected_url=url,
                evidence_type="initial-html/json-ld", responsible_party="site-published link",
                impact="A machine-readable representation is present but cannot be parsed.",
                suggested_action=f"Remove or populate JSON-LD block {index} with valid scoped data.", priority=60))
            continue
        try:
            data = json.loads(raw)
            parsed_nodes.extend((index, node) for node in _walk_jsonld(data))
        except json.JSONDecodeError as exc:
            findings.append(finding(
                code="jsonld-invalid", title="JSON-LD block contains invalid JSON", severity="Medium",
                confidence=1.0,
                evidence={"block": index, "line": exc.lineno, "column": exc.colno,
                          "message": exc.msg, "excerpt": compact(raw)}, affected_url=url,
                evidence_type="initial-html/json-ld", responsible_party="site-published link",
                impact="Consumers cannot parse this structured-data block.",
                suggested_action=f"Correct JSON syntax in JSON-LD block {index} at line {exc.lineno}, column {exc.colno}.",
                priority=65))
    rules = {
        "product": (("name",), ("offers", "aggregateRating", "review", "sku", "description")),
        "article": (("headline",), ()),
        "newsarticle": (("headline",), ()),
        "blogposting": (("headline",), ()),
        "recipe": (("name", "recipeIngredient"), ()),
        "organization": (("name",), ()),
        "breadcrumblist": (("itemListElement",), ()),
    }
    for block, node in parsed_nodes:
        for node_type in sorted(_types(node) & rules.keys()):
            required, one_of = rules[node_type]
            missing = [prop for prop in required if not node.get(prop)]
            if one_of and not any(node.get(prop) for prop in one_of):
                missing.append("one of: " + ", ".join(one_of))
            if missing:
                findings.append(finding(
                    code=f"schema-minimum-{node_type}",
                    title=f"{node_type} node lacks feature-minimum evidence",
                    severity="Medium", confidence=.91,
                    evidence={"block": block, "type": node.get("@type"), "missing": missing,
                              "id": node.get("@id")}, affected_url=url,
                    evidence_type="initial-html/json-ld", responsible_party="site-published link",
                    impact="The declared entity is incomplete for its represented feature.",
                    suggested_action=f"Add the supported {', '.join(missing)} evidence to this {node_type} node, or remove the unsupported type.",
                    priority=55))
        if "offer" in _types(node) and node.get("price") not in (None, "") and not node.get("priceCurrency"):
            findings.append(finding(
                code="offer-currency", title="Offer price has no currency scope", severity="Medium",
                confidence=.96, evidence={"block": block, "type": node.get("@type"),
                                          "price": node.get("price"), "missing": "priceCurrency"},
                affected_url=url, evidence_type="initial-html/json-ld",
                responsible_party="site-published link",
                impact="The numerical price cannot be interpreted at the required currency scope.",
                suggested_action="Add priceCurrency matching the visible, region-specific offer.", priority=70))
    if not page.jsonld and not page.microdata and not page.rdfa:
        unresolved.append("structured-data: no machine-readable representation observed; improvement only, not a finding")
    return findings, unresolved


def content_engagement_audit(page: PageParser, url: str) -> tuple[list[dict], list[str]]:
    findings, unresolved = [], []
    text = page.visible_text
    word_count = len(re.findall(r"\b\w+\b", text))
    meaningful_links = [item for item in page.links if item["text"].strip()]
    if word_count < 25 and page.script_chars > max(1500, len(text) * 8):
        findings.append(finding(
            code="initial-html-answer-empty", title="Initial HTML contains no substantial answer-bearing text",
            severity="Medium", confidence=.9,
            evidence={"readable_word_count": word_count, "script_characters": page.script_chars,
                      "title": page.title, "text_excerpt": compact(text)}, affected_url=url,
            evidence_type="initial-html", responsible_party="site-published link",
            impact="A text-only consumer receives an app shell or very thin representation instead of a supported answer.",
            suggested_action="Include the page's primary answer and entity identity in the initial HTML while retaining progressive enhancement.",
            priority=75))
    image_facts = [img for img in page.images if not img.get("alt") and (img.get("src") or img.get("title"))]
    if word_count < 40 and image_facts and not page.headings:
        findings.append(finding(
            code="image-only-evidence", title="Primary representation appears image-dependent without text alternatives",
            severity="Medium", confidence=.76,
            evidence={"readable_word_count": word_count, "images_without_alt": image_facts[:3]},
            affected_url=url, evidence_type="initial-html/accessibility",
            responsible_party="site-published link",
            impact="Important identity or task evidence may be unavailable to non-visual consumers.",
            suggested_action="Provide concise text and meaningful alternatives for evidence currently carried only by images.",
            priority=58))
    commerce_words = re.search(r"\b(out of stock|sold out|unavailable)\b", text, re.I)
    continuation = re.search(r"\b(notify|email me|similar|alternative|back in stock|choose another)\b", text, re.I)
    if commerce_words and not continuation and not meaningful_links:
        findings.append(finding(
            code="oos-no-route", title="Out-of-stock state has no observed continuation route",
            severity="Medium", confidence=.88,
            evidence={"state": commerce_words.group(0), "links_with_text": 0,
                      "text_excerpt": compact(text)}, affected_url=url,
            evidence_type="initial-html/visible-text", responsible_party="site-published link",
            impact="A referred visitor reaches a known unavailable state with no usable next action in the fetched representation.",
            suggested_action="Expose a relevant alternative, variant selector, or existing notification path as a normal link or accessible control.",
            priority=68))
    if word_count < 25 and page.script_chars:
        unresolved.append("content-engagement: runtime JavaScript behavior not assessed; hydration markers alone do not prove breakage")
    return findings, unresolved


def bot_directives_audit(page: PageParser, headers: dict[str, str], url: str,
                         robots_result: dict[str, str]) -> tuple[list[dict], list[str]]:
    """Evaluate cached search directives without creating a sixth skill."""
    findings, unresolved = [], []
    directives = []
    if page.meta.get("robots"):
        directives.extend(re.split(r"[,\s]+", page.meta["robots"].casefold()))
    if headers.get("x-robots-tag"):
        directives.extend(re.split(r"[,\s]+", headers["x-robots-tag"].casefold()))
    directives = [item for item in directives if item]
    if "index" in directives and "noindex" in directives:
        findings.append(finding(
            code="conflicting-index-directives",
            title="Initial response publishes conflicting index directives",
            severity="Medium", confidence=.98,
            evidence={"meta_robots": page.meta.get("robots"),
                      "x_robots_tag": headers.get("x-robots-tag")},
            affected_url=url, evidence_type="http-headers/initial-html",
            responsible_party="site-published link",
            impact="Automated consumers receive contradictory eligibility instructions.",
            suggested_action="Publish one intentional index eligibility directive consistently in HTML and HTTP headers.",
            priority=64))
    elif "noindex" in directives:
        unresolved.append("bot-directives: noindex observed; treated as a deliberate restriction, not a defect")
    if robots_result.get("result") == "denied":
        unresolved.append("bot-directives: target denied by robots.txt; deliberate restriction is not a finding")
    return findings, unresolved


def improvement_opportunity_audit(page: PageParser, url: str) -> list[dict[str, Any]]:
    """Emit conservative opportunities using only the cached initial representation."""
    items: list[dict[str, Any]] = []
    text = page.visible_text
    text_folded = text.casefold()
    headings_text = " ".join(item["text"] for item in page.headings if item["text"])
    title_and_headings = f"{page.title} {headings_text}".casefold()

    if not page.jsonld and not page.microdata and not page.rdfa:
        items.append(opportunity(
            rule_id="opportunity-structured-data", priority="low",
            category="ai-discoverability",
            action="Add appropriate machine-readable entity metadata.",
            reason="No JSON-LD, Microdata, or RDFa was observed in the fetched HTML.",
            url=url, source="initial HTML", observed="No machine-readable metadata detected",
            confidence="certain"))

    factual_images = []
    for image in page.images:
        descriptor = compact(image.get("alt") or image.get("title") or "")
        factual = bool(re.search(
            r"(?:\b\d+(?:[.,]\d+)?\s*(?:%|kg|g|mg|lb|oz|cm|mm|m|gb|mb|hours?|mins?)\b|[$€£₹]\s*\d|\b(?:price|calories|dimensions?|specifications?|rating)\b)",
            descriptor, re.I))
        if descriptor and factual and descriptor.casefold() not in text_folded:
            factual_images.append({"src": image.get("src", ""), "descriptor": descriptor})
    if factual_images:
        items.append(opportunity(
            rule_id="opportunity-media-text-equivalent", priority="high",
            category="content-clarity",
            action="Provide equivalent visible text for factual content carried by images or media.",
            reason="A factual image description was observed without equivalent wording in the visible page text.",
            url=url, source="initial HTML", observed=json.dumps(factual_images[:3], sort_keys=True),
            confidence="likely"))

    supported_label = re.search(
        r"\b(?:product|service|guide|article|documentation)\s*:\s*([A-Z][A-Za-z0-9][A-Za-z0-9 .&-]{2,48})",
        text)
    if supported_label:
        term = compact(supported_label.group(1)).rstrip(". ")
        if term and term.casefold() not in title_and_headings:
            items.append(opportunity(
                rule_id="opportunity-terminology-alignment", priority="medium",
                category="content-clarity",
                action="Align the page title or a primary heading with the clearly named subject in the page text.",
                reason="The visible page names a subject that is absent from the title and headings.",
                url=url, source="initial HTML",
                observed=f"Visible subject '{term}'; title/headings '{compact(page.title + ' ' + headings_text)}'",
                confidence="likely"))

    first_heading = page.headings[0]["text"] if page.headings else ""
    if first_heading and first_heading in page.visible_chunks:
        heading_index = page.visible_chunks.index(first_heading)
        preceding_words = len(" ".join(page.visible_chunks[:heading_index]).split())
        if preceding_words >= 150:
            items.append(opportunity(
                rule_id="opportunity-answer-prominence", priority="medium",
                category="engagement",
                action="Move the page's key answer or identifying facts earlier in the initial representation.",
                reason="The first observed heading follows substantial visible text.",
                url=url, source="initial HTML",
                observed=f"{preceding_words} visible words precede the first heading '{compact(first_heading)}'",
                confidence="likely"))

    unavailable = re.search(r"\b(out of stock|sold out|currently unavailable|service unavailable)\b", text, re.I)
    recovery_terms = re.search(
        r"\b(waitlist|notify|email me|back in stock|alternative|similar|other option|contact us)\b",
        text, re.I)
    recovery_link = any(re.search(
        r"\b(waitlist|notify|alternative|similar|contact|other option)\b", item.get("text", ""), re.I)
        for item in page.links)
    if unavailable and not recovery_terms and not recovery_link:
        items.append(opportunity(
            rule_id="opportunity-recovery-path", priority="high", category="engagement",
            action="Provide an explicit recovery path for the visibly unavailable offering.",
            reason="An unavailable state was observed without a waitlist, notification, contact, or alternative path.",
            url=url, source="initial HTML", observed=unavailable.group(0), confidence="certain"))

    time_sensitive = re.search(
        r"\b(updated regularly|latest|current as of|today(?:'s)?|availability may change|schedule)\b",
        text, re.I)
    freshness = any(key in page.meta for key in (
        "article:published_time", "article:modified_time", "date", "last-modified")) or any(
            re.search(r'"date(?:Published|Modified)"\s*:', block) for block in page.jsonld)
    if time_sensitive and not freshness:
        items.append(opportunity(
            rule_id="opportunity-freshness-signal", priority="medium", category="trust",
            action="Add a suitable visible and machine-readable publication or modification date.",
            reason="Time-sensitive wording was observed without a publication or modification signal.",
            url=url, source="initial HTML", observed=compact(time_sensitive.group(0)),
            confidence="likely"))

    meaningful_links = [item for item in page.links if item.get("text", "").strip()]
    next_action = any(re.search(
        r"\b(read more|learn more|get started|contact|download|apply|book|compare|view|continue)\b",
        item.get("text", ""), re.I) for item in meaningful_links)
    if len(meaningful_links) >= 3 and len(text.split()) >= 40 and not next_action:
        items.append(opportunity(
            rule_id="opportunity-clear-next-action", priority="low", category="engagement",
            action="Add a clearer continuation link aligned with the page's stated purpose.",
            reason="Navigation links were observed, but none describes a clear task-relevant continuation.",
            url=url, source="observed link",
            observed="Link labels: " + ", ".join(compact(item["text"], 40) for item in meaningful_links[:6]),
            confidence="likely"))

    attribute_prose = re.search(
        r"\b(?:price|size|weight|duration|compatibility|includes|features?|requirements?)\s*(?:is|:)",
        text, re.I)
    product_or_service = re.search(r"\b(product|service|plan|offering)\b", text, re.I)
    structured_section = re.search(r"\b(specifications?|features?|compare|attributes?)\b", headings_text, re.I)
    if attribute_prose and product_or_service and not structured_section:
        items.append(opportunity(
            rule_id="opportunity-structured-attributes", priority="low",
            category="content-clarity",
            action="Present supported product or service facts in concise specifications, attributes, or comparison blocks.",
            reason="Offering information appears in visible prose without an observed attribute-oriented section.",
            url=url, source="initial HTML",
            observed=compact(text[max(0, attribute_prose.start() - 60):attribute_prose.end() + 100]),
            confidence="likely"))

    return deduplicate_opportunities(items)


def deduplicate_opportunities(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    priority_order = {"high": 0, "medium": 1, "low": 2}
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for item in items:
        key = (item["id"], item["evidence"]["url"])
        merged.setdefault(key, item)
    return sorted(merged.values(), key=lambda item: (
        priority_order[item["priority"]], item["id"], item["evidence"]["url"]))


def page_identity(page: PageParser) -> dict[str, str | None]:
    h1 = next((h["text"] for h in page.headings if h["level"] == "h1" and h["text"]), None)
    return {"entity": h1 or page.meta.get("og:title") or page.title or None,
            "predicate": "identity", "value": h1 or page.title or None,
            "source_location": "final destination"}


def destination_observation(link: dict[str, str], source_url: str, evidence,
                            destination_page: PageParser | None) -> tuple[list[dict], list[str]]:
    findings, unresolved = [], []
    context = link.get("text", "").strip()
    responsibility = "site-published link"
    if evidence.outcome in {"network-error", "unresolved-redirect", "redirect-loop", "redirect-limit"} or \
            (evidence.status is not None and evidence.status >= 400):
        findings.append(finding(
            code="destination-broken", title="Published link has an unresolved destination",
            severity="High", confidence=.98,
            evidence={"link_text": context, "authored_url": link["url"],
                      "redirect_chain": evidence.redirect_chain, "status": evidence.status,
                      "outcome": evidence.outcome, "detail": evidence.detail}, affected_url=source_url,
            evidence_type="http-destination-chain", responsible_party=responsibility,
            impact="The cited continuation cannot be reached as published.",
            suggested_action="Update the published link to a verified supporting destination or explain the successor.",
            priority=90))
        return findings, unresolved
    if evidence.outcome == "robots-denied":
        unresolved.append(f"citation-destination: access deliberately restricted for {link['url']}; not assessed")
        return findings, unresolved
    if destination_page is None:
        unresolved.append(f"citation-destination: non-HTML or empty destination not semantically assessed: {link['url']}")
        return findings, unresolved
    path = urllib.parse.urlsplit(evidence.final_url).path
    specific_context = len(context.split()) >= 4 or bool(re.search(r"\d", context))
    if specific_context and path in {"", "/"}:
        findings.append(finding(
            code="specific-citation-homepage", title="Specific published citation resolves to a homepage",
            severity="High", confidence=.84,
            evidence={"link_text": context, "authored_url": link["url"],
                      "redirect_chain": evidence.redirect_chain, "final_url": evidence.final_url,
                      "destination_title": destination_page.title}, affected_url=source_url,
            evidence_type="claim-link-destination", responsible_party=responsibility,
            impact="The final destination does not preserve the specific task or entity expressed by the citation.",
            suggested_action="Link directly to the stable page that supports the attached claim or task.",
            priority=82))
    return findings, unresolved


def source_verification(claims: list[dict[str, Any]], source_pages: list[tuple[str, PageParser]],
                        target_url: str | None = None) -> tuple[list[dict], list[str]]:
    findings, unresolved = [], []
    if not source_pages:
        return [], ["source-verification: not assessed; no suitable independent source was supplied and fetched"]
    independent = []
    fingerprints: set[str] = set()
    target_origin = urllib.parse.urlsplit(target_url).netloc.casefold() if target_url else None
    for source_url, page in source_pages:
        if target_origin and urllib.parse.urlsplit(source_url).netloc.casefold() == target_origin:
            unresolved.append(f"source-verification: {source_url} is first-party, not an independent source")
            continue
        identity = (page.canonicals[0] if page.canonicals else source_url).casefold()
        fingerprint = hashlib.sha256(page.visible_text.casefold().encode()).hexdigest()
        marker = identity + "|" + fingerprint
        if marker in fingerprints:
            unresolved.append(f"source-verification: {source_url} duplicates an observed canonical/feed copy and is not independent")
            continue
        fingerprints.add(marker)
        independent.append((source_url, page))
    if not independent:
        unresolved.append("source-verification: not assessed; no suitable independent source remained")
        return findings, unresolved
    if not claims:
        unresolved.append("source-verification: sources fetched but no scoped claims were supplied for deterministic comparison")
        return findings, unresolved
    for claim in claims:
        scoped = normalize_scope(claim)
        if not scoped["entity"] or not scoped["predicate"] or scoped["value"] is None:
            unresolved.append("source-verification: skipped claim missing entity, predicate, or value")
            continue
        candidates = []
        needle = str(claim.get("value", ""))
        for source_url, page in independent:
            if needle and needle.casefold() in page.visible_text.casefold():
                candidates.append(source_url)
        if not candidates:
            unresolved.append(f"source-verification: supplied sources did not expose comparable text for {scoped['entity']} / {scoped['predicate']}")
    return findings, unresolved


def deduplicate_findings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    order = {"Critical": 3, "High": 2, "Medium": 1}
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for item in items:
        key = (item.get("_code", item["title"]), item["affected_url"])
        if key not in grouped:
            grouped[key] = item
            continue
        current = grouped[key]
        if order[item["severity"]] > order[current["severity"]]:
            current["severity"] = item["severity"]
        current["confidence"] = max(current["confidence"], item["confidence"])
        if item["evidence"] != current["evidence"]:
            values = current["evidence"] if isinstance(current["evidence"], list) else [current["evidence"]]
            if item["evidence"] not in values:
                values.append(item["evidence"])
            current["evidence"] = values
    results = []
    for item in grouped.values():
        item.pop("_code", None)
        results.append(item)
    return sorted(results, key=lambda item: (-item["priority"], item["id"]))
