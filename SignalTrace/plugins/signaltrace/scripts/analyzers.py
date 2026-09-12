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
    VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input",
                 "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title = ""
        self.meta: dict[str, str] = {}
        self.links: list[dict[str, str]] = []
        self.headings: list[dict[str, str]] = []
        self.images: list[dict[str, str]] = []
        self.controls: list[dict[str, str]] = []
        self.forms: list[dict[str, Any]] = []
        self.labels: dict[str, str] = {}
        self.jsonld: list[str] = []
        self.microdata = 0
        self.rdfa = 0
        self.canonicals: list[str] = []
        self.visible_chunks: list[str] = []
        self.content_chunks: list[str] = []
        self.script_chars = 0
        self._stack: list[dict[str, Any]] = []
        self._jsonld_buffer: list[str] | None = None

    def handle_starttag(self, tag: str, attrs_list):
        attrs = {k.lower(): (v or "") for k, v in attrs_list}
        tag = tag.lower()
        hidden = any(item.get("hidden") for item in self._stack)
        hidden = hidden or tag in {"script", "style", "template", "noscript", "svg"}
        hidden = hidden or "hidden" in attrs or attrs.get("aria-hidden", "").lower() == "true"
        node = {
            "tag": tag,
            "attrs": attrs,
            "text": [],
            "hidden": hidden,
            "links": [],
            "controls": [],
            "ancestors": tuple(item["tag"] for item in self._stack),
        }
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
            # Alternative text may label an enclosing link without becoming
            # ordinary rendered page copy.
            if attrs.get("alt"):
                for ancestor in reversed(self._stack[:-1]):
                    if ancestor["tag"] == "a":
                        ancestor["text"].append(attrs["alt"])
                        break
        if tag == "script" and attrs.get("type", "").split(";", 1)[0].strip().casefold() == "application/ld+json":
            self._jsonld_buffer = []
        if tag in self.VOID_TAGS:
            self.handle_endtag(tag)

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
            ancestor_tags = {item["tag"] for item in self._stack}
            if not ancestor_tags.intersection({"nav", "header", "footer", "script", "style"}):
                self.content_chunks.append(data)

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
            ancestors = set(node.get("ancestors", ()))
            section = next((item for item in ("nav", "header", "main", "footer", "form")
                            if item in ancestors), "body")
            link = {
                "url": urllib.parse.urljoin(self.base_url, attrs["href"]),
                "text": text or attrs.get("title", ""),
                "title": attrs.get("title", ""),
                "rel": attrs.get("rel", ""),
                "section": section,
            }
            self.links.append(link)
            for ancestor in self._stack[:index]:
                ancestor["links"].append(link)
        elif re.fullmatch(r"h[1-6]", tag):
            self.headings.append({"level": tag, "text": text})
        elif tag in {"button", "input", "select"}:
            control = {
                "tag": tag,
                "id": attrs.get("id", ""),
                "type": attrs.get("type", ""),
                "name": attrs.get("name", ""),
                "text": text or attrs.get("value", "") or attrs.get("placeholder", ""),
                "aria_label": attrs.get("aria-label", ""),
                "placeholder": attrs.get("placeholder", ""),
                "disabled": "true" if "disabled" in attrs else "false",
            }
            self.controls.append(control)
            for ancestor in self._stack[:index]:
                ancestor["controls"].append(control)
        elif tag == "label":
            if attrs.get("for") and text:
                self.labels[attrs["for"]] = text
            for control in node.get("controls", []):
                if text:
                    control["label"] = text
        elif tag == "form":
            self.forms.append({
                "action": urllib.parse.urljoin(self.base_url, attrs.get("action") or self.base_url),
                "method": (attrs.get("method") or "get").casefold(),
                "text": text,
                "controls": list(node.get("controls", [])),
            })
        if tag in {"article", "li", "section", "div"} and text and len(text) <= 800:
            for link in node.get("links", []):
                if not link.get("context"):
                    link["context"] = text
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
    for control in parser.controls:
        if control.get("id") in parser.labels:
            control["label"] = parser.labels[control["id"]]
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
    continuation = re.search(r"\b(notify|email me|waitlist|similar|alternative|back in stock|choose another)\b", text, re.I)
    useful_route = any(re.search(
        r"\b(notify|waitlist|similar|alternative|other (?:product|option)|contact|back|category|shop|browse)\b",
        item.get("text", ""), re.I) for item in meaningful_links)
    if commerce_words and not continuation and not useful_route:
        findings.append(finding(
            code="oos-no-route", title="Out-of-stock state has no observed continuation route",
            severity="Medium", confidence=.88,
            evidence={"state": commerce_words.group(0), "useful_recovery_route": False,
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


def improvement_opportunity_audit(page: PageParser, url: str,
                                  evidence_source: str = "initial HTML") -> list[dict[str, Any]]:
    """Emit conservative opportunities using only the cached initial representation."""
    items: list[dict[str, Any]] = []
    text = page.visible_text
    text_folded = text.casefold()
    headings_text = " ".join(item["text"] for item in page.headings if item["text"])
    title_and_headings = f"{page.title} {headings_text}".casefold()

    if not page.jsonld and not page.microdata and not page.rdfa:
        items.append(opportunity(
            rule_id="opportunity-structured-data", priority="low",
            category="discoverability",
            action="Add appropriate machine-readable entity metadata.",
            reason="No JSON-LD, Microdata, or RDFa was observed in the fetched HTML.",
            url=url, source=evidence_source, observed="No machine-readable metadata detected",
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
            url=url, source=evidence_source, observed=json.dumps(factual_images[:3], sort_keys=True),
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
                url=url, source=evidence_source,
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
                url=url, source=evidence_source,
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
            rule_id="opportunity-recovery-path", priority="high", category="availability",
            action="Provide an explicit recovery path for the visibly unavailable offering.",
            reason="An unavailable state was observed without a waitlist, notification, contact, or alternative path.",
            url=url, source=evidence_source, observed=unavailable.group(0), confidence="certain"))

    time_sensitive = re.search(
        r"\b(updated regularly|latest (?:version|update|release|availability)|current as of|availability may change)\b",
        text, re.I)
    freshness = any(key in page.meta for key in (
        "article:published_time", "article:modified_time", "date", "last-modified")) or any(
            re.search(r'"date(?:Published|Modified)"\s*:', block) for block in page.jsonld)
    if time_sensitive and not freshness:
        items.append(opportunity(
            rule_id="opportunity-freshness-signal", priority="medium", category="trust",
            action="Add a suitable visible and machine-readable publication or modification date.",
            reason="Time-sensitive wording was observed without a publication or modification signal.",
            url=url, source=evidence_source, observed=compact(time_sensitive.group(0)),
            confidence="likely"))

    meaningful_links = [item for item in page.links if item.get("text", "").strip()]
    next_action = any(re.search(
        r"\b(read more|learn more|get started|contact|download|apply|book|buy|add to (?:cart|basket)|"
        r"shop|browse|compare|view|continue|pricing|products?|categories|log ?in|sign ?up)\b",
        item.get("text", ""), re.I) for item in meaningful_links)
    next_action = next_action or any(classify_link(item) == "detail" for item in meaningful_links)
    if len(meaningful_links) >= 3 and len(text.split()) >= 40 and not next_action:
        items.append(opportunity(
            rule_id="opportunity-clear-next-action", priority="low", category="engagement",
            action="Add a clearer continuation link aligned with the page's stated purpose.",
            reason="Navigation links were observed, but none describes a clear task-relevant continuation.",
            url=url, source=evidence_source,
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
            url=url, source=evidence_source,
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


def classify_link(link: dict[str, str]) -> str:
    """Classify an already extracted link for bounded journey sampling."""
    split = urllib.parse.urlsplit(link.get("url", ""))
    value = " ".join((link.get("text", ""), split.path.replace("-", " ").replace("_", " "),
                      split.query, link.get("section", "")))
    if re.search(r"(?:^|/)category(?:/|$)", split.path, re.I):
        return "navigation"
    for role, expression in (
        ("policy", r"\b(return|refund|shipping|delivery|privacy|terms|warranty|policy)\b"),
        ("support", r"\b(contact|help|support|about|faq)\b"),
        ("search", r"\b(search|find)\b"),
    ):
        if re.search(expression, value, re.I):
            return role
    if re.search(r"\b(category|categories|department)\b|/category/", value, re.I):
        return "navigation"
    if re.search(r"\b(product|item|detail|view|book|course|service|listing)\b|"
                 r"/catalogue/.+_\d+/index\.html$", value, re.I):
        return "detail"
    if link.get("section") in {"nav", "header"}:
        return "navigation"
    if re.search(r"/[^/]+/[^/]+/?$", split.path) and split.path not in {"", "/"}:
        return "detail"
    if re.search(r"\b(catalog|shop|browse|collection|menu)\b", value, re.I):
        return "navigation"
    return "other"


_PRICE_RE = re.compile(
    r"(?:(?P<symbol>[$€£₹])\s*(?P<amount>\d[\d,]*(?:\.\d{1,2})?)|"
    r"(?P<code>USD|EUR|GBP|INR)\s*(?P<code_amount>\d[\d,]*(?:\.\d{1,2})?))",
    re.I)
_CURRENCY = {"$": "USD", "€": "EUR", "£": "GBP", "₹": "INR"}


def _prices(text: str) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    for match in _PRICE_RE.finditer(text or ""):
        amount = (match.group("amount") or match.group("code_amount")).replace(",", "")
        currency = _CURRENCY.get(match.group("symbol"), (match.group("code") or "").upper())
        item = {"value": amount, "unit": currency, "observed": match.group(0)}
        if item not in results:
            results.append(item)
    return results


def _entity_name(page: PageParser) -> str:
    return next((item["text"] for item in page.headings
                 if item["level"] == "h1" and item["text"]), "") or page.title


def _has_next_action(page: PageParser) -> bool:
    action = re.compile(
        r"\b(add to (?:cart|basket)|buy|purchase|book|apply|contact|notify|waitlist|"
        r"view|details?|read more|learn more|get started|shop|browse|compare|continue|related)\b",
        re.I)
    return any(action.search(item.get("text", "") + " " + item.get("aria_label", ""))
               and item.get("disabled") != "true" for item in page.controls + page.links) or any(
                   classify_link(link) == "detail" for link in page.links)


def visitor_journey_audit(target_page: PageParser, target_url: str,
                          sampled_pages: list[dict[str, Any]]) -> tuple[list[dict], list[dict], list[str]]:
    """Compare the cached landing page with a small, non-recursive page sample."""
    findings: list[dict[str, Any]] = []
    opportunities: list[dict[str, Any]] = []
    unresolved: list[str] = []
    pages = [{"role": "landing", "url": target_url, "page": target_page, "link": None}] + [
        item for item in sampled_pages if item.get("page") is not None]

    for item in pages:
        page = item["page"]
        current_path = urllib.parse.urlsplit(item["url"]).path
        if item["role"] == "detail" and page.canonicals:
            canonical = page.canonicals[0]
            canonical_parts = urllib.parse.urlsplit(canonical)
            if (canonical_parts.netloc.casefold() == urllib.parse.urlsplit(item["url"]).netloc.casefold()
                    and current_path not in {"", "/"} and canonical_parts.path in {"", "/"}):
                findings.append(finding(
                    code="detail-canonical-home",
                    title="Detail page canonical contradicts its visible detail identity",
                    severity="High", confidence=.97,
                    evidence={"detail_url": item["url"], "canonical": canonical,
                              "visible_entity": _entity_name(page)}, affected_url=item["url"],
                    evidence_type="sampled-internal-page/canonical",
                    responsible_party="site-published content",
                    impact="Automated consumers are instructed to consolidate a distinct detail entity into the homepage.",
                    suggested_action="Publish a self-referencing or correct entity-level canonical for this detail page.",
                    priority=88))
        visible_entity = _entity_name(page)
        for raw in page.jsonld:
            try:
                nodes = list(_walk_jsonld(json.loads(raw)))
            except (json.JSONDecodeError, TypeError):
                continue
            for node in nodes:
                machine_name = str(node.get("name") or node.get("headline") or "").strip()
                visible_tokens = set(re.findall(r"[a-z0-9]{3,}", visible_entity.casefold()))
                machine_tokens = set(re.findall(r"[a-z0-9]{3,}", machine_name.casefold()))
                if (visible_entity and machine_name and visible_tokens and machine_tokens
                        and not visible_tokens.intersection(machine_tokens)):
                    findings.append(finding(
                        code="visible-machine-identity-conflict",
                        title="Visible and machine-readable entity names contradict one another",
                        severity="High", confidence=.96,
                        evidence={"visible_entity": visible_entity, "machine_entity": machine_name,
                                  "type": node.get("@type")}, affected_url=item["url"],
                        evidence_type="cached-visible-text/json-ld",
                        responsible_party="site-published content",
                        impact="Visitors and automated consumers receive different identities for the same page.",
                        suggested_action="Align the title, primary heading, and scoped machine-readable entity name.",
                        priority=89))

    # A landing page should quickly identify what is offered and a supported
    # continuation. Generic slogans alone are only an improvement signal.
    initial = compact(" ".join(target_page.content_chunks), 500)
    first_heading = target_page.headings[0]["text"] if target_page.headings else ""
    vague = re.fullmatch(r"(?:welcome|discover|explore|hello|home|better starts here)[.! ]*",
                         first_heading.strip(), re.I) if first_heading else None
    offering_terms = re.search(
        r"\b(product|service|book|course|software|tool|shop|catalog|documentation|guide|platform|plan)\b",
        f"{target_page.title} {first_heading} {initial}", re.I)
    if (vague or (not offering_terms and len(initial.split()) < 45)) and not _has_next_action(target_page):
        opportunities.append(opportunity(
            rule_id="opportunity-value-proposition", priority="high", category="content-clarity",
            action="State the concrete offering in the first readable block and provide a task-relevant next action.",
            reason="The initial landing content does not clearly identify an offering or an actionable route.",
            url=target_url, source="initial HTML",
            observed=f"Heading: {first_heading or '(none)'}; first content: {initial or '(none)'}",
            confidence="likely"))

    nav_links = [link for link in target_page.links if link.get("section") in {"nav", "header"}]
    labels: dict[str, set[str]] = {}
    for link in nav_links:
        label = compact(link.get("text", "")).casefold()
        if label:
            labels.setdefault(label, set()).add(link.get("url", ""))
    ambiguous = sorted(label for label, urls in labels.items()
                       if len(urls) > 1 or label in {"more", "learn", "explore", "click here", "item"})
    empty_nav = sum(not link.get("text", "").strip() for link in nav_links)
    if ambiguous or empty_nav:
        opportunities.append(opportunity(
            rule_id="opportunity-navigation-labels", priority="medium", category="navigation",
            action="Use unique, descriptive labels for primary navigation destinations.",
            reason="The fetched navigation contains ambiguous, repeated, or empty link labels.",
            url=target_url, source="initial HTML",
            observed=json.dumps({"ambiguous_labels": ambiguous[:8], "empty_labels": empty_nav}, sort_keys=True),
            confidence="certain"))

    internal = [link for link in target_page.links
                if urllib.parse.urlsplit(link.get("url", "")).netloc.casefold() ==
                urllib.parse.urlsplit(target_url).netloc.casefold()]
    if len(internal) >= 10 and not any(classify_link(link) == "detail" for link in internal):
        opportunities.append(opportunity(
            rule_id="opportunity-detail-route", priority="high", category="discoverability",
            action="Expose a normal same-origin link from the listing or navigation to a concrete detail page.",
            reason="Many internal links were observed, but none was identifiable as a detail route.",
            url=target_url, source="initial HTML",
            observed=f"{len(internal)} internal links; 0 identifiable detail routes", confidence="likely"))

    for form in target_page.forms:
        search_like = re.search(r"\b(search|find|query)\b", form.get("text", ""), re.I) or any(
            (control.get("type") == "search" or re.search(r"\b(q|query|search)\b", control.get("name", ""), re.I))
            for control in form.get("controls", []))
        query_controls = [control for control in form.get("controls", [])
                          if control.get("tag") == "input" and control.get("type") not in {"submit", "button", "hidden"}]
        if search_like and (form.get("method") != "get" or not any(item.get("name") for item in query_controls)):
            opportunities.append(opportunity(
                rule_id="opportunity-search-form", priority="high", category="navigation",
                action="Expose a labeled GET search field with a named query parameter and stable results URL.",
                reason="A search-like form was observed without a static, inspectable query route.",
                url=target_url, source="initial HTML", observed=json.dumps(form, sort_keys=True),
                confidence="certain"))

    for item in pages:
        page = item["page"]
        unlabeled = [control for control in page.controls
                     if control.get("tag") in {"input", "select", "button"}
                     and not (control.get("text") or control.get("aria_label") or control.get("label"))
                     and control.get("type") not in {"hidden", "submit", "checkbox", "radio"}]
        if unlabeled:
            opportunities.append(opportunity(
                rule_id="opportunity-control-labels", priority="high", category="engagement",
                action="Give each interactive control a visible or programmatic task label and nearby outcome guidance.",
                reason="The fetched representation contains controls with no inspectable label.",
                url=item["url"], source="initial HTML" if item["role"] == "landing" else "sampled internal page",
                observed=json.dumps(unlabeled[:5], sort_keys=True), confidence="certain"))

    product_pages = [item for item in pages if item["role"] == "detail"]
    for item in product_pages:
        page = item["page"]
        entity = _entity_name(page)
        facts = {
            "name": bool(entity),
            "price": bool(_prices(page.visible_text)),
            "availability": bool(re.search(r"\b(in stock|out of stock|available|unavailable|sold out)\b",
                                            page.visible_text, re.I)),
            "attributes": bool(re.search(r"\b(specifications?|features?|dimensions?|weight|sku|upc|format)\b",
                                          page.visible_text, re.I)),
            "next_action": _has_next_action(page),
        }
        missing = [name for name, present in facts.items() if not present]
        if missing:
            opportunities.append(opportunity(
                rule_id="opportunity-detail-facts", priority="high" if "next_action" in missing else "medium",
                category="engagement" if "next_action" in missing else "content-clarity",
                action="Expose the supported identity, decision facts, availability, and next action in readable HTML.",
                reason="The sampled detail representation omits visitor-decision elements.",
                url=item["url"], source="sampled internal page",
                observed="Missing: " + ", ".join(missing), confidence="likely"))

        route_labels = " ".join(link.get("text", "") for link in page.links)
        if not _has_next_action(page) and not re.search(
                r"\b(back|category|related|similar|alternative|shop|browse|contact)\b", route_labels, re.I):
            opportunities.append(opportunity(
                rule_id="opportunity-detail-continuation", priority="high", category="engagement",
                action="Add a clear category, related-item, alternative, purchase, or contact continuation.",
                reason="The sampled detail page exposes no readable next step or route back into the journey.",
                url=item["url"], source="sampled internal page",
                observed="No supported continuation label or enabled action observed", confidence="certain"))

        link = item.get("link") or {}
        listing_prices = _prices(link.get("context", ""))
        detail_prices = _prices(page.visible_text)
        label = compact(link.get("text", "") or link.get("title", ""))
        aligned = bool(label and entity and
                       (label.casefold() in entity.casefold() or entity.casefold() in label.casefold()))
        if aligned and len(listing_prices) == 1 and len(detail_prices) == 1:
            left = {"entity": entity, "predicate": "price", **listing_prices[0],
                    "source_location": "listing"}
            right = {"entity": entity, "predicate": "price", **detail_prices[0],
                     "source_location": "detail"}
            # source_location is provenance, not a commercial qualifier.
            left_scope, right_scope = dict(left), dict(right)
            left_scope.pop("source_location", None)
            right_scope.pop("source_location", None)
            if compare_scopes(left_scope, right_scope) == "conflicting":
                findings.append(finding(
                    code="listing-detail-price-conflict",
                    title="Listing and detail page publish conflicting prices for the same offering",
                    severity="High", confidence=.98,
                    evidence={"entity": entity, "listing": left, "detail": right,
                              "listing_url": target_url, "detail_url": item["url"]},
                    affected_url=item["url"], evidence_type="cached-listing/detail-visible-text",
                    responsible_party="site-published content",
                    impact="Visitors can receive contradictory decision-critical pricing along one journey.",
                    suggested_action="Publish one scoped price for this offering across the listing and detail representations.",
                    priority=92))

    # Product journeys benefit from visible policy/support routes, but absence is
    # an opportunity unless a concrete promise is contradicted.
    if product_pages and not any(classify_link(link) in {"policy", "support"} for link in internal):
        opportunities.append(opportunity(
            rule_id="opportunity-decision-support", priority="medium", category="trust",
            action="Link relevant support, delivery, return, or policy guidance from the product journey.",
            reason="A product detail route was sampled without an observed support or policy route from the landing page.",
            url=target_url, source="initial HTML", observed="No support or policy link classified",
            confidence="likely"))

    if len(pages) >= 2:
        per_page_chunks = []
        for item in pages:
            chunks = {compact(chunk).casefold() for chunk in item["page"].visible_chunks
                      if len(compact(chunk).split()) >= 3}
            per_page_chunks.append(chunks)
        common = set.intersection(*per_page_chunks) if per_page_chunks else set()
        target_words = max(1, len(target_page.visible_text.split()))
        common_words = sum(len(chunk.split()) for chunk in common)
        if target_words >= 50 and common_words / target_words >= .7:
            opportunities.append(opportunity(
                rule_id="opportunity-page-specific-content", priority="medium", category="content-clarity",
                action="Increase concise page-specific content relative to repeated navigation and boilerplate.",
                reason="Most readable landing-page words also recur across every sampled internal page.",
                url=target_url, source="sampled internal page",
                observed=f"{common_words} common words across {len(pages)} pages; {target_words} landing words",
                confidence="likely"))

    return findings, deduplicate_opportunities(opportunities), unresolved


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
    authored_path = urllib.parse.urlsplit(link["url"]).path
    specific_context = len(context.split()) >= 4 or bool(re.search(r"\d", context))
    if path in {"", "/"} and authored_path not in {"", "/"}:
        findings.append(finding(
            code="specific-citation-homepage", title="Specific published citation resolves to a homepage",
            severity="High", confidence=.94 if specific_context else .86,
            evidence={"link_text": context, "authored_url": link["url"],
                      "redirect_chain": evidence.redirect_chain, "final_url": evidence.final_url,
                      "destination_title": destination_page.title}, affected_url=source_url,
            evidence_type="claim-link-destination", responsible_party=responsibility,
            impact="The final destination does not preserve the specific task or entity expressed by the citation.",
            suggested_action="Link directly to the stable page that supports the attached claim or task.",
            priority=82))
    words = len(re.findall(r"\b\w+\b", destination_page.visible_text))
    if evidence.status is not None and 200 <= evidence.status < 300 and words < 5:
        findings.append(finding(
            code="destination-empty", title="Published link resolves to an effectively empty HTML page",
            severity="Medium", confidence=.95,
            evidence={"link_text": context, "authored_url": link["url"],
                      "final_url": evidence.final_url, "readable_word_count": words,
                      "redirect_chain": evidence.redirect_chain}, affected_url=source_url,
            evidence_type="http-destination-chain/initial-html",
            responsible_party=responsibility,
            impact="The continuation succeeds technically but exposes no usable readable destination evidence.",
            suggested_action="Publish readable task or entity content at the linked destination, or remove the link.",
            priority=72))
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
