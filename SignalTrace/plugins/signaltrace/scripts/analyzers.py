#!/usr/bin/env python3
"""Local SignalTrace specialist analyzers. No network operations live here."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from copy import deepcopy
from html.parser import HTMLParser
from typing import Any, Iterable

from scope import compare_scopes, normalize_scope


def compact(value: str, limit: int = 280) -> str:
    value = re.sub(r"\s+", " ", value or "").strip()
    return value if len(value) <= limit else value[:limit - 1] + "…"


_TRACKING_PARAMETER_NAMES = {
    "gclid", "gad_source", "gad_campaignid", "gbraid", "clickid", "fbclid",
    "dclid", "msclkid", "twclid", "mc_cid", "mc_eid", "srsltid", "campaign_id",
    "deep_link_value", "is_retargeting", "pid", "c", "host_internal",
    "product_name", "storecontext",
}

# Known-incomplete tracker signatures; this is not a full tracker database.
_TRACKING_IMAGE_HOSTS = {
    "px.ads.linkedin.com", "google-analytics.com", "www.google-analytics.com",
    "doubleclick.net", "www.doubleclick.net",
}
_TRACKING_IMAGE_PATHS = ("/pixel", "/collect", "/beacon", "/tr")


def canonicalize_url(url: str) -> str:
    """Remove known tracking-only query parameters while preserving page scope."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return url
    if not parts.query:
        return url
    kept = [(key, value) for key, value in urllib.parse.parse_qsl(
        parts.query, keep_blank_values=True)
            if key.casefold() not in _TRACKING_PARAMETER_NAMES
            and not key.casefold().startswith(("utm_", "af_"))]
    query = urllib.parse.urlencode(kept, doseq=True)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _canonicalize_url_fields(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: (canonicalize_url(item) if isinstance(item, str) and
                      (key == "url" or key.endswith("_url")) else
                      _canonicalize_url_fields(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [_canonicalize_url_fields(item) for item in value]
    return value


def _finding_identity_evidence(value: Any) -> Any:
    """Remove volatile diagnostic-only fields from stable finding identity."""
    if isinstance(value, dict):
        return {key: _finding_identity_evidence(item)
                for key, item in value.items() if key != "script_characters"}
    if isinstance(value, list):
        return [_finding_identity_evidence(item) for item in value]
    return value


def _is_tracking_image(image: dict[str, str]) -> bool:
    src = str(image.get("src") or "")
    parts = urllib.parse.urlsplit(src)
    host = (parts.hostname or "").casefold()
    path = parts.path.casefold()
    known_host = host in _TRACKING_IMAGE_HOSTS or any(
        host.endswith("." + domain) for domain in _TRACKING_IMAGE_HOSTS)
    known_path = any(path == marker or path.startswith(marker + "/")
                     for marker in _TRACKING_IMAGE_PATHS)
    if known_host and (known_path or host in _TRACKING_IMAGE_HOSTS):
        return True

    def trivial_dimension(value: str) -> bool:
        match = re.fullmatch(r"\s*(\d+)\s*(?:px)?\s*", str(value or ""), re.I)
        return bool(match and int(match.group(1)) <= 2)

    return trivial_dimension(image.get("width", "")) and trivial_dimension(image.get("height", ""))


def finding(*, code: str, title: str, severity: str, confidence: float,
            evidence: Any, affected_url: str, evidence_type: str,
            responsible_party: str, impact: str, suggested_action: str,
            priority: int, coverage_status: str = "confirmed") -> dict[str, Any]:
    affected_url = canonicalize_url(affected_url)
    evidence = _canonicalize_url_fields(evidence)
    severity = severity.casefold()
    if severity not in {"critical", "high", "medium"}:
        raise ValueError(f"unsupported finding severity: {severity}")
    stable = "|".join((code, affected_url, json.dumps(
        _finding_identity_evidence(evidence), sort_keys=True)))
    action_priority = ("critical" if priority >= 95 else
                       "high" if priority >= 80 else
                       "medium" if priority >= 60 else "low")
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
        "suggested_action": {"summary": suggested_action, "priority": action_priority},
        "priority": priority,
        "coverage_status": coverage_status,
        "is_finding": True,
        "_code": code,
    }


def opportunity(*, rule_id: str, priority: str, category: str, action: str,
                reason: str, url: str, source: str, observed: Any,
                confidence: str, page_role: str | None = None) -> dict[str, Any]:
    """Build a non-finding recommendation from a concrete cached observation."""
    item = {
        "id": rule_id,
        "priority": priority,
        "category": category,
        "action": action,
        "reason": reason,
        "evidence": _canonicalize_url_fields({
            "url": canonicalize_url(url),
            "source": source,
            "observed": compact(observed) if isinstance(observed, str) else observed,
        }),
        "confidence": confidence,
        "is_finding": False,
    }
    if page_role:
        item["page_role"] = page_role
    return item


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
        self.controls: list[dict[str, Any]] = []
        self.forms: list[dict[str, Any]] = []
        self.labels: dict[str, str] = {}
        self.element_text_by_id: dict[str, str] = {}
        self.jsonld: list[str] = []
        self.microdata = 0
        self.rdfa = 0
        self.canonicals: list[str] = []
        self.visible_chunks: list[str] = []
        self.content_chunks: list[str] = []
        self.text_elements: list[dict[str, str]] = []
        self.script_chars = 0
        self._stack: list[dict[str, Any]] = []
        self._jsonld_buffer: list[str] | None = None
        self._jsonld_parse_cache: tuple[list[tuple[int, dict[str, Any]]],
                                        list[dict[str, Any]]] | None = None

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
            "accessible_text": [],
            "hidden": hidden,
            "links": [],
            "controls": [],
            "sr_only_text": [],
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
            self.images.append({k: attrs.get(k, "") for k in ("src", "alt", "title", "width", "height")})
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
        if not node["hidden"]:
            for ancestor in self._stack:
                if not ancestor["hidden"]:
                    ancestor["accessible_text"].append(data)
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
        accessible_text = compact(" ".join(node["accessible_text"]))
        attrs = node["attrs"]
        if attrs.get("id") and accessible_text and not node.get("hidden"):
            self.element_text_by_id[attrs["id"]] = accessible_text
        class_tokens = set(re.split(r"\s+", attrs.get("class", "").casefold()))
        if text and class_tokens.intersection({
                "sr-only", "sr_only", "visually-hidden", "visuallyhidden",
                "screen-reader-only", "screen-reader-text", "a11y-hidden"}):
            for ancestor in self._stack[:index]:
                if ancestor["tag"] in {"button", "input", "select"}:
                    ancestor["sr_only_text"].append(text)
        if tag in {"p", "li", "dt", "dd", "td", "th"} and text:
            self.text_elements.append({"tag": tag, "text": text})
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
            if text:
                for ancestor in reversed(self._stack[:index]):
                    if ancestor["tag"] in {"section", "article", "form", "fieldset"}:
                        ancestor["heading_context"] = text
                        break
        elif tag == "legend" and text:
            for ancestor in reversed(self._stack[:index]):
                if ancestor["tag"] == "fieldset":
                    ancestor["legend_context"] = text
                    break
        elif tag in {"button", "input", "select"}:
            surrounding_heading = next((
                ancestor.get("heading_context", "")
                for ancestor in reversed(self._stack[:index])
                if ancestor["tag"] in {"section", "article", "form", "fieldset"}
                and ancestor.get("heading_context")
            ), "")
            fieldset_context = next((
                ancestor.get("legend_context", "")
                for ancestor in reversed(self._stack[:index])
                if ancestor["tag"] == "fieldset" and ancestor.get("legend_context")
            ), "")
            control = {
                "tag": tag,
                "id": attrs.get("id", ""),
                "type": attrs.get("type", ""),
                "name": attrs.get("name", ""),
                "text": accessible_text if tag != "input" else attrs.get("value", ""),
                "aria_label": attrs.get("aria-label", ""),
                "aria_labelledby": attrs.get("aria-labelledby", ""),
                "title": attrs.get("title", ""),
                "placeholder": attrs.get("placeholder", ""),
                "sr_only_text": compact(" ".join(node.get("sr_only_text", []))),
                "fieldset_context": fieldset_context,
                "surrounding_heading": surrounding_heading,
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
                    control["wrapped_label"] = text
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
            control["associated_label"] = parser.labels[control["id"]]
            control["label"] = parser.labels[control["id"]]
        references = control.get("aria_labelledby", "").split()
        control["aria_labelledby_text"] = compact(" ".join(
            parser.element_text_by_id.get(reference, "") for reference in references))
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


def parsed_jsonld_nodes(page: PageParser) -> tuple[list[tuple[int, dict[str, Any]]],
                                                   list[dict[str, Any]]]:
    """Parse JSON-LD once so structured-data and identity checks share nodes."""
    if page._jsonld_parse_cache is not None:
        return page._jsonld_parse_cache
    nodes: list[tuple[int, dict[str, Any]]] = []
    errors: list[dict[str, Any]] = []
    for index, raw in enumerate(page.jsonld, 1):
        if not raw:
            errors.append({"block": index, "kind": "empty", "excerpt": ""})
            continue
        try:
            data = json.loads(raw)
            nodes.extend((index, node) for node in _walk_jsonld(data))
        except json.JSONDecodeError as exc:
            errors.append({
                "block": index, "kind": "invalid", "line": exc.lineno,
                "column": exc.colno, "message": exc.msg, "excerpt": compact(raw),
            })
    page._jsonld_parse_cache = (nodes, errors)
    return page._jsonld_parse_cache


def structured_data_audit(page: PageParser, url: str) -> tuple[list[dict], list[str]]:
    findings, unresolved = [], []
    parsed_nodes, parse_errors = parsed_jsonld_nodes(page)
    for error in parse_errors:
        index = error["block"]
        if error["kind"] == "empty":
            findings.append(finding(
                code="jsonld-empty", title="JSON-LD block is empty", severity="Medium",
                confidence=1.0, evidence={"block": index, "excerpt": ""}, affected_url=url,
                evidence_type="initial-html/json-ld", responsible_party="site-published link",
                impact="A machine-readable representation is present but cannot be parsed.",
                suggested_action=f"Remove or populate JSON-LD block {index} with valid scoped data.", priority=60))
            continue
        findings.append(finding(
            code="jsonld-invalid", title="JSON-LD block contains invalid JSON", severity="Medium",
            confidence=1.0,
            evidence={"block": index, "line": error["line"], "column": error["column"],
                      "message": error["message"], "excerpt": error["excerpt"]}, affected_url=url,
            evidence_type="initial-html/json-ld", responsible_party="site-published link",
            impact="Consumers cannot parse this structured-data block.",
            suggested_action=f"Correct JSON syntax in JSON-LD block {index} at line {error['line']}, column {error['column']}.",
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
    image_facts = [img for img in page.images
                   if not _is_tracking_image(img)
                   and not img.get("alt") and (img.get("src") or img.get("title"))]
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


_ACTIVITY_PATTERNS = {
    "running": r"\b(?:running|daily runs?|jogging)\b",
    "trail activity": r"\b(?:trail|trail running)\b",
    "hiking": r"\b(?:hiking|trekking)\b",
    "office commuting": r"\b(?:office|professional|work|commut(?:e|er|ing)|business)\b",
    "travel": r"\b(?:travel|travelling|traveling)\b",
    "walking": r"\b(?:walking|everyday walks?)\b",
    "cycling": r"\b(?:cycling|biking)\b",
    "gaming": r"\b(?:gaming|gameplay)\b",
}
_BENEFIT_PATTERNS = {
    "cushioning": r"\b(?:cushioning|cushioned)\b",
    "wide fit": r"\b(?:wide[- ]fit|wide fit|wider fit)\b",
    "trail grip": r"\b(?:trail grip|grip|traction)\b",
    "water resistance": r"\b(?:water[- ]resistant|water resistance|waterproof)\b",
    "ankle support": r"\bankle support\b",
    "professional styling": r"\b(?:professional styl(?:e|ing)|professional design)\b",
    "laptop compartment": r"\b(?:laptop compartment|laptop sleeve)\b",
    "durability": r"\b(?:durable|durability|long-lasting)\b",
    "lightweight": r"\blightweight\b",
    "compatibility": r"\b(?:compatible|compatibility)\b",
}
_MATERIAL_PATTERN = re.compile(
    r"\b(?:recycled (?:rubber|plastic|polyester|material|materials|sole)|leather|canvas|cotton|"
    r"polyester|nylon|rubber|wool|wood|steel|aluminium|aluminum|carbon fiber)\b", re.I)
_SUSTAINABILITY_PATTERN = re.compile(
    r"\b(?:recycled|low[- ]impact|sustainab(?:le|ility)|organic|fair[ -]trade|"
    r"FSC[- ]certified|certified organic)\b", re.I)
_AVAILABILITY_PATTERN = re.compile(
    r"\b(?:in stock|out of stock|sold out|currently unavailable|available now|available)\b", re.I)
_SPEC_PATTERN = re.compile(
    r"\b(?:\d+(?:[.,]\d+)?\s*(?:mm|cm|m|inches?|inch|kg|g|lb|oz|litres?|liters?|L|"
    r"GB|TB|MHz|GHz|W|hours?)|\d{1,2}[- ]inch|dimensions?|capacity|weight|size|"
    r"compatibility|processor|memory|storage)\b", re.I)
_DIMENSION_PATTERN = re.compile(
    r"\b(?:dimensions?|\d+(?:[.,]\d+)?\s*(?:mm|cm|m|inches?|inch|kg|g|lb|oz|litres?|liters?|L))\b",
    re.I)
_GENERIC_HEADINGS = {
    "product", "products", "item", "details", "catalog", "catalogue", "collection",
    "shop", "welcome", "home", "our products", "featured product", "new arrival",
}


def _normalized_observation(value: Any) -> str:
    """Normalize extracted evidence through SignalTrace's shared scope primitive."""
    normalized = normalize_scope({
        "entity": "observed page", "predicate": "product evidence", "value": value,
    })
    return str(normalized["value"] or "")


def product_service_evidence(page: PageParser, url: str) -> list[dict[str, Any]]:
    """Extract bounded product/service facts with exact cached provenance."""
    facts: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(field: str, location: str, exact: Any, normalized: Any | None = None,
            confidence: str = "certain") -> None:
        raw = compact(str(exact))
        if not raw:
            return
        value = _normalized_observation(raw if normalized is None else normalized)
        key = (field, location, value)
        if not value or key in seen:
            return
        seen.add(key)
        facts.append({
            "url": url,
            "field": field,
            "source_location": location,
            "exact_observed_text": raw,
            "normalized_value": value,
            "confidence": confidence,
        })

    if page.title:
        add("page_title", "title", page.title)
    h1_values = [heading["text"] for heading in page.headings
                 if heading["level"] == "h1" and heading["text"]]
    for heading in page.headings:
        field = "main_heading" if heading["level"] == "h1" else "subheading"
        add(field, heading["level"], heading["text"])
    visible_name = h1_values[0] if h1_values else page.title
    if visible_name and _normalized_observation(visible_name) not in _GENERIC_HEADINGS:
        add("product_or_service_name", "h1" if h1_values else "title", visible_name,
            confidence="likely")
    for key in ("description", "og:description", "twitter:description"):
        if page.meta.get(key):
            add("product_description", f"meta {key}", page.meta[key])
    for index, element in enumerate(page.text_elements[:80], 1):
        if element["tag"] == "p":
            add("product_description", f"p[{index}]", element["text"], confidence="likely")

    site_origin = urllib.parse.urlsplit(url).netloc.casefold()
    for index, link in enumerate(page.links[:120], 1):
        label = compact(link.get("text", ""))
        if not label:
            continue
        if urllib.parse.urlsplit(link.get("url", "")).netloc.casefold() == site_origin:
            add("internal_link", f"a[{index}]", label)
        if classify_link(link) == "navigation" and (
                "/category/" in urllib.parse.urlsplit(link.get("url", "")).path.casefold()
                or re.search(r"\b(?:shoes?|bags?|laptops?|books?|services?|products?|running|trail|hiking)\b",
                             label, re.I)):
            add("category_label", f"a[{index}]", label)
    for index, control in enumerate(page.controls[:50], 1):
        label = compact(control.get("text") or control.get("aria_label") or control.get("label") or "")
        if label and re.search(
                r"\b(?:buy|shop|view|learn|contact|book|add|compare|browse|continue|start)\b", label, re.I):
            add("call_to_action", f"{control.get('tag', 'control')}[{index}]", label)

    sources = [(item["source_location"], item["exact_observed_text"])
               for item in list(facts)]
    for location, exact in sources:
        price_matches = list(_PRICE_RE.finditer(exact))
        for match in price_matches:
            price = _prices(match.group(0))[0]
            add("price", location, match.group(0), f"{price['value']} {price['unit']}")
        if len(price_matches) >= 2 and re.search(
                r"(?:-|–|—|\bto\b)", exact[price_matches[0].end():price_matches[1].start()], re.I):
            add("price_range", location,
                exact[price_matches[0].start():price_matches[1].end()])
        match = _AVAILABILITY_PATTERN.search(exact)
        if match:
            add("availability", location, match.group(0))
        for name, expression in _ACTIVITY_PATTERNS.items():
            match = re.search(expression, exact, re.I)
            if match:
                add("activity_or_use_case", location, match.group(0), name)
        for name, expression in _BENEFIT_PATTERNS.items():
            match = re.search(expression, exact, re.I)
            if match:
                add("explicit_benefit", location, match.group(0), name)
        material = _MATERIAL_PATTERN.search(exact)
        if material:
            add("material", location, material.group(0))
        sustainable = _SUSTAINABILITY_PATTERN.search(exact)
        if sustainable:
            add("sustainability_or_certification", location, sustainable.group(0))
        if _SPEC_PATTERN.search(exact):
            add("technical_specification", location, exact)
        if _DIMENSION_PATTERN.search(exact):
            add("dimensions", location, exact)
        audience = re.search(
            r"\bfor\s+((?:daily |everyday |professional |office |trail |recreational |budget[- ]conscious )?"
            r"(?:runners?|hikers?|commuters?|students?|teams?|travellers?|travelers?|cyclists?|walkers?))\b",
            exact, re.I)
        if audience:
            add("explicit_audience", location, audience.group(0), audience.group(1))
        location_match = re.search(
            r"\b(?:serving|available in|located in|based in)\s+[A-Z][A-Za-z .'-]{2,50}", exact)
        if location_match:
            add("location_or_service_context", location, location_match.group(0))
        budget = re.search(
            r"\b(?:under|below|less than|up to)\s*(?:[$€£₹]\s*\d[\d,]*(?:\.\d{1,2})?|"
            r"(?:USD|EUR|GBP|INR)\s*\d[\d,]*(?:\.\d{1,2})?)", exact, re.I)
        if budget:
            add("price_or_value_tier", location, budget.group(0))

    nodes, _ = parsed_jsonld_nodes(page)
    for block, node in nodes:
        node_types = _types(node)
        if not node_types.intersection({"product", "service", "offer"}):
            continue
        prefix = f"JSON-LD block {block}"
        for prop, field in (
            ("name", "product_or_service_name"), ("category", "category"),
            ("description", "product_description"), ("material", "material"),
            ("availability", "availability"), ("price", "price"),
            ("priceRange", "price_range"), ("audience", "explicit_audience"),
        ):
            value = node.get(prop)
            if value not in (None, "", [], {}):
                if isinstance(value, dict):
                    value = value.get("name") or value.get("@id") or json.dumps(value, sort_keys=True)
                add(field, f"{prefix} {prop}", value)
        for prop in ("width", "height", "depth", "weight", "size", "sku", "mpn"):
            if node.get(prop) not in (None, ""):
                field = "dimensions" if prop in {"width", "height", "depth", "weight", "size"} \
                    else "technical_specification"
                add(field, f"{prefix} {prop}", node[prop])
        offers = node.get("offers")
        offer_values = offers if isinstance(offers, list) else [offers]
        for offer_index, offer in enumerate(offer_values, 1):
            if not isinstance(offer, dict):
                continue
            offer_location = f"{prefix} offers[{offer_index}]"
            if offer.get("price") not in (None, ""):
                exact_price = " ".join(filter(None, (
                    str(offer.get("price")), str(offer.get("priceCurrency") or ""))))
                add("price", f"{offer_location}.price", exact_price)
            if offer.get("availability"):
                add("availability", f"{offer_location}.availability", offer["availability"])

    # Structured descriptions and categories are cached evidence too. Scan them
    # after node extraction so they use the same controlled inference vocabulary.
    structured_text = [item for item in list(facts)
                       if item["source_location"].startswith("JSON-LD block")
                       and item["field"] in {"product_description", "category",
                                             "product_or_service_name", "material"}]
    for item in structured_text:
        exact, location = item["exact_observed_text"], item["source_location"]
        for name, expression in _ACTIVITY_PATTERNS.items():
            match = re.search(expression, exact, re.I)
            if match:
                add("activity_or_use_case", location, match.group(0), name)
        for name, expression in _BENEFIT_PATTERNS.items():
            match = re.search(expression, exact, re.I)
            if match:
                add("explicit_benefit", location, match.group(0), name)
        sustainable = _SUSTAINABILITY_PATTERN.search(exact)
        if sustainable:
            add("sustainability_or_certification", location, sustainable.group(0))

    return facts


def _fact_values(facts: list[dict[str, Any]], *fields: str) -> str:
    selected = [item["normalized_value"] for item in facts if item["field"] in fields]
    return " ".join(selected)


def _joined_phrases(values: list[str]) -> str:
    if len(values) < 2:
        return values[0] if values else ""
    return ", ".join(values[:-1]) + " and " + values[-1]


def _communication_has(concept: str, communication: str) -> bool:
    expressions = {
        "running": r"\brunn?(?:ing|er|ers)?\b",
        "trail": r"\btrail\b",
        "hiking": r"\bhik(?:e|ing|er|ers)\b",
        "office commuting": r"\b(?:office|professional|work|commut)\w*\b",
        "cushioning": r"\bcushion\w*\b",
        "wide fit": r"\bwide[- ]fit\b|\bwider fit\b",
        "trail grip": r"\b(?:grip|traction)\b",
        "water resistance": r"\bwater[- ]?(?:resistan\w*|proof)\b",
        "ankle support": r"\bankle support\b",
        "professional styling": r"\bprofessional (?:styl\w*|design)\b",
        "laptop compartment": r"\blaptop (?:compartment|sleeve)\b",
        "durability": r"\bdurab\w*\b|\blong-lasting\b",
        "lightweight": r"\blightweight\b",
        "compatibility": r"\bcompatib\w*\b",
    }
    expression = expressions.get(concept, rf"\b{re.escape(concept)}\b")
    return bool(re.search(expression, communication, re.I))


def _candidate_positioning(facts: list[dict[str, Any]]) -> dict[str, Any] | None:
    searchable = _fact_values(
        facts, "product_or_service_name", "category", "category_label", "product_description",
        "activity_or_use_case", "explicit_benefit", "material", "technical_specification",
        "sustainability_or_certification")
    activities = {item["normalized_value"] for item in facts
                  if item["field"] == "activity_or_use_case"}
    benefits = set(item["normalized_value"] for item in facts if item["field"] == "explicit_benefit")
    sustainability_label = next((item["normalized_value"] for item in facts
                                 if item["field"] == "sustainability_or_certification"), "")
    daily = bool(re.search(r"\b(?:daily|everyday)\b", searchable))
    wide = "wide fit" in benefits
    cushioning = "cushioning" in benefits
    budget_fact = next((item["exact_observed_text"] for item in facts
                        if item["field"] == "price_or_value_tier"), "")

    result: dict[str, Any]
    footwear = bool(re.search(r"\b(?:shoes?|footwear|trainers?|sneakers?|boots?)\b", searchable))
    if ("running" in activities and footwear
            and not activities.intersection({"hiking", "trail activity"})):
        use_case = "daily recreational running" if daily else "recreational running"
        needs = [item for item, present in (("cushioning", cushioning), ("a wide fit", wide)) if present]
        audience = "Candidate audience: runners" + (" seeking " + _joined_phrases(needs) if needs else "")
        headline = ("Daily " if daily else "") + "Running Shoes"
        attributes = []
        if cushioning:
            attributes.append("Cushioning")
        if wide:
            attributes.append("a Wide Fit")
        if attributes:
            headline += " with " + _joined_phrases(attributes)
        taglines = []
        if cushioning or wide:
            taglines.append(_joined_phrases(attributes) + (" for Daily Running" if daily else " for Running"))
        else:
            taglines.append("Shoes for " + ("Daily Running" if daily else "Running"))
        categories = ["Wide-Fit Running Shoes" if wide else "Running Shoes"]
        search = [" ".join(filter(None, (
            "wide-fit" if wide else "", "cushioned" if cushioning else "",
            "daily" if daily else "", "running shoes"))).strip()]
        if sustainability_label:
            search.append(f"running shoes with {sustainability_label}")
        if budget_fact:
            search.append(f"running shoes {budget_fact.casefold()}")
        headlines = [headline]
        if budget_fact:
            headlines.append(("Daily " if daily else "") + f"Running Shoes {budget_fact}")
        result = {"use_case": use_case, "audience": audience, "activity": "running",
                  "headlines": headlines, "taglines": taglines,
                  "category_labels": categories, "search_phrases": search}
    elif activities.intersection({"hiking", "trail activity"}) and footwear:
        if not benefits.intersection({"trail grip", "water resistance", "ankle support"}):
            return None
        primary_activity = "trail" if "trail activity" in activities else "hiking"
        activity_label = "Trail" if primary_activity == "trail" else "Hiking"
        labels = [label for label in ("Trail Grip" if "trail grip" in benefits else "",
                                      "Water Resistance" if "water resistance" in benefits else "",
                                      "Ankle Support" if "ankle support" in benefits else "") if label]
        result = {
            "use_case": "hiking or trail activity",
            "audience": "Candidate audience: people seeking " + _joined_phrases([label.casefold() for label in labels])
                        + " for hiking or trail activity",
            "activity": primary_activity,
            "headlines": [activity_label + " Footwear with " + _joined_phrases(labels)],
            "taglines": [_joined_phrases(labels) + " for " + activity_label],
            "category_labels": [activity_label + " Footwear"],
            "search_phrases": [" ".join(label.casefold() for label in labels)
                               + " " + activity_label.casefold() + " footwear"],
        }
    elif (re.search(r"\b(?:laptop bag|laptop backpack|notebook bag)\b", searchable)
          and "office commuting" in activities and "laptop compartment" in benefits):
        capacity = next((item["exact_observed_text"] for item in facts
                         if item["field"] == "technical_specification"
                         and re.search(r"\b\d{1,2}[- ]inch\b", item["exact_observed_text"], re.I)), "")
        size = re.search(r"\b\d{1,2}[- ]inch\b", capacity, re.I)
        size_label = size.group(0) if size else ""
        result = {
            "use_case": "office commuting with a laptop",
            "audience": "Candidate audience: office commuters carrying a laptop",
            "activity": "office commuting",
            "headlines": [(size_label + " " if size_label else "") + "Laptop Bags for Office Commuting"],
            "taglines": ["A Laptop Compartment for Office Commutes"],
            "category_labels": ["Office-Commuter Laptop Bags"],
            "search_phrases": [" ".join(filter(None, (size_label.casefold(), "laptop bag for office commuting")))],
        }
    elif "gaming" in activities and re.search(r"\b(?:laptop|computer|notebook)\b", searchable):
        device = "Laptop" if re.search(r"\b(?:laptop|notebook)\b", searchable) else "Computer"
        result = {
            "use_case": "gaming",
            "audience": f"Candidate audience: people seeking a {device.casefold()} for gaming",
            "activity": "gaming",
            "headlines": [f"{device} for Gaming"],
            "taglines": [f"For Gaming on a {device}"],
            "category_labels": [f"Gaming {device}s"],
            "search_phrases": [f"{device.casefold()} for gaming"],
        }
    else:
        return None
    result["concepts"] = [result["activity"]] + sorted(benefits)
    return result


def _positioning_opportunity(*, rule_id: str, priority: str, category: str,
                             action: str, reason: str, url: str, source: str,
                             observed: list[dict[str, Any]], candidate: dict[str, Any],
                             confidence: str = "likely") -> dict[str, Any]:
    return {
        "id": rule_id, "priority": priority, "category": category,
        "action": action, "reason": reason,
        "evidence": {"url": url, "source": source, "observed": observed},
        "candidate_use_case": candidate["use_case"],
        "candidate_audience": candidate["audience"],
        "suggested_headlines": list(dict.fromkeys(candidate["headlines"])),
        "suggested_taglines": list(dict.fromkeys(candidate["taglines"])),
        "suggested_category_labels": list(dict.fromkeys(candidate["category_labels"])),
        "suggested_search_phrases": list(dict.fromkeys(candidate["search_phrases"])),
        "confidence": confidence, "is_finding": False,
    }


def positioning_opportunity_audit(page: PageParser, url: str,
                                  evidence_source: str = "initial HTML") -> list[dict[str, Any]]:
    """Find communication gaps without treating a missing tagline as a defect."""
    facts = product_service_evidence(page, url)
    candidate = _candidate_positioning(facts)
    if candidate is None:
        return []
    communication_facts = [item for item in facts if item["field"] in {
        "page_title", "main_heading", "subheading", "category", "category_label"}]
    communication = " ".join(item["normalized_value"] for item in communication_facts)
    main_heading = next((item["normalized_value"] for item in facts
                         if item["field"] == "main_heading"), "")
    generic_heading = not main_heading or main_heading in _GENERIC_HEADINGS
    missing_concepts = [concept for concept in candidate["concepts"]
                        if concept and not _communication_has(concept, communication)]
    prominent_fields = {"page_title", "main_heading", "subheading", "category", "category_label",
                        "product_or_service_name"}

    def evidence_for(*specific_fields: str) -> list[dict[str, Any]]:
        wanted = prominent_fields | set(specific_fields)
        selected = [item for item in facts if item["field"] in wanted]
        # Put the gap-specific facts first so an evidence cap cannot hide the
        # observation that supports the recommendation.
        selected.sort(key=lambda item: (item["field"] in prominent_fields,
                                        item["source_location"], item["field"]))
        return selected[:20]

    items: list[dict[str, Any]] = []

    if generic_heading or not _communication_has(candidate["activity"], communication):
        items.append(_positioning_opportunity(
            rule_id="opportunity-positioning-use-case", priority="high", category="positioning",
            action="Test a primary heading that states the observed product use case and supported attributes.",
            reason="Specific use-case evidence is present, but the primary communication does not state it clearly.",
            url=url, source=evidence_source,
            observed=evidence_for("activity_or_use_case", "explicit_benefit", "explicit_audience"),
            candidate=candidate))
    if len(missing_concepts) >= 2:
        items.append(_positioning_opportunity(
            rule_id="opportunity-positioning-search-language", priority="medium",
            category="discoverability",
            action="Test observed use-case and attribute terms in the title, headings, or category labels.",
            reason="Multiple search-relevant terms in cached body evidence are absent from prominent page labels.",
            url=url, source=evidence_source,
            observed=evidence_for("activity_or_use_case", "explicit_benefit"), candidate=candidate))
    benefits = [item for item in facts if item["field"] == "explicit_benefit"]
    communicated_benefits = [item for item in benefits
                             if _communication_has(item["normalized_value"], communication)]
    if len(benefits) >= 2 and len(communicated_benefits) < 2:
        items.append(_positioning_opportunity(
            rule_id="opportunity-positioning-attribute-summary", priority="medium",
            category="content-clarity",
            action="Group the observed functional attributes into one concise visitor-readable value proposition.",
            reason="Multiple supported attributes are present but are not summarized together in prominent communication.",
            url=url, source=evidence_source,
            observed=evidence_for("explicit_benefit", "technical_specification", "dimensions"),
            candidate=candidate))
    sustainable = [item for item in facts if item["field"] == "sustainability_or_certification"]
    if sustainable and not any(_communication_has(item["normalized_value"], communication)
                               for item in sustainable):
        items.append(_positioning_opportunity(
            rule_id="opportunity-positioning-sustainability", priority="low",
            category="positioning",
            action="Test the observed material or sustainability wording in a concise product summary.",
            reason="A sustainability-related attribute is present in cached evidence but absent from prominent labels.",
            url=url, source=evidence_source,
            observed=evidence_for("sustainability_or_certification", "material", "explicit_benefit"),
            candidate=candidate))
    value_tier = [item for item in facts if item["field"] == "price_or_value_tier"]
    if value_tier and not any(item["normalized_value"] in communication for item in value_tier):
        items.append(_positioning_opportunity(
            rule_id="opportunity-positioning-value-tier", priority="low", category="positioning",
            action="Test the exact observed price-tier language alongside the supported use case.",
            reason="The page states a price threshold, but prominent communication does not connect it to the product use case.",
            url=url, source=evidence_source,
            observed=evidence_for("price_or_value_tier", "price", "activity_or_use_case"),
            candidate=candidate))
    activities = {item["normalized_value"] for item in facts if item["field"] == "activity_or_use_case"}
    activity_groups = {"trail/hiking" if item in {"trail activity", "hiking"} else item
                       for item in activities}
    if len(activity_groups) >= 2 and sum(_communication_has(activity, communication)
                                         for activity in activities) < len(activities):
        items.append(_positioning_opportunity(
            rule_id="opportunity-positioning-multiple-use-cases", priority="low",
            category="content-clarity",
            action="Distinguish the separately observed use cases in headings or category labels.",
            reason="Cached evidence supports multiple activities, but prominent communication does not distinguish them.",
            url=url, source=evidence_source,
            observed=evidence_for("activity_or_use_case", "explicit_benefit"), candidate=candidate))
    return deduplicate_opportunities(items)


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

    parsed_nodes, _ = parsed_jsonld_nodes(page)
    product_or_service_nodes = [node for _, node in parsed_nodes
                                if _types(node).intersection({"product", "service"})]
    for node in product_or_service_nodes:
        missing = [field for field in ("aggregateRating", "review")
               if field not in node or node.get(field) in (None, "")]
        if missing:
            items.append(opportunity(
                rule_id="opportunity-structured-review-signals", priority="low",
                category="discoverability",
                action="Add supported AggregateRating or Review properties when verified evidence exists.",
                reason="A Product or Service JSON-LD entity was observed without one or more review signal properties.",
                url=url, source=evidence_source,
                observed={"type": node.get("@type"), "id": node.get("@id"), "missing": missing},
                confidence="likely"))
            break

    organization_nodes = [node for _, node in parsed_nodes if "organization" in _types(node)]
    if organization_nodes and not any(node.get("sameAs") for node in organization_nodes):
        items.append(opportunity(
            rule_id="opportunity-organization-sameas", priority="low",
            category="discoverability",
            action="Declare verified social or profile links in Organization JSON-LD when available.",
            reason="An Organization JSON-LD entity was observed without a sameAs property.",
            url=url, source=evidence_source,
            observed={"organization_types": [node.get("@type") for node in organization_nodes],
                      "missing": ["sameAs"]}, confidence="likely"))

    faq_pattern = re.compile(r"\b(?:q(?:uestion)?|a(?:nswer)?)\s*[:\-]|\?", re.I)
    faq_visible = bool(faq_pattern.search(page.visible_text)) or sum(
        1 for heading in page.headings if "?" in heading.get("text", "")) >= 2
    has_faq_schema = any("faqpage" in _types(node) for _, node in parsed_nodes)
    if faq_visible and not has_faq_schema:
        items.append(opportunity(
            rule_id="opportunity-faq-schema", priority="low", category="discoverability",
            action="Add FAQPage structured data for the observed question-and-answer content when it meets the format requirements.",
            reason="Question-and-answer patterns were observed in readable HTML without an FAQPage JSON-LD node.",
            url=url, source=evidence_source,
            observed="Visible question-and-answer pattern; FAQPage schema not observed", confidence="likely"))

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

    items.extend(positioning_opportunity_audit(page, url, evidence_source))
    return deduplicate_opportunities(items)


def _normalized_opportunity_url(url: str) -> str:
    split = urllib.parse.urlsplit(url)
    path = re.sub(r"/{2,}", "/", split.path or "/")
    if path != "/":
        path = path.rstrip("/")
    query = urllib.parse.urlencode(sorted(urllib.parse.parse_qsl(
        split.query, keep_blank_values=True)))
    return urllib.parse.urlunsplit((
        split.scheme.casefold(), split.netloc.casefold(), path, query, ""))


def _url_scope(url: str) -> str:
    path = urllib.parse.unquote(urllib.parse.urlsplit(url).path).strip("/")
    parts = [part for part in path.split("/") if part and part.casefold() not in {
        "index.html", "index.htm", "index.php"}]
    value = parts[-1] if parts else "landing"
    value = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
    return (value or "landing")[:48].rstrip("-")


def _opportunity_scope(item: dict[str, Any]) -> str:
    role = str(item.get("page_role") or "").casefold()
    if role == "navigation":
        role = "collection"
    if role in {"collection", "detail", "support", "policy", "landing"}:
        return role
    return _url_scope(item["evidence"]["url"])


def _merge_opportunity_group(group: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge one rule/page group without discarding distinct cached evidence."""
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))
    result = deepcopy(min(group, key=canonical))
    observed_values: dict[str, Any] = {}
    for item in group:
        observed = item.get("evidence", {}).get("observed")
        observed_values.setdefault(canonical(observed), observed)
    if len(observed_values) > 1:
        observations: dict[str, Any] = {}
        for observed in observed_values.values():
            values = observed if isinstance(observed, list) else [observed]
            for value in values:
                observations.setdefault(canonical(value), value)
        result["evidence"]["observed"] = [
            deepcopy(observations[key]) for key in sorted(observations)]
    return result


def deduplicate_opportunities(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group by rule/page, merge evidence, and scope colliding public IDs."""
    priority_order = {"high": 0, "medium": 1, "low": 2}
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in items:
        url = _normalized_opportunity_url(item["evidence"]["url"])
        grouped.setdefault((item["id"], url), []).append(item)
    merged = [_merge_opportunity_group(grouped[key]) for key in sorted(grouped)]

    by_rule: dict[str, list[dict[str, Any]]] = {}
    for item in merged:
        by_rule.setdefault(item["id"], []).append(item)
    for rule_id, group in by_rule.items():
        if len(group) < 2:
            continue
        candidates = [_opportunity_scope(item) for item in group]
        candidate_counts = {value: candidates.count(value) for value in set(candidates)}
        used: set[str] = set()
        for item, candidate in sorted(zip(group, candidates), key=lambda pair: (
                _normalized_opportunity_url(pair[0]["evidence"]["url"]), pair[1])):
            if candidate_counts[candidate] > 1:
                url_scope = _url_scope(item["evidence"]["url"])
                candidate = f"{candidate}-{url_scope}" if url_scope != candidate else candidate
            scoped_id = f"{rule_id}-{candidate}"
            if scoped_id in used:
                normalized_url = _normalized_opportunity_url(item["evidence"]["url"])
                suffix = hashlib.sha256(normalized_url.encode()).hexdigest()[:8]
                scoped_id = f"{scoped_id}-{suffix}"
            item["id"] = scoped_id
            used.add(scoped_id)
    merged = _consolidate_opportunities(merged, "")
    return sorted(merged, key=lambda item: (
        priority_order[item["priority"]], item["id"],
        _normalized_opportunity_url(item["evidence"]["url"])))


def _opportunity_root_key(item: dict[str, Any]) -> tuple[str, str, str, str]:
    return (item["id"], item.get("category", ""), item.get("action", ""), item.get("reason", ""))


def _consolidate_opportunities(items: list[dict[str, Any]], target_url: str) -> list[dict[str, Any]]:
    """Merge same-root opportunities across pages while retaining page evidence."""
    grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for item in items:
        grouped.setdefault(_opportunity_root_key(item), []).append(item)
    result: list[dict[str, Any]] = []
    for group in grouped.values():
        urls = {_normalized_opportunity_url(item["evidence"]["url"]) for item in group}
        if len(urls) < 2:
            result.extend(group)
            continue
        canonical = deepcopy(min(group, key=lambda value: json.dumps(value, sort_keys=True)))
        pages = []
        for item in sorted(group, key=lambda value: _normalized_opportunity_url(value["evidence"]["url"])):
            evidence = item["evidence"]
            observed = evidence.get("observed")
            occurrence_count = 1
            if isinstance(observed, list):
                occurrence_count = sum(
                    int(control.get("occurrence_count", 1))
                    for control in observed if isinstance(control, dict)) or 1
            pages.append({"url": evidence["url"], "source": evidence.get("source"),
                          "observed": observed, "occurrence_count": occurrence_count})
        canonical["evidence"]["url"] = canonicalize_url(target_url) if target_url else pages[0]["url"]
        canonical["evidence"]["observed"] = pages
        result.append(canonical)
    return result


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


_PAGE_SCOPED_ENTITY_TYPES = {
    "webpage", "product", "article", "newsarticle", "blogposting", "recipe",
    "service", "course", "event", "jobposting", "faqpage", "profilepage",
}


def _page_scoped_entity_names(page: PageParser) -> list[tuple[str, str]]:
    """Return names from JSON-LD entities that describe this page's own subject."""
    entities: list[tuple[str, str]] = []
    for _, node in parsed_jsonld_nodes(page)[0]:
        if not _types(node).intersection(_PAGE_SCOPED_ENTITY_TYPES):
            continue
        name = str(node.get("name") or node.get("headline") or "").strip()
        if name:
            entities.append((name, str(node.get("@type") or "")))
    return entities


def _has_next_action(page: PageParser) -> bool:
    action = re.compile(
        r"\b(add to (?:cart|basket)|buy|purchase|book|apply|contact|notify|waitlist|"
        r"view|details?|read more|learn more|get started|shop|browse|compare|continue|related)\b",
        re.I)
    return any(action.search(item.get("text", "") + " " + item.get("aria_label", ""))
               and item.get("disabled") != "true" for item in page.controls + page.links) or any(
                   classify_link(link) == "detail" for link in page.links)


_CONTROL_NAME_CHECKS = [
    "direct text", "aria-label", "aria-labelledby", "title",
    "associated label", "wrapped label", "placeholder",
    "visually hidden text", "fieldset context", "surrounding heading",
]


def _static_control_name(control: dict[str, Any]) -> tuple[str, str]:
    """Return the first supported name and its static HTML mechanism."""
    tag = str(control.get("tag") or "").casefold()
    control_type = str(control.get("type") or "").casefold()
    direct_text = control.get("text") if (
        tag == "button" or (tag == "input" and control_type in {"button", "reset"})) else ""
    candidates = [
        ("direct text", direct_text),
        ("aria-label", control.get("aria_label")),
        ("aria-labelledby", control.get("aria_labelledby_text")),
        ("title", control.get("title")),
        ("associated label", control.get("associated_label")),
        ("wrapped label", control.get("wrapped_label")),
    ]
    placeholder_types = {
        "", "text", "search", "email", "tel", "url", "password", "number",
        "date", "datetime-local", "month", "time", "week",
    }
    if tag == "input" and control_type in placeholder_types:
        candidates.append(("placeholder", control.get("placeholder")))
    candidates.extend([
        ("visually hidden text", control.get("sr_only_text")),
        ("fieldset context", control.get("fieldset_context")),
        ("surrounding heading", control.get("surrounding_heading")),
    ])
    for mechanism, value in candidates:
        normalized = compact(str(value or ""))
        if normalized:
            return normalized, mechanism
    return "", ""


def _unlabelled_control_evidence(control: dict[str, Any]) -> dict[str, Any]:
    check_results = {name: "not observed" for name in _CONTROL_NAME_CHECKS}
    placeholder_types = {
        "", "text", "search", "email", "tel", "url", "password", "number",
        "date", "datetime-local", "month", "time", "week",
    }
    if (control.get("tag") != "input"
            or str(control.get("type") or "").casefold() not in placeholder_types):
        check_results["placeholder"] = "not applicable to this control"
    return {
        "tag": control.get("tag", ""),
        "type": control.get("type", ""),
        "id": control.get("id", ""),
        "name": control.get("name", ""),
        "checks": list(_CONTROL_NAME_CHECKS),
        "check_results": check_results,
        "observed": "No accessible name was observable in the fetched HTML using the supported static checks.",
    }


def _group_unlabelled_control_evidence(controls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Retain each distinct control signature and count indistinguishable repeats."""
    grouped: dict[str, tuple[dict[str, Any], int]] = {}
    for control in controls:
        evidence = _unlabelled_control_evidence(control)
        key = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
        prior, count = grouped.get(key, (evidence, 0))
        grouped[key] = (prior, count + 1)
    result = []
    for key in sorted(grouped):
        evidence, count = grouped[key]
        if count > 1:
            evidence["occurrence_count"] = count
        result.append(evidence)
    return result


def _public_page_role(role: str) -> str:
    role = (role or "unknown").casefold()
    return "collection" if role == "navigation" else (
        role if role in {"detail", "support", "policy", "landing"} else "unknown")


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
        visible_tokens = set(re.findall(r"[a-z0-9]{3,}", visible_entity.casefold()))
        for machine_name, machine_type in _page_scoped_entity_names(page):
            machine_tokens = set(re.findall(r"[a-z0-9]{3,}", machine_name.casefold()))
            if (visible_entity and machine_name and visible_tokens and machine_tokens
                    and not visible_tokens.intersection(machine_tokens)):
                findings.append(finding(
                    code="visible-machine-identity-conflict",
                    title="Visible and page-scoped machine-readable entity names contradict one another",
                    severity="High", confidence=.96,
                    evidence={"visible_entity": visible_entity, "machine_entity": machine_name,
                              "type": machine_type}, affected_url=item["url"],
                    evidence_type="cached-visible-text/page-scoped-json-ld",
                    responsible_party="site-published content",
                    impact="The fetched visible and page-scoped machine-readable representations publish different identities for the same page.",
                    suggested_action="Align the title, primary heading, and page-scoped machine-readable entity name.",
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
        unlabeled_controls = [
            control for control in page.controls
            if control.get("tag") in {"input", "select", "button"}
            and control.get("type", "").casefold() not in {"hidden", "submit"}
            and not _static_control_name(control)[0]
        ]
        unlabeled = _group_unlabelled_control_evidence(unlabeled_controls)
        if unlabeled:
            opportunities.append(opportunity(
                rule_id="opportunity-control-labels", priority="high", category="engagement",
                action="Expose a visible or programmatic task label for the affected control and provide nearby outcome guidance.",
                reason="No accessible name was observable in the fetched HTML using the supported static checks.",
                url=item["url"], source="initial HTML" if item["role"] == "landing" else "sampled internal page",
                observed=unlabeled, confidence="certain",
                page_role=_public_page_role(item["role"])))

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
        listing_text = compact(" ".join((link.get("text", ""), link.get("context", ""))), 1600)
        listing_activities = {
            name for name, expression in _ACTIVITY_PATTERNS.items()
            if re.search(expression, listing_text, re.I)
        }
        detail_facts = product_service_evidence(page, item["url"])
        detail_activities = {
            fact["normalized_value"] for fact in detail_facts
            if fact["field"] == "activity_or_use_case"
        }
        listing_groups = {"trail/hiking" if value in {"trail activity", "hiking"} else value
                          for value in listing_activities}
        detail_groups = {"trail/hiking" if value in {"trail activity", "hiking"} else value
                         for value in detail_activities}
        detail_candidate = _candidate_positioning(detail_facts)
        if (listing_groups and detail_groups and listing_groups.isdisjoint(detail_groups)
                and detail_candidate is not None):
            observations = [{
                "url": target_url, "field": "listing_activity_or_use_case",
                "source_location": "listing link text/context",
                "exact_observed_text": listing_text,
                "normalized_value": ", ".join(sorted(listing_activities)),
                "confidence": "certain",
            }] + [fact for fact in detail_facts if fact["field"] in {
                "page_title", "main_heading", "category", "category_label",
                "activity_or_use_case", "explicit_benefit"}][:12]
            opportunities.append(_positioning_opportunity(
                rule_id="opportunity-positioning-listing-detail-terminology",
                priority="high", category="content-clarity",
                action="Align the listing and detail terminology around the same observed product activity.",
                reason="The cached listing and detail representations use different explicit activity terms for this route.",
                url=item["url"], source="sampled internal page", observed=observations,
                candidate=detail_candidate, confidence="certain"))
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
                    impact="The fetched listing and detail representations publish contradictory decision-critical pricing for the same offering.",
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


def same_as_declarations(page: PageParser, site_url: str) -> tuple[list[dict[str, Any]],
                                                                  list[str], str]:
    """Extract external Organization/Person sameAs claims from shared parsed JSON-LD."""
    parsed_nodes, _ = parsed_jsonld_nodes(page)
    site_origin = urllib.parse.urlsplit(site_url).netloc.casefold()
    declarations: list[dict[str, Any]] = []
    unresolved: list[str] = []
    seen: set[tuple[str, str]] = set()
    saw_property = False
    for block, node in parsed_nodes:
        identity_types = _types(node) & {"organization", "person"}
        if not identity_types or "sameAs" not in node:
            continue
        saw_property = True
        raw_values = node.get("sameAs")
        values = raw_values if isinstance(raw_values, list) else [raw_values]
        brand = str(node.get("name") or "").strip()
        for raw in values:
            value = raw.get("@id") if isinstance(raw, dict) else raw
            if not isinstance(value, str) or not value.strip():
                unresolved.append(
                    f"sameAs-identity: JSON-LD block {block} contains a non-URL sameAs value; not assessed")
                continue
            url = value.strip()
            try:
                parts = urllib.parse.urlsplit(url)
                if parts.scheme.casefold() not in {"http", "https"} or not parts.hostname:
                    raise ValueError("not an absolute HTTP(S) URL")
            except ValueError as exc:
                unresolved.append(
                    f"sameAs-identity: JSON-LD block {block} value {compact(url)} is invalid: {exc}; not assessed")
                continue
            if parts.netloc.casefold() == site_origin:
                unresolved.append(
                    f"sameAs-identity: {url} is same-origin rather than an external identity URL; not assessed")
                continue
            key = (url, brand.casefold())
            if key in seen:
                continue
            seen.add(key)
            declarations.append({
                "url": url, "brand": brand, "block": block,
                "node_type": sorted(identity_types)[0].title(),
            })
    if declarations:
        return declarations, unresolved, "applicable"
    if saw_property:
        return [], unresolved, "inconclusive"
    return [], unresolved, "not applicable"


def _identity_candidates(page: PageParser) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    h1 = next((item["text"] for item in page.headings
               if item["level"] == "h1" and item["text"]), "")
    values = (
        ("h1", h1),
        ("og:title", page.meta.get("og:title", "")),
        ("twitter:title", page.meta.get("twitter:title", "")),
        ("title", page.title),
        ("profile:username", page.meta.get("profile:username", "")),
    )
    seen: set[str] = set()
    for source, value in values:
        cleaned = compact(value)
        if cleaned and cleaned.casefold() not in seen:
            seen.add(cleaned.casefold())
            candidates.append({"source": source, "value": cleaned})
    nodes, _ = parsed_jsonld_nodes(page)
    for _, node in nodes:
        if _types(node) & {"organization", "person", "profilepage"} and node.get("name"):
            cleaned = compact(str(node["name"]))
            if cleaned.casefold() not in seen:
                seen.add(cleaned.casefold())
                candidates.append({"source": "destination JSON-LD", "value": cleaned})
    return candidates


def _normalized_identity(value: str) -> str:
    scoped = normalize_scope({"entity": "sameAs claim", "predicate": "identity", "value": value})
    return str(scoped["value"] or "")


def _compare_same_as_identity(brand: str, candidate: dict[str, str]) -> str:
    """Compare identity text, allowing platform decoration in the HTML title only."""
    if candidate.get("source") == "title" and brand.strip() and re.search(
            rf"(?<!\w){re.escape(brand.strip())}(?!\w)", candidate.get("value", ""), re.I):
        return "compatible"
    return compare_scopes(
        {"entity": "sameAs claim", "predicate": "identity", "value": brand},
        {"entity": "sameAs claim", "predicate": "identity", "value": candidate["value"]})


def _documented_successor(brand: str, page: PageParser) -> bool:
    if not brand:
        return False
    h1 = next((item["text"] for item in page.headings
               if item["level"] == "h1" and item["text"]), "")
    text = compact(" ".join((
        page.title, h1, page.meta.get("description", ""),
        page.meta.get("og:description", ""), page.meta.get("twitter:description", ""))), 4000)
    name = re.escape(brand)
    return bool(re.search(
        rf"(?:formerly|previously known as)\s+{name}\b|\b{name}\s+(?:is now|became|rebranded as)\b",
        text, re.I))


def same_as_destination_observation(declaration: dict[str, Any], source_url: str,
                                    evidence, destination_page: PageParser | None
                                    ) -> tuple[list[dict], list[str], dict[str, Any]]:
    """Classify one governor-fetched sameAs identity destination."""
    declared_url = declaration["url"]
    brand = declaration.get("brand", "")
    result: dict[str, Any] = {
        "declared_url": declared_url,
        "brand": brand,
        "node_type": declaration.get("node_type"),
        "block": declaration.get("block"),
        "classification": "inconclusive",
        "identity_verdict": "not assessed",
        "status": evidence.status,
        "final_url": evidence.final_url,
        "redirect_chain": evidence.redirect_chain,
    }
    findings: list[dict[str, Any]] = []
    unresolved: list[str] = []
    if evidence.outcome == "robots-denied":
        result["classification"] = "robots-denied"
        unresolved.append(f"sameAs-identity: {declared_url} denied by robots.txt; not assessed")
        return findings, unresolved, result
    if evidence.outcome in {"blocked", "origin-blocked"} or evidence.status in {403, 429}:
        result["classification"] = "blocked"
        unresolved.append(
            f"sameAs-identity: {declared_url} was blocked or unavailable ({evidence.detail}); not assessed")
        return findings, unresolved, result

    dead_outcomes = {"unresolved-redirect", "redirect-loop", "redirect-limit"}
    is_http_dead = evidence.status is not None and evidence.status >= 400
    if evidence.outcome in {"timeout", "network-error"}:
        result["classification"] = "dead"
        unresolved.append(
            f"sameAs-identity: {declared_url} could not be reached ({evidence.outcome}); identity claim not assessed")
        return findings, unresolved, result
    if evidence.outcome in dead_outcomes or is_http_dead:
        result["classification"] = "dead"
        findings.append(finding(
            code="sameas-dead", title="Published sameAs identity URL is dead",
            severity="High", confidence=.98,
            evidence={"brand": brand, "declared_url": declared_url,
                      "status": evidence.status, "outcome": evidence.outcome,
                      "detail": evidence.detail, "redirect_chain": evidence.redirect_chain},
            affected_url=source_url, evidence_type="json-ld/sameAs/http-destination-chain",
            responsible_party="site-published link",
            impact="The site publishes an external identity claim whose destination cannot be reached.",
            suggested_action="Replace or remove the dead sameAs URL after verifying the intended public identity profile.",
            priority=90))
        return findings, unresolved, result

    declared_parts = urllib.parse.urlsplit(declared_url)
    final_parts = urllib.parse.urlsplit(evidence.final_url)
    material_redirect = bool(evidence.redirect_chain) and (
        declared_parts.netloc.casefold() != final_parts.netloc.casefold() or
        declared_parts.path.rstrip("/").casefold() != final_parts.path.rstrip("/").casefold())
    result["classification"] = (
        "redirects-to-materially-different-destination" if material_redirect else "resolves-cleanly")
    if destination_page is None:
        unresolved.append(
            f"sameAs-identity: {declared_url} resolved without usable public HTML identity evidence; not assessed")
        return findings, unresolved, result

    parked_identity_text = " ".join(item["value"] for item in _identity_candidates(destination_page))
    parked_identity_text += " " + destination_page.meta.get("description", "")
    parked = re.search(
        r"\b(?:this domain is for sale|buy this domain|domain (?:is )?parked|sedo domain parking|"
        r"afternic|parkingcrew)\b", parked_identity_text, re.I)
    if parked:
        result["classification"] = "squatted-or-parked"
        result["identity_verdict"] = "conflicting"
        findings.append(finding(
            code="sameas-parked", title="Published sameAs identity URL resolves to a parked or for-sale page",
            severity="High", confidence=.98,
            evidence={"brand": brand, "declared_url": declared_url,
                      "final_url": evidence.final_url, "observed": compact(parked.group(0)),
                      "redirect_chain": evidence.redirect_chain}, affected_url=source_url,
            evidence_type="json-ld/sameAs/destination-visible-text",
            responsible_party="site-published link",
            impact="The published identity claim resolves to a destination that presents itself as parked or for sale.",
            suggested_action="Remove the identity claim or replace it with a verified profile controlled by the named entity.",
            priority=92))
        return findings, unresolved, result

    candidates = _identity_candidates(destination_page)
    result["destination_identity"] = candidates[:8]
    exact_results = []
    brand_normalized = _normalized_identity(brand)
    plausible = False
    for candidate in candidates:
        compared = _compare_same_as_identity(brand, candidate)
        exact_results.append({"source": candidate["source"], "result": compared})
        candidate_normalized = _normalized_identity(candidate["value"])
        if compared == "compatible" or (brand_normalized and candidate_normalized and
                (brand_normalized in candidate_normalized or candidate_normalized in brand_normalized)):
            plausible = True
    result["scope_comparisons"] = exact_results
    comparison_results = [item["result"] for item in exact_results]
    successor = _documented_successor(brand, destination_page)
    result["documented_successor"] = successor
    if successor:
        result["identity_verdict"] = "documented successor"
        return findings, unresolved, result
    if "conflicting" in comparison_results:
        result["identity_verdict"] = "conflicting"
    elif plausible:
        result["identity_verdict"] = "plausible match"
        return findings, unresolved, result
    elif comparison_results and all(item == "insufficient-evidence" for item in comparison_results):
        result["identity_verdict"] = "not assessed"
        unresolved.append(
            f"sameAs-identity: {declared_url} did not contain a declared comparable name; not assessed")
        return findings, unresolved, result

    generic = re.compile(
        r"^(?:facebook|instagram|linkedin|twitter|x|youtube|tiktok|wikipedia|crunchbase|"
        r"home|log ?in|sign ?in|page not found)(?:\W.*)?$", re.I)
    positive = [item for item in candidates if not generic.match(item["value"].strip())]
    if brand and positive:
        result["identity_verdict"] = "conflicting"
        findings.append(finding(
            code="sameas-identity-mismatch",
            title="Published sameAs destination states a different identity",
            severity="High", confidence=.9,
            evidence={"brand": brand, "declared_url": declared_url,
                      "final_url": evidence.final_url, "destination_identity": positive[:5],
                      "scope_comparisons": exact_results,
                      "redirect_chain": evidence.redirect_chain}, affected_url=source_url,
            evidence_type="json-ld/sameAs/destination-identity",
            responsible_party="site-published link",
            impact="The site's machine-readable identity claim points to a page that states a different entity name.",
            suggested_action="Correct the sameAs URL or align it with the verified external identity for this entity.",
            priority=91))
    else:
        unresolved.append(
            f"sameAs-identity: {declared_url} resolved but exposed no comparable public identity name; not assessed")
    return findings, unresolved, result


def destination_observation(link: dict[str, str], source_url: str, evidence,
                            destination_page: PageParser | None) -> tuple[list[dict], list[str]]:
    findings, unresolved = [], []
    context = link.get("text", "").strip()
    responsibility = "site-published link"
    if evidence.outcome in {"blocked", "origin-blocked"} or evidence.status in {403, 429}:
        unresolved.append(
            f"citation-destination: {link['url']} blocked or unavailable ({evidence.detail}); not assessed")
        return findings, unresolved
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
    order = {"critical": 3, "high": 2, "medium": 1}
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
