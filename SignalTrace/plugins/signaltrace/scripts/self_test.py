#!/usr/bin/env python3
"""Dependency-free behavioral and packaging checks for SignalTrace."""

from __future__ import annotations

import json
import pathlib
import concurrent.futures
import time
import unittest

from analyzers import (
    content_engagement_audit, deduplicate_findings, destination_observation,
    parse_page, source_verification, structured_data_audit,
)
from runtime import Evidence, RequestGovernor
from scope import compare_scopes, normalize_scope


class ScopeTests(unittest.TestCase):
    def test_normalizes_all_fields(self):
        value = normalize_scope({"entity": "  Café  X ", "predicate": "PRICE", "value": 19.90,
                                 "unit": "usd", "region": "in", "date": "2026-09-11T04:00:00Z"})
        self.assertEqual(value["entity"], "café x")
        self.assertEqual(value["value"], "19.9")
        self.assertEqual(value["unit"], "USD")
        self.assertEqual(value["date"], "2026-09-11")
        self.assertEqual(set(value), {"entity", "predicate", "value", "unit", "plan", "version",
                                      "variant", "region", "date", "operation", "source_location"})

    def test_scope_outcomes(self):
        base = {"entity": "Widget", "predicate": "price", "value": "20", "unit": "USD", "region": "US"}
        self.assertEqual(compare_scopes(base, dict(base)), "compatible")
        self.assertEqual(compare_scopes(base, {**base, "value": "21"}), "conflicting")
        no_region = dict(base); no_region.pop("region")
        self.assertEqual(compare_scopes(base, no_region), "ambiguous")
        self.assertEqual(compare_scopes(base, {**base, "entity": "Other"}), "insufficient-evidence")


class AnalyzerTests(unittest.TestCase):
    def test_jsonld_arrays_graphs_and_exact_malformed_location(self):
        html = """<html><head>
        <script type='application/ld+json'>{"@graph":[{"@type":"Offer","price":"9.00"}]}</script>
        <script type='application/ld+json'>{"@type":"Product", bad}</script>
        </head><body><h1>Widget</h1></body></html>"""
        page = parse_page(html, "https://example.com/widget")
        findings, _ = structured_data_audit(page, "https://example.com/widget")
        titles = {item["title"] for item in findings}
        self.assertIn("Offer price has no currency scope", titles)
        self.assertIn("JSON-LD block contains invalid JSON", titles)
        malformed = next(item for item in findings if "invalid JSON" in item["title"])
        self.assertEqual(malformed["evidence"]["block"], 2)
        self.assertIn("line", malformed["evidence"])

    def test_microdata_without_jsonld_is_not_failure(self):
        page = parse_page("<div itemscope itemtype='https://schema.org/Product'><span itemprop='name'>A</span></div>",
                          "https://example.com/a")
        findings, unresolved = structured_data_audit(page, "https://example.com/a")
        self.assertEqual(findings, [])
        self.assertEqual(unresolved, [])

    def test_app_shell_and_out_of_stock_rules_are_evidence_bound(self):
        page = parse_page("<html><head><script>" + ("x" * 3000) +
                          "</script></head><body><div id='app'>Sold out</div></body></html>",
                          "https://example.com/p")
        findings, unresolved = content_engagement_audit(page, "https://example.com/p")
        codes = {item["_code"] for item in findings}
        self.assertIn("initial-html-answer-empty", codes)
        self.assertIn("oos-no-route", codes)
        self.assertTrue(any("runtime JavaScript" in item for item in unresolved))

    def test_broken_assistant_citation_keeps_responsibility(self):
        link = {"url": "https://example.net/missing", "text": "Widget price 20 USD",
                "responsible_party": "assistant-generated citation"}
        evidence = Evidence(link["url"], link["url"], 404, {}, b"", [], "http-error")
        findings, _ = destination_observation(link, "https://example.com", evidence, None)
        findings[0]["responsible_party"] = link["responsible_party"]
        self.assertEqual(findings[0]["responsible_party"], "assistant-generated citation")

    def test_deduplication_merges_same_defect(self):
        page = parse_page("<script type='application/ld+json'>{bad}</script>" * 2, "https://example.com")
        findings, _ = structured_data_audit(page, "https://example.com")
        merged = deduplicate_findings(findings)
        self.assertEqual(len(merged), 1)
        self.assertIsInstance(merged[0]["evidence"], list)

    def test_copied_external_sources_are_not_double_counted(self):
        html = "<html><head><title>Publisher</title><link rel='canonical' href='https://wire.example/story'></head><body>" + \
               ("Widget price is 20 USD. " * 10) + "</body></html>"
        one = parse_page(html, "https://one.example/story")
        two = parse_page(html, "https://two.example/copy")
        _, unresolved = source_verification(
            [{"entity": "Widget", "predicate": "price", "value": "20", "unit": "USD"}],
            [("https://one.example/story", one), ("https://two.example/copy", two)],
            "https://shop.example/widget")
        self.assertTrue(any("duplicates" in item for item in unresolved))


class RuntimeTests(unittest.TestCase):
    def test_robots_denial_prevents_page_request(self):
        governor = RequestGovernor(max_requests=3, max_concurrency=1, timeout=1,
                                   max_body_bytes=1000, deadline_seconds=3, max_per_origin=3)
        calls = []
        def fake_request(url, body_limit=None):
            calls.append(url)
            return Evidence(url, url, 200, {"content-type": "text/plain"},
                            b"User-agent: *\nDisallow: /private\n", [], "ok")
        governor._request_once = fake_request  # type: ignore[method-assign]
        result = governor.fetch("https://example.com/private")
        self.assertEqual(result.outcome, "robots-denied")
        self.assertEqual(calls, ["https://example.com/robots.txt"])

    def test_concurrent_same_origin_fetches_share_one_robots_request(self):
        governor = RequestGovernor(max_requests=5, max_concurrency=2, timeout=1,
                                   max_body_bytes=1000, deadline_seconds=3, max_per_origin=5)
        calls = []
        def fake_request(url, body_limit=None):
            calls.append(url)
            if url.endswith("/robots.txt"):
                time.sleep(.02)
                return Evidence(url, url, 200, {"content-type": "text/plain"},
                                b"User-agent: *\nAllow: /\n", [], "ok")
            return Evidence(url, url, 200, {"content-type": "text/html"}, b"<p>ok</p>", [], "ok")
        governor._request_once = fake_request  # type: ignore[method-assign]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(governor.fetch, ["https://example.com/a", "https://example.com/b"]))
        self.assertEqual(calls.count("https://example.com/robots.txt"), 1)


class PackageTests(unittest.TestCase):
    def test_exactly_five_skills_and_one_entrypoint(self):
        plugin = pathlib.Path(__file__).resolve().parents[1]
        skill_files = sorted(plugin.glob("skills/*/SKILL.md"))
        self.assertEqual(len(skill_files), 5)
        implicit = []
        for skill_file in skill_files:
            config = (skill_file.parent / "agents/openai.yaml").read_text()
            if "allow_implicit_invocation: true" in config:
                implicit.append(skill_file.parent.name)
        self.assertEqual(implicit, ["audit-entrypoint"])

    def test_marketplace_and_manifest_paths(self):
        plugin = pathlib.Path(__file__).resolve().parents[1]
        root = plugin.parents[1]
        marketplace = json.loads((root / "marketplace.json").read_text())
        manifest = json.loads((plugin / ".codex-plugin/plugin.json").read_text())
        self.assertEqual(marketplace["plugins"][0]["name"], manifest["name"])
        self.assertEqual(marketplace["plugins"][0]["source"]["path"], "./plugins/signaltrace")


if __name__ == "__main__":
    unittest.main(verbosity=2)
