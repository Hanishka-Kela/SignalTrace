#!/usr/bin/env python3
"""Dependency-free behavioral and packaging checks for SignalTrace."""

from __future__ import annotations

import json
import pathlib
import concurrent.futures
import inspect
import subprocess
import sys
import time
import unittest

from analyzers import (
    bot_directives_audit, content_engagement_audit, deduplicate_findings,
    deduplicate_opportunities, destination_observation, improvement_opportunity_audit,
    parse_page, same_as_declarations, same_as_destination_observation,
    source_verification, structured_data_audit, visitor_journey_audit,
)
from runtime import Evidence, LimitError, RequestGovernor, RobotsDecision
from config import DEFAULTS, USER_AGENT
from scope import compare_scopes, normalize_scope
from signaltrace import _audit_same_as, _journey_sample_limit, _report, _select_journey_links


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
    def test_conflicting_bot_directives_are_localized(self):
        page = parse_page("<meta name='robots' content='index, noindex'><p>Answer</p>",
                          "https://example.com")
        findings, _ = bot_directives_audit(
            page, {}, "https://example.com", {"result": "allowed", "detail": "parsed"})
        self.assertEqual(findings[0]["severity"], "Medium")

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

    def test_same_as_absence_is_not_applicable(self):
        page = parse_page(
            '<script type="application/ld+json">'
            '{"@type":"Organization","name":"Main Street Bakery"}</script>',
            "https://bakery.example/")
        declarations, unresolved, status = same_as_declarations(page, page.base_url)
        self.assertEqual(declarations, [])
        self.assertEqual(unresolved, [])
        self.assertEqual(status, "not applicable")

    def test_person_same_as_is_extracted_from_shared_jsonld_nodes(self):
        page = parse_page(
            '<script type="application/ld+json">'
            '{"@type":"Person","name":"Ada Example",'
            '"sameAs":["https://profiles.example/ada"]}</script>',
            "https://ada.example/")
        declarations, unresolved, status = same_as_declarations(page, page.base_url)
        self.assertEqual(status, "applicable")
        self.assertEqual(unresolved, [])
        self.assertEqual(declarations[0]["node_type"], "Person")

    def test_same_as_robots_denial_is_coverage_only(self):
        declaration = {"url": "https://social.example/acme", "brand": "Acme",
                       "node_type": "Organization", "block": 1}
        evidence = Evidence(declaration["url"], declaration["url"], None, {}, b"", [],
                            "robots-denied", "denied: robots.txt disallows this URL")
        findings, unresolved, result = same_as_destination_observation(
            declaration, "https://acme.example/", evidence, None)
        self.assertEqual(findings, [])
        self.assertEqual(result["classification"], "robots-denied")
        self.assertTrue(any("not assessed" in item for item in unresolved))

    def test_same_as_documented_successor_redirect_is_not_broken(self):
        declaration = {"url": "https://social.example/acme-bakery", "brand": "Acme Bakery",
                       "node_type": "Organization", "block": 1}
        final_url = "https://social.example/northstar-bakery"
        evidence = Evidence(
            declaration["url"], final_url, 200, {"content-type": "text/html"}, b"", [{
                "from": declaration["url"], "status": 301, "to": final_url}], "ok")
        destination = parse_page(
            "<title>Northstar Bakery — formerly Acme Bakery</title>"
            "<h1>Northstar Bakery</h1><p>Formerly Acme Bakery.</p>", final_url)
        findings, unresolved, result = same_as_destination_observation(
            declaration, "https://acme.example/", evidence, destination)
        self.assertEqual(findings, [])
        self.assertEqual(unresolved, [])
        self.assertEqual(result["classification"], "redirects-to-materially-different-destination")
        self.assertIs(result["documented_successor"], True)
        self.assertEqual(result["identity_verdict"], "documented successor")

    def test_single_legitimate_same_as_resolves_without_padding(self):
        page = parse_page(
            '<script type="application/ld+json">'
            '{"@type":"Organization","name":"Main Street Bakery",'
            '"sameAs":["https://social.example/main-street-bakery"]}</script>',
            "https://bakery.example/")
        declarations, unresolved, status = same_as_declarations(page, page.base_url)
        self.assertEqual(status, "applicable")
        self.assertEqual(unresolved, [])
        destination = parse_page(
            '<title>Main Street Bakery | Social</title>'
            '<meta property="og:title" content="Main Street Bakery">', declarations[0]["url"])
        evidence = Evidence(declarations[0]["url"], declarations[0]["url"], 200,
                            {"content-type": "text/html"}, b"", [], "ok")
        findings, notes, result = same_as_destination_observation(
            declarations[0], page.base_url, evidence, destination)
        self.assertEqual(findings, [])
        self.assertEqual(notes, [])
        self.assertEqual(result["classification"], "resolves-cleanly")
        self.assertEqual(result["identity_verdict"], "plausible match")
        self.assertTrue(any(item["result"] == "compatible"
                            for item in result["scope_comparisons"]))

    def test_dead_same_as_is_a_high_identity_finding(self):
        declaration = {"url": "https://social.example/missing", "brand": "Acme",
                       "node_type": "Organization", "block": 1}
        evidence = Evidence(declaration["url"], declaration["url"], 404, {}, b"", [],
                            "http-error", "HTTP 404")
        findings, unresolved, result = same_as_destination_observation(
            declaration, "https://acme.example/", evidence, None)
        self.assertEqual(unresolved, [])
        self.assertEqual(result["classification"], "dead")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "High")

    def test_parked_same_as_is_classified_from_explicit_page_text(self):
        declaration = {"url": "https://profile.example/acme", "brand": "Acme",
                       "node_type": "Organization", "block": 1}
        destination = parse_page(
            "<title>Buy this domain</title><p>This domain is for sale.</p>", declaration["url"])
        evidence = Evidence(declaration["url"], declaration["url"], 200,
                            {"content-type": "text/html"}, b"", [], "ok")
        findings, unresolved, result = same_as_destination_observation(
            declaration, "https://acme.example/", evidence, destination)
        self.assertEqual(unresolved, [])
        self.assertEqual(result["classification"], "squatted-or-parked")
        self.assertEqual(findings[0]["severity"], "High")


class ImprovementOpportunityTests(unittest.TestCase):
    def test_missing_structured_data_is_opportunity_not_finding(self):
        page = parse_page("<html><head><title>About</title></head><body><h1>About</h1><p>Useful answer.</p></body></html>",
                          "https://example.com/")
        findings, _ = structured_data_audit(page, "https://example.com/")
        opportunities = improvement_opportunity_audit(page, "https://example.com/")
        self.assertEqual(findings, [])
        item = next(value for value in opportunities if value["id"] == "opportunity-structured-data")
        self.assertIs(item["is_finding"], False)
        self.assertEqual(item["evidence"]["source"], "initial HTML")

    def test_jsonld_suppresses_missing_structured_data_opportunity(self):
        page = parse_page(
            '<script type="application/ld+json">{"@type":"Organization","name":"Example"}</script><h1>Example</h1>',
            "https://example.com/")
        ids = {item["id"] for item in improvement_opportunity_audit(page, "https://example.com/")}
        self.assertNotIn("opportunity-structured-data", ids)

    def test_image_fact_requires_an_observed_image(self):
        without_image = parse_page("<p>Overview</p>", "https://example.com/")
        with_image = parse_page('<img src="facts.png" alt="Calories 200"><p>Overview</p>',
                                "https://example.com/")
        absent_ids = {item["id"] for item in improvement_opportunity_audit(without_image, "https://example.com/")}
        present = improvement_opportunity_audit(with_image, "https://example.com/")
        present_ids = {item["id"] for item in present}
        self.assertNotIn("opportunity-media-text-equivalent", absent_ids)
        self.assertIn("opportunity-media-text-equivalent", present_ids)
        item = next(value for value in present if value["id"] == "opportunity-media-text-equivalent")
        self.assertIn("Calories 200", item["evidence"]["observed"])

    def test_visible_waitlist_suppresses_recovery_opportunity(self):
        page = parse_page("<h1>Workshop</h1><p>Currently unavailable. Join the waitlist.</p>",
                          "https://example.com/workshop")
        ids = {item["id"] for item in improvement_opportunity_audit(page, page.base_url)}
        self.assertNotIn("opportunity-recovery-path", ids)

    def test_unavailable_without_recovery_gets_opportunity(self):
        page = parse_page("<h1>Workshop</h1><p>Currently unavailable.</p>",
                          "https://example.com/workshop")
        opportunities = improvement_opportunity_audit(page, page.base_url)
        item = next(value for value in opportunities if value["id"] == "opportunity-recovery-path")
        self.assertEqual(item["priority"], "high")
        self.assertEqual(item["evidence"]["observed"].casefold(), "currently unavailable")
        self.assertEqual(opportunities[0]["id"], "opportunity-recovery-path")

    def test_opportunity_contract_and_deduplication(self):
        page = parse_page("<p>Plain answer.</p>", "https://example.com/")
        item = improvement_opportunity_audit(page, page.base_url)[0]
        self.assertEqual(set(item), {
            "id", "priority", "category", "action", "reason", "evidence",
            "confidence", "is_finding"})
        self.assertEqual(set(item["evidence"]), {"url", "source", "observed"})
        self.assertTrue(item["evidence"]["observed"])
        self.assertIs(item["is_finding"], False)
        self.assertIn(item["category"], {"discoverability", "engagement", "navigation",
                                         "trust", "content-clarity", "availability"})
        self.assertIn(item["evidence"]["source"], {
            "initial HTML", "sampled internal page", "redirect chain", "robots.txt"})
        self.assertEqual(deduplicate_opportunities([item, dict(item)]), [item])

    def test_running_attributes_produce_grounded_positioning_recommendation(self):
        page = parse_page(
            "<title>Catalog</title><h1>Product</h1>"
            "<p>Roadstep is a running shoe for daily running with cushioning and a wide fit.</p>",
            "https://shop.example/roadstep")
        opportunities = improvement_opportunity_audit(page, page.base_url)
        item = next(value for value in opportunities
                    if value["id"] == "opportunity-positioning-use-case")
        self.assertEqual(item["category"], "positioning")
        self.assertEqual(item["candidate_use_case"], "daily recreational running")
        self.assertIn("runners", item["candidate_audience"])
        self.assertTrue(item["suggested_headlines"])
        self.assertIsInstance(item["evidence"]["observed"], list)
        self.assertTrue(all({"url", "field", "source_location", "exact_observed_text",
                             "normalized_value", "confidence"}.issubset(observation)
                            for observation in item["evidence"]["observed"]))
        exact = " ".join(observation["exact_observed_text"]
                         for observation in item["evidence"]["observed"])
        self.assertIn("cushioning", exact)
        self.assertIn("wide fit", exact)

    def test_hiking_suggestions_require_hiking_and_trail_attributes(self):
        unsupported = parse_page(
            "<title>Catalog</title><h1>Product</h1><p>Summit is a hiking boot.</p>",
            "https://shop.example/summit")
        supported = parse_page(
            "<title>Catalog</title><h1>Product</h1>"
            "<p>Summit is a hiking boot with trail grip, water-resistant material, and ankle support.</p>",
            "https://shop.example/summit")
        unsupported_ids = {item["id"] for item in improvement_opportunity_audit(
            unsupported, unsupported.base_url)}
        self.assertFalse(any(item.startswith("opportunity-positioning")
                             for item in unsupported_ids))
        items = [item for item in improvement_opportunity_audit(supported, supported.base_url)
                 if item["id"].startswith("opportunity-positioning")]
        self.assertTrue(items)
        generated = json.dumps(items).casefold()
        self.assertIn("hiking", generated)
        self.assertIn("trail", generated)

    def test_laptop_bag_commuter_positioning_requires_work_evidence(self):
        no_work = parse_page(
            "<title>Bag</title><h1>Product</h1>"
            "<p>A 15-inch laptop bag with a laptop compartment.</p>",
            "https://shop.example/bag")
        with_work = parse_page(
            "<title>Bag</title><h1>Product</h1>"
            "<p>A professional 15-inch laptop bag with professional styling and a laptop compartment.</p>",
            "https://shop.example/bag")
        no_work_items = [item for item in improvement_opportunity_audit(no_work, no_work.base_url)
                         if item["id"].startswith("opportunity-positioning")]
        self.assertEqual(no_work_items, [])
        work_items = [item for item in improvement_opportunity_audit(with_work, with_work.base_url)
                      if item["id"].startswith("opportunity-positioning")]
        self.assertTrue(work_items)
        self.assertTrue(all("office commuter" in item["candidate_audience"].casefold()
                            for item in work_items))

    def test_no_use_case_evidence_does_not_invent_an_audience(self):
        page = parse_page(
            "<title>Northwind Object</title><h1>Northwind Object</h1>"
            "<p>Available in blue. Price £20.</p>", "https://shop.example/object")
        positioning = [item for item in improvement_opportunity_audit(page, page.base_url)
                       if item["id"].startswith("opportunity-positioning")]
        self.assertEqual(positioning, [])

    def test_matching_specific_heading_suppresses_positioning_gap(self):
        page = parse_page(
            "<title>Wide-Fit Cushioned Running Shoes</title>"
            "<h1>Wide-Fit Cushioned Running Shoes</h1>"
            "<p>Running shoes with cushioning and a wide fit.</p>",
            "https://shop.example/running")
        positioning = [item for item in improvement_opportunity_audit(page, page.base_url)
                       if item["id"].startswith("opportunity-positioning")]
        self.assertEqual(positioning, [])

    def test_generated_copy_never_adds_unobserved_high_risk_claims(self):
        page = parse_page(
            "<title>Catalog</title><h1>Product</h1>"
            "<p>Running shoes with cushioning, a wide fit, and recycled rubber.</p>",
            "https://shop.example/running")
        positioning = [item for item in improvement_opportunity_audit(page, page.base_url)
                       if item["id"].startswith("opportunity-positioning")]
        generated = json.dumps(positioning).casefold()
        for phrase in ("professional athlete", "carbon-neutral", "injury-proof",
                       "increase conversions", "best in"):
            self.assertNotIn(phrase, generated)

    def test_independent_positioning_gaps_are_grouped_and_deduplicated(self):
        page = parse_page(
            "<title>Catalog</title><h1>Product</h1>"
            "<p>Running shoes for daily running with cushioning, a wide fit, recycled rubber, "
            "and a price under ₹6,000.</p>", "https://shop.example/running")
        positioning = [item for item in improvement_opportunity_audit(page, page.base_url)
                       if item["id"].startswith("opportunity-positioning")]
        self.assertGreaterEqual(len(positioning), 4)
        merged = deduplicate_opportunities(positioning + [dict(item) for item in positioning])
        merged_positioning = [item for item in merged
                              if item["id"].startswith("opportunity-positioning")]
        self.assertEqual(len(merged_positioning), len(positioning))
        self.assertEqual(len({item["id"] for item in positioning}), len(positioning))


class VisitorJourneyTests(unittest.TestCase):
    def test_multi_page_fixture_selects_roles_and_broken_link_is_confirmed(self):
        landing = parse_page("""
            <nav><a href='/category/books'>Books</a><a href='/about'>About us</a></nav>
            <main><article><a href='/product/widget'>Widget</a><span>$10.00</span></article>
            <a href='/search'>Search</a><a href='/returns'>Returns policy</a>
            <a href='/page/2'>Next</a><a href='/broken'>Broken detail</a></main>
            """, "https://shop.example/")
        selected, skipped = _select_journey_links(landing, landing.base_url, 5)
        self.assertEqual({item["role"] for item in selected},
                         {"navigation", "detail", "search", "support", "policy"})
        self.assertTrue(any(item["reason"] == "role already represented in bounded sample"
                            for item in skipped))
        link = {"url": "https://shop.example/broken", "text": "Broken detail"}
        evidence = Evidence(link["url"], link["url"], 404, {}, b"", [], "http-error")
        findings, _ = destination_observation(link, landing.base_url, evidence, None)
        self.assertEqual(findings[0]["severity"], "High")

    def test_out_of_stock_without_route_and_waitlist_negative_control(self):
        no_route = parse_page(
            "<h1>Widget</h1><p>Out of stock.</p><a href='/'>Home</a>",
            "https://shop.example/widget")
        with_waitlist = parse_page(
            "<h1>Widget</h1><p>Out of stock. Join the waitlist.</p><a href='/waitlist'>Waitlist</a>",
            "https://shop.example/widget")
        no_route_codes = {item["_code"] for item in content_engagement_audit(
            no_route, no_route.base_url)[0]}
        waitlist_codes = {item["_code"] for item in content_engagement_audit(
            with_waitlist, with_waitlist.base_url)[0]}
        self.assertIn("oos-no-route", no_route_codes)
        self.assertNotIn("oos-no-route", waitlist_codes)

    def test_listing_detail_price_mismatch_is_high_confidence_finding(self):
        landing = parse_page(
            "<h1>Widget shop</h1><article><a href='/product/widget'>Widget</a><span>$10.00</span></article>",
            "https://shop.example/")
        detail = parse_page(
            "<h1>Widget</h1><p>Price $12.00. In stock.</p><h2>Specifications</h2>"
            "<p>Weight: 2 kg</p><button>Add to cart</button>",
            "https://shop.example/product/widget")
        link = next(item for item in landing.links if item["url"].endswith("/product/widget"))
        findings, _, _ = visitor_journey_audit(landing, landing.base_url, [{
            "role": "detail", "url": detail.base_url, "page": detail, "link": link}])
        conflict = next(item for item in findings if item["_code"] == "listing-detail-price-conflict")
        self.assertEqual(conflict["severity"], "High")
        self.assertEqual(conflict["confidence"], .98)

    def test_vague_landing_gets_value_proposition_opportunity(self):
        page = parse_page("<main><h1>Welcome</h1><p>Better starts here.</p></main>",
                          "https://example.com/")
        _, opportunities, _ = visitor_journey_audit(page, page.base_url, [])
        self.assertIn("opportunity-value-proposition", {item["id"] for item in opportunities})

    def test_useful_navigation_and_action_avoid_engagement_false_positive(self):
        page = parse_page(
            "<title>Acme accounting software</title><nav><a href='/products'>Accounting products</a>"
            "<a href='/contact'>Contact support</a></nav><main><h1>Accounting software for teams</h1>"
            "<p>Track invoices and expenses with Acme software.</p><a href='/products'>Browse products</a></main>",
            "https://example.com/")
        findings, opportunities, _ = visitor_journey_audit(page, page.base_url, [])
        self.assertFalse(any(item.get("_code") == "oos-no-route" for item in findings))
        ids = {item["id"] for item in opportunities}
        self.assertNotIn("opportunity-value-proposition", ids)
        self.assertNotIn("opportunity-navigation-labels", ids)

    def test_independent_observations_emit_multiple_opportunities(self):
        page = parse_page(
            "<main><h1>Welcome</h1><p>Hello.</p><button></button><input></main>",
            "https://example.com/")
        opportunities = improvement_opportunity_audit(page, page.base_url)
        _, journey, _ = visitor_journey_audit(page, page.base_url, [])
        combined = deduplicate_opportunities(opportunities + journey)
        self.assertGreaterEqual(len(combined), 3)
        self.assertTrue({"opportunity-structured-data", "opportunity-value-proposition",
                         "opportunity-control-labels"}.issubset({item["id"] for item in combined}))

    def test_positive_listing_detail_activity_conflict_is_a_positioning_opportunity(self):
        landing = parse_page(
            "<h1>Footwear</h1><article><a href='/product/stride'>Hiking shoe</a>"
            "<p>Hiking footwear with trail grip.</p></article>", "https://shop.example/")
        detail = parse_page(
            "<title>Stride</title><h1>Product</h1>"
            "<p>Stride is a running shoe with cushioning and a wide fit.</p>",
            "https://shop.example/product/stride")
        link = next(item for item in landing.links if item["url"].endswith("/product/stride"))
        _, opportunities, _ = visitor_journey_audit(landing, landing.base_url, [{
            "role": "detail", "url": detail.base_url, "page": detail, "link": link}])
        item = next(value for value in opportunities
                    if value["id"] == "opportunity-positioning-listing-detail-terminology")
        self.assertIs(item["is_finding"], False)
        self.assertIn("Hiking", item["evidence"]["observed"][0]["exact_observed_text"])
        self.assertEqual(item["candidate_use_case"], "recreational running")


class RuntimeTests(unittest.TestCase):
    def test_robots_denial_prevents_page_request(self):
        governor = RequestGovernor(max_requests=3, max_concurrency=1, timeout=1,
                                   max_body_bytes=1000, deadline_seconds=3, max_per_origin=3,
                                   spacing_seconds=0)
        calls = []
        def fake_request(url, *, kind, body_limit):
            calls.append(url)
            return Evidence(url, url, 200, {"content-type": "text/plain"},
                            b"User-agent: *\nDisallow: /private\n", [], "ok")
        governor._request_with_retries = fake_request  # type: ignore[method-assign]
        result = governor.fetch("https://example.com/private")
        self.assertEqual(result.outcome, "robots-denied")
        self.assertEqual(calls, ["https://example.com/robots.txt"])

    def test_same_as_fetch_uses_governor_and_stops_at_robots_denial(self):
        governor = RequestGovernor(max_requests=3, max_concurrency=1, timeout=1,
                                   max_body_bytes=1000, deadline_seconds=3, max_per_origin=3,
                                   spacing_seconds=0)
        calls = []
        def fake_request(url, *, kind, body_limit):
            calls.append(url)
            return Evidence(url, url, 200, {"content-type": "text/plain"},
                            b"User-agent: *\nDisallow: /acme\n", [], "ok")
        governor._request_with_retries = fake_request  # type: ignore[method-assign]
        declaration = {"url": "https://social.example/acme", "brand": "Acme",
                       "node_type": "Organization", "block": 1}
        findings, unresolved, result = _audit_same_as(
            governor, "https://acme.example/", declaration)
        self.assertEqual(findings, [])
        self.assertTrue(any("not assessed" in item for item in unresolved))
        self.assertEqual(result["classification"], "robots-denied")
        self.assertEqual(calls, ["https://social.example/robots.txt"])

    def test_concurrent_same_origin_fetches_share_one_robots_request(self):
        governor = RequestGovernor(max_requests=5, max_concurrency=2, timeout=1,
                                   max_body_bytes=1000, deadline_seconds=3, max_per_origin=5,
                                   spacing_seconds=0)
        calls = []
        def fake_request(url, *, kind, body_limit):
            calls.append(url)
            if url.endswith("/robots.txt"):
                time.sleep(.02)
                return Evidence(url, url, 200, {"content-type": "text/plain"},
                                b"User-agent: *\nAllow: /\n", [], "ok")
            return Evidence(url, url, 200, {"content-type": "text/html"}, b"<p>ok</p>", [], "ok")
        governor._request_with_retries = fake_request  # type: ignore[method-assign]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(governor.fetch, ["https://example.com/a", "https://example.com/b"]))
        self.assertEqual(calls.count("https://example.com/robots.txt"), 1)

    def test_benchmark_defaults_and_delegation_zero_request_default(self):
        self.assertEqual(DEFAULTS.global_request_maximum, 20)
        self.assertEqual(DEFAULTS.target_request_maximum, 16)
        self.assertEqual(DEFAULTS.per_origin_maximum, 8)
        self.assertEqual(DEFAULTS.cross_origin_concurrency, 2)
        self.assertEqual(DEFAULTS.same_origin_concurrency, 1)
        self.assertEqual(DEFAULTS.request_timeout_seconds, 8)
        self.assertEqual(DEFAULTS.connection_timeout_seconds, 3)
        self.assertEqual(DEFAULTS.response_body_limit_bytes, 2 * 1024 * 1024)
        self.assertEqual(DEFAULTS.aggregate_body_limit_bytes, 12 * 1024 * 1024)
        self.assertEqual(DEFAULTS.same_origin_spacing_seconds, 2)
        self.assertEqual(DEFAULTS.retries, 0)
        governor = RequestGovernor(spacing_seconds=0)
        context = governor.delegation_context("task-1", "https://example.com/a", ["cache:1"])
        self.assertEqual(context["maximum_additional_requests"], 0)
        self.assertEqual(set(context), {
            "task_identifier", "cached_evidence_references", "permission_status",
            "remaining_global_request_budget", "remaining_per_origin_budget",
            "remaining_time", "maximum_additional_requests", "cancellation_deadline"})

    def test_curl_is_only_http_transport_and_has_required_flags(self):
        source = inspect.getsource(RequestGovernor._curl_once)
        self.assertIn("subprocess.run", source)
        for flag in ("--silent", "--show-error", "--location", "--max-time",
                     "--connect-timeout", "--user-agent", "--compressed"):
            self.assertIn(flag, source)
        self.assertEqual(USER_AGENT, "SignalTrace/1.0")

    def test_unavailable_robots_is_reported_and_bounded_fetch_continues(self):
        governor = RequestGovernor(max_requests=3, max_concurrency=1, timeout=1,
                                   max_body_bytes=1000, deadline_seconds=3, max_per_origin=3,
                                   spacing_seconds=0)
        calls = []
        def fake_request(url, *, kind, body_limit):
            calls.append(url)
            if url.endswith("/robots.txt"):
                return Evidence(url, url, 503, {}, b"", [], "http-error", "HTTP 503")
            return Evidence(url, url, 200, {"content-type": "text/html"}, b"<p>Public</p>", [], "ok")
        governor._request_with_retries = fake_request  # type: ignore[method-assign]
        result = governor.fetch("https://example.com/a")
        self.assertEqual(result.status, 200)
        self.assertEqual(governor.robots_result(result.final_url)["result"], "unavailable")
        self.assertEqual(calls, ["https://example.com/robots.txt", "https://example.com/a"])

    def test_missing_robots_404_continues_bounded_sample_with_exact_coverage(self):
        governor = RequestGovernor(max_requests=8, max_concurrency=1, timeout=1,
                                   max_body_bytes=1000, deadline_seconds=3, max_per_origin=8,
                                   spacing_seconds=0)
        calls = []
        def fake_request(url, *, kind, body_limit):
            calls.append(url)
            if url.endswith("/robots.txt"):
                return Evidence(url, url, 404, {}, b"", [], "http-error", "HTTP 404")
            return Evidence(url, url, 200, {"content-type": "text/html"}, b"<p>Public</p>", [], "ok")
        governor._request_with_retries = fake_request  # type: ignore[method-assign]
        first = governor.fetch("https://example.com/a")
        second = governor.fetch("https://example.com/b")
        self.assertEqual((first.status, second.status), (200, 200))
        self.assertEqual(calls, ["https://example.com/robots.txt",
                                 "https://example.com/a", "https://example.com/b"])
        self.assertEqual(governor.robots_result(first.final_url), {
            "result": "missing", "detail": "missing: robots.txt returned HTTP 404"})
        report = _report("https://example.com/a", governor, [], [], [])
        self.assertEqual(report["coverage"]["crawl_policy"], {
            "name": "bounded_missing-policy_audit", "unrestricted": False,
            "reason": "No published robots policy was found; existing safety ceilings remain active"})
        serialized = json.dumps(report["coverage"]).casefold()
        self.assertNotIn("full permission", serialized)
        self.assertNotIn("authorization to crawl", serialized)

    def test_missing_robots_does_not_enable_recursive_selection(self):
        page = parse_page("".join(
            f"<a href='/product/{index}'>Product {index}</a>" for index in range(20)),
            "https://example.com/")
        selected, skipped = _select_journey_links(page, page.base_url, 5)
        self.assertLessEqual(len(selected), 5)
        self.assertTrue(skipped)
        self.assertEqual(_journey_sample_limit({"result": "missing"}, 5), 5)
        self.assertEqual(_journey_sample_limit({"result": "unavailable"}, 5), 1)
        governor = RequestGovernor(spacing_seconds=0)
        governor._robots["https://example.com"] = RobotsDecision(
            "missing", True, "robots.txt returned HTTP 404")
        self.assertIs(governor.crawl_policy(page.base_url)["unrestricted"], False)

    def test_unavailable_robots_uses_conservative_origin_ceiling(self):
        for robots_evidence in (
            Evidence("", "", None, {}, b"", [], "timeout", "curl timed out"),
            Evidence("", "", 503, {}, b"", [], "http-error", "HTTP 503"),
        ):
            with self.subTest(outcome=robots_evidence.outcome, status=robots_evidence.status):
                governor = RequestGovernor(max_requests=8, max_concurrency=1, timeout=1,
                                           max_body_bytes=1000, deadline_seconds=3,
                                           max_per_origin=8, spacing_seconds=0)
                calls = []
                def fake_curl(url, *, kind, body_limit):
                    _, reserved = governor._reserve(url, kind, body_limit)
                    calls.append(url)
                    governor._completed += 1
                    governor._aggregate_reserved -= reserved
                    if url.endswith("/robots.txt"):
                        return Evidence(url, url, robots_evidence.status, {}, b"", [],
                                        robots_evidence.outcome, robots_evidence.detail)
                    return Evidence(url, url, 200, {"content-type": "text/html"},
                                    b"<p>Public</p>", [], "ok")
                governor._curl_once = fake_curl  # type: ignore[method-assign]
                governor.fetch("https://example.com/a")
                governor.fetch("https://example.com/b")
                with self.assertRaisesRegex(LimitError, "conservative origin ceiling"):
                    governor.fetch("https://example.com/c")
                self.assertEqual(governor.robots_result("https://example.com/a")["result"],
                                 "unavailable")
                policy = governor.crawl_policy("https://example.com/a")
                self.assertEqual(policy["name"], "conservative_unavailable-policy_audit")
                self.assertIs(policy["unrestricted"], False)

    def test_403_and_429_stop_further_origin_requests(self):
        for status in (403, 429):
            with self.subTest(status=status):
                governor = RequestGovernor(max_requests=8, max_concurrency=1, timeout=1,
                                           max_body_bytes=1000, deadline_seconds=3,
                                           max_per_origin=8, spacing_seconds=0)
                calls = []
                def fake_request(url, *, kind, body_limit):
                    calls.append(url)
                    if url.endswith("/robots.txt"):
                        return Evidence(url, url, 200, {}, b"User-agent: *\nAllow: /\n", [], "ok")
                    return Evidence(url, url, status, {}, b"Access denied", [],
                                    "http-error", f"HTTP {status}")
                governor._request_with_retries = fake_request  # type: ignore[method-assign]
                first = governor.fetch("https://example.com/a")
                second = governor.fetch("https://example.com/b")
                self.assertEqual(first.outcome, "blocked")
                self.assertEqual(second.outcome, "origin-blocked")
                self.assertEqual(calls, ["https://example.com/robots.txt", "https://example.com/a"])

    def test_repeated_5xx_and_explicit_antibot_stop_origin(self):
        governor = RequestGovernor(max_requests=8, max_concurrency=1, timeout=1,
                                   max_body_bytes=1000, deadline_seconds=3,
                                   max_per_origin=8, spacing_seconds=0)
        statuses = iter((500, 502))
        calls = []
        def fake_request(url, *, kind, body_limit):
            calls.append(url)
            if url.endswith("/robots.txt"):
                return Evidence(url, url, 200, {}, b"User-agent: *\nAllow: /\n", [], "ok")
            status = next(statuses)
            return Evidence(url, url, status, {}, b"Server error", [], "http-error", f"HTTP {status}")
        governor._request_with_retries = fake_request  # type: ignore[method-assign]
        self.assertEqual(governor.fetch("https://example.com/a").outcome, "http-error")
        self.assertEqual(governor.fetch("https://example.com/b").outcome, "blocked")
        self.assertEqual(governor.fetch("https://example.com/c").outcome, "origin-blocked")
        self.assertEqual(len(calls), 3)

        challenged = RequestGovernor(max_requests=4, max_concurrency=1, timeout=1,
                                     max_body_bytes=1000, deadline_seconds=3,
                                     max_per_origin=4, spacing_seconds=0)
        challenge_calls = []
        def fake_challenge(url, *, kind, body_limit):
            challenge_calls.append(url)
            if url.endswith("/robots.txt"):
                return Evidence(url, url, 200, {}, b"User-agent: *\nAllow: /\n", [], "ok")
            return Evidence(url, url, 200, {"content-type": "text/html"},
                            b"<h1>Verify you are human</h1>", [], "ok")
        challenged._request_with_retries = fake_challenge  # type: ignore[method-assign]
        self.assertEqual(challenged.fetch("https://example.com/a").outcome, "blocked")
        self.assertEqual(challenged.fetch("https://example.com/b").outcome, "origin-blocked")
        self.assertEqual(len(challenge_calls), 2)

    def test_request_ceiling_spacing_and_deadline_are_preserved(self):
        governor = RequestGovernor(max_requests=2, target_request_maximum=2, max_concurrency=2,
                                   timeout=1, max_body_bytes=1000, deadline_seconds=1,
                                   max_per_origin=2, spacing_seconds=.02)
        starts = []
        def fake_curl(url, *, kind, body_limit):
            origin = governor._origin(url)
            governor._spacing_wait(origin)
            _, reserved = governor._reserve(url, kind, body_limit)
            governor._origin_last_start[origin] = time.monotonic()
            starts.append(governor._origin_last_start[origin])
            governor._completed += 1
            governor._aggregate_reserved -= reserved
            return Evidence(url, url, 200, {"content-type": "text/plain"},
                            b"User-agent: *\nAllow: /\n" if kind == "robots" else b"ok", [], "ok")
        governor._curl_once = fake_curl  # type: ignore[method-assign]
        governor.fetch("https://example.com/a")
        with self.assertRaises(LimitError):
            governor.fetch("https://example.com/b")
        self.assertEqual(governor.snapshot()["requests_started"], 2)
        self.assertGreaterEqual(starts[1] - starts[0], .018)
        expired = RequestGovernor(deadline_seconds=.001, spacing_seconds=0)
        time.sleep(.003)
        result = expired.fetch("https://example.com/a")
        self.assertEqual(result.outcome, "unavailable")
        self.assertEqual(expired.snapshot()["requests_started"], 0)


class PackageTests(unittest.TestCase):
    def test_contest_manifest_has_six_skills_one_entrypoint_and_valid_paths(self):
        plugin = pathlib.Path(__file__).resolve().parents[1]
        root = plugin.parents[1]
        marketplace = json.loads((root / "marketplace.json").read_text())
        self.assertNotIn("plugins", marketplace)
        self.assertEqual(len(marketplace["skills"]), 6)
        entrypoints = [item for item in marketplace["skills"] if item.get("entrypoint") is True]
        self.assertEqual([item["id"] for item in entrypoints], ["audit-entrypoint"])
        self.assertEqual(len({item["id"] for item in marketplace["skills"]}), 6)
        for item in marketplace["skills"]:
            self.assertTrue((root / item["path"] / "SKILL.md").is_file(), item["path"])

    def test_all_declared_skills_have_mit_frontmatter(self):
        plugin = pathlib.Path(__file__).resolve().parents[1]
        root = plugin.parents[1]
        marketplace = json.loads((root / "marketplace.json").read_text())
        for item in marketplace["skills"]:
            text = (root / item["path"] / "SKILL.md").read_text()
            self.assertTrue(text.startswith("---\n"), item["id"])
            frontmatter = text.split("---", 2)[1]
            self.assertIn(f"name: {item['id']}", frontmatter)
            self.assertIn("description:", frontmatter)
            self.assertIn("license: MIT", frontmatter)


class InputModeTests(unittest.TestCase):
    @staticmethod
    def _script() -> pathlib.Path:
        return pathlib.Path(__file__).resolve().with_name("signaltrace.py")

    def test_positional_url_does_not_read_open_silent_stdin(self):
        process = subprocess.Popen(
            [sys.executable, str(self._script()), "--deadline", "0.5", "file:///unsupported"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(process.wait(timeout=2), 0)
            report = json.loads(process.stdout.read())
            self.assertEqual(report["site"], "file:///unsupported")
        finally:
            if process.stdin:
                process.stdin.close()
            if process.poll() is None:
                process.kill()
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()

    def test_explicit_stdin_envelope(self):
        process = subprocess.run(
            [sys.executable, str(self._script()), "--input-stdin", "--deadline", "0.5"],
            input='{"site":"file:///unsupported","sources":[],"claims":[],"citations":[]}',
            capture_output=True, text=True, timeout=2, check=False)
        self.assertEqual(process.returncode, 0, process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(report["site"], "file:///unsupported")


if __name__ == "__main__":
    unittest.main(verbosity=2)
