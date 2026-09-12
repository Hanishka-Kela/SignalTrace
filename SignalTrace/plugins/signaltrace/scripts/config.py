#!/usr/bin/env python3
"""Single source of configurable SignalTrace benchmark defaults."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Limits:
    global_request_maximum: int = 20
    target_request_maximum: int = 16
    per_origin_maximum: int = 8
    same_origin_concurrency: int = 1
    cross_origin_concurrency: int = 2
    request_timeout_seconds: float = 8.0
    connection_timeout_seconds: float = 3.0
    response_body_limit_bytes: int = 2 * 1024 * 1024
    aggregate_body_limit_bytes: int = 12 * 1024 * 1024
    same_origin_spacing_seconds: float = 2.0
    retries: int = 0
    global_deadline_seconds: float = 30.0
    maximum_redirects: int = 5
    robots_body_limit_bytes: int = 256 * 1024
    selected_link_maximum: int = 5
    skipped_link_evidence_maximum: int = 50


DEFAULTS = Limits()
USER_AGENT = "SignalTrace/1.0"
