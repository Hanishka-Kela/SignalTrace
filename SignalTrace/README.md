# SignalTrace

> Trace what an AI can find, what it can prove, and where the visitor ends up.

SignalTrace is a recommendation-only, read-only Agent Skill marketplace package for the Adobe University Hackathon Round 3. It audits public HTTP(S) pages for AI discoverability, citation correctness, and the on-site route an AI-referred visitor receives. It never changes the target site. Python uses the installed `curl` executable for all HTTP traffic; no Python networking package is used.

## Package layout

The repository-level contest `marketplace.json` declares exactly five Agent Skills. `audit-entrypoint` is its only entrypoint; the other four skills are bounded specialists used by it. `.codex-plugin/plugin.json` remains separate optional Codex package metadata and is not the contest manifest.

```text
marketplace.json
plugins/signaltrace/
  .codex-plugin/plugin.json
  scripts/
  references/
  skills/
    audit-entrypoint/
    structured-data-audit/
    content-engagement-audit/
    citation-destination-audit/
    source-verification-audit/
```

## Run an audit

Python 3.10+ is sufficient. Output is exactly one JSON value on stdout; diagnostics and usage errors go to stderr.

```bash
python3 plugins/signaltrace/scripts/signaltrace.py https://example.com/
```

Optional bounded evidence can be supplied through a JSON envelope on stdin:

```bash
printf '%s' '{"site":"https://example.com/product","sources":["https://publisher.example/review"],"claims":[{"entity":"Widget","predicate":"price","value":"19.99","unit":"USD","region":"US","source_location":"target"}]}' | python3 plugins/signaltrace/scripts/signaltrace.py --input-stdin
```

Useful limits:

```bash
python3 plugins/signaltrace/scripts/signaltrace.py \
  --max-requests 20 --target-request-maximum 16 --max-per-origin 8 \
  --max-concurrency 2 --deadline 30 --timeout 8 --connect-timeout 3 \
  --max-body-bytes 2097152 --aggregate-body-bytes 12582912 \
  --spacing 2 --retries 0 https://example.com/
```

All defaults live in `plugins/signaltrace/scripts/config.py`. Request and per-origin counts include `robots.txt`, redirect hops, and retries. Redirects are advanced manually, each new origin is checked first, same-origin requests are serialized and spaced, cross-origin concurrency is capped at two, every response is cached, URLs are deduplicated, aggregate bytes are bounded, and private/reserved targets are rejected. A denial is never retried through an alternate identity or URL. Robots results distinguish denial, missing policy, unreachable policy, timeout, HTTP error, and parser error.

Source verification is intentionally opt-in: only URLs explicitly provided in `sources` are fetched. If none are provided, that check reports `not assessed` through coverage rather than inventing corroboration.

## Input contract

The CLI accepts either a positional URL or one stdin JSON object. Positional URL mode never reads stdin, including when stdin is an inherited open pipe. JSON-envelope mode reads stdin only when `--input-stdin` is present.

- `site` (required): public `http` or `https` URL.
- `sources` (optional): targeted external evidence URLs.
- `claims` (optional): scoped claim objects using the fields in `references/audit-contract.md`.

Every audit is read-only: SignalTrace does not modify a live website, submit forms, or trigger site actions. Requests remain bounded, politely spaced, and robots.txt-aware under the shared governor.

CLI options override the default resource limits. Exit code `0` means a valid audit report was emitted, including reports where access was denied or the URL is outside the supported public HTTP(S) scope. Exit code `2` is reserved for a missing or malformed input envelope, for which no audit JSON can be constructed.

## Validate

```bash
python3 plugins/signaltrace/scripts/self_test.py
python3 /path/to/skill-creator/scripts/quick_validate.py plugins/signaltrace/skills/audit-entrypoint
python3 /path/to/plugin-creator/scripts/validate_plugin.py plugins/signaltrace
```

SignalTrace is diagnostic. Its findings are evidence-bound recommendations, not claims about traffic, conversion, demand, or guaranteed AI citation.
