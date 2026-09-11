# SignalTrace

> Trace what an AI can find, what it can prove, and where the visitor ends up.

SignalTrace is a recommendation-only, read-only Agent Skill marketplace package for the Adobe University Hackathon Round 3. It audits public HTTP(S) pages for AI discoverability, citation correctness, and the on-site route an AI-referred visitor receives. It never changes the target site and uses only the Python standard library.

## Package layout

The repository-level `marketplace.json` exposes one local plugin, `plugins/signaltrace`. The plugin contains exactly five Agent Skills. `audit-entrypoint` is the only implicitly invokable entrypoint; the other four skills are bounded specialists used by it.

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
printf '%s' '{"site":"https://example.com/product","sources":["https://publisher.example/review"],"claims":[{"entity":"Widget","predicate":"price","value":"19.99","unit":"USD","region":"US","source_location":"target"}]}' | python3 plugins/signaltrace/scripts/signaltrace.py
```

Useful limits:

```bash
python3 plugins/signaltrace/scripts/signaltrace.py \
  --max-requests 12 --max-concurrency 3 --deadline 30 \
  --timeout 8 --max-body-bytes 1500000 https://example.com/
```

The request count includes `robots.txt`. Redirects are followed manually, each new origin is checked first, URLs are deduplicated, private/reserved network targets are rejected, and a denial is never retried through an alternate identity or URL. `robots.txt` 401/403, redirects, malformed responses, or temporary failures are treated as unavailable/denied; 404/410 means no policy was published.

Source verification is intentionally opt-in: only URLs explicitly provided in `sources` are fetched. If none are provided, that check reports `not assessed` through coverage rather than inventing corroboration.

## Input contract

The CLI accepts either a positional URL or one stdin JSON object:

- `site` (required): public `http` or `https` URL.
- `sources` (optional): targeted external evidence URLs.
- `claims` (optional): scoped claim objects using the fields in `references/audit-contract.md`.

CLI options override the default resource limits. Exit code `0` means a valid audit report was emitted, including reports where access was denied or the URL is outside the supported public HTTP(S) scope. Exit code `2` is reserved for a missing or malformed input envelope, for which no audit JSON can be constructed.

## Validate

```bash
python3 plugins/signaltrace/scripts/self_test.py
python3 /path/to/skill-creator/scripts/quick_validate.py plugins/signaltrace/skills/audit-entrypoint
python3 /path/to/plugin-creator/scripts/validate_plugin.py plugins/signaltrace
```

SignalTrace is diagnostic. Its findings are evidence-bound recommendations, not claims about traffic, conversion, demand, or guaranteed AI citation.
