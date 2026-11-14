# Changelog

All notable changes to Dep-Hunter are documented here.

## [1.0.0] - 2026-11-14

Initial public release.

### Added

- Passive, scope-enforced crawling with GET/HEAD-only requests, robots.txt support,
  manual redirect validation, and private-address protection.
- Public GitHub and GitLab harvesting with bounded repository, file, and history
  collection.
- Extractors for npm, PyPI, Maven, NuGet, Go, RubyGems, Packagist, crates.io, Cargo,
  Docker, and CI configuration.
- Public registry clients with authoritative-response handling, caching, rate limits,
  and error semantics that never convert failures into findings.
- Intent, routing, classification, and static verification engines with conservative
  confidence caps.
- SQLite-backed scans, evidence storage, resumable phases, and registry caching.
- Markdown, standalone HTML, and JSON reports with evidence references, verification
  verdicts, runtime, progress, and per-phase timings.
- Coloured CLI with an ASCII banner, live weighted progress, elapsed time, scan
  summaries, and `--no-color` / `NO_COLOR` support.
- `doctor`, `setup`, and `update` commands for local environment management.
- Test suite covering extraction, scope enforcement, HTTP safety, database behavior,
  registry semantics, analysis, reporting, CLI behavior, and a local crawl integration
  flow.
- Public documentation, threat model, architecture notes, install and usage guides,
  security policy, contributing guide, and CI workflow.

[1.0.0]: https://github.com/chinnuy93/dep-hunter/releases/tag/v1.0.0
