# Dep-Hunter Architecture

Dep-Hunter is a passive dependency-confusion discovery platform for explicitly
authorized bug bounty and penetration-testing engagements. It collects
dependency evidence from public target assets, enriches package names with
public registry intelligence, and classifies confusion risk with a conservative
evidence model. It never publishes, installs, or executes packages.

## Goals and non-goals

Goals:

- Discover internal-looking dependency names from JavaScript bundles, source
  maps, manifests, lockfiles, CI configuration, and public repositories.
- Parse ten package ecosystems and their lockfile/registry configuration.
- Correlate dependency names with public registry metadata.
- Distinguish "name is public" from "registry lookup failed" from "name is
  unclaimed".
- Explain every classification with reproducible, stored evidence.
- Support resumable, rate-limited, scope-enforced scans.
- Produce bug-bounty-grade Markdown, HTML, and JSON reports.

Non-goals (hard exclusions):

- Publishing or reserving packages on any registry.
- Installing target packages or running package lifecycle scripts.
- Callback servers, beaconing, credential collection, or exfiltration.
- Any state-changing request against a third party.
- Claiming a target is exploitable without static evidence.

## Data flow

```
 scope.yaml ──► ScopePolicy ──┐
                              ├──► SafeHttpClient (GET/HEAD only, host allowlist,
 user config ──► Settings ─────┘     private-IP guard, retries, throttling)
                                      │
            ┌─────────────────────────┼────────────────────────┐
            ▼                         ▼                        ▼
     WebCrawler                 GitHubHarvester          RegistryManager
  (robots.txt, JS, maps)     (trees, contents, history)  (npm, PyPI, Maven,
            │                         │                   NuGet, Go, RubyGems,
            │                         │                   Packagist, crates,
            ▼                         ▼                   Docker Hub)
      ArtifactStore ──────────► Extractors ──► SQLite (deps, config facts,
      (gzip evidence)            (10 ecosystems)   assets, registry cache)
                                      │
                                      ▼
                              AnalysisEngine
                     intent + routing + registry state
                     + contradiction evidence
                                      │
                                      ▼
                          Findings (confidence classes)
                                      │
                                      ▼
                        ReportManager (MD / HTML / JSON)
```

## Components

| Package | Responsibility |
|---|---|
| `dephunter/core` | Settings, scope policy, network policy, models, logging, HTTP, names |
| `dephunter/database` | SQLite schema, migrations, scan state, evidence metadata, cache |
| `dephunter/extractors` | Manifest/lockfile/config parsers, JS and source-map mining |
| `dephunter/registries` | Public registry clients, error semantics, rate limits, cache |
| `dephunter/crawler` | Async web crawl, URL discovery, robots, evidence capture |
| `dephunter/github` | Public GitHub harvesting (orgs/repos, files, history) |
| `dephunter/analysis` | Name heuristics, resolution routing, classification |
| `dephunter/verification` | Static-only verification narratives and guardrails |
| `dephunter/reporting` | Markdown, HTML, JSON report generation |
| `dephunter/setup` | OS/runtime detection, setup, doctor, update, install report |
| `dephunter/cli` | Command-line interface and orchestration |

## Scan lifecycle

A scan is a durable database record with phases. `scan` runs:

1. **crawl** (web assets, optional) — seed URLs from scope, fetch within policy,
   preserve evidence hashes, store discovered URLs, extract dependencies.
2. **github** (public repositories, optional) — enumerate configured orgs and
   repositories, fetch manifests at the default branch and (optionally) in
   history, deduplicate by content hash, extract dependencies.
3. **analyze** — group dependencies, decide which names need registry checks
   (internal intent first), query registries with caching, compute routing and
   contradiction evidence, classify, persist findings.
4. **report** — render Markdown/HTML/JSON from stored rows only.

Crawl and GitHub phases are resumable: discovered URLs and repository files are
persisted with statuses (`PENDING`, `FETCHED`, `PARSED`, `SKIPPED`, `ERROR`,
`DISALLOWED`). Re-running `crawl --scan-id N` continues pending work. Analysis
is idempotent: it regenerates registry checks and findings for that scan using
the registry cache, so re-analysis does not repeat network calls while the
cache is fresh.

## Data model (SQLite)

- `scans` — program, scope snapshot, phase/status, stats, timestamps.
- `assets` — crawled URLs, status, HTTP metadata, content hash, evidence path.
- `repo_files` — repository, path, commit/ref, content hash, status.
- `dependencies` — ecosystem, raw and normalized name, constraint, provenance
  (URL/path/line/commit), lockfile `resolved` URL, safe-source markers.
- `config_facts` — `.npmrc`/Pipfile/pom/Gemfile/Cargo/NuGet registry facts,
  redacted secrets markers, CI install commands.
- `registry_checks` — one per ecosystem+name per scan: EXISTS/MISSING/ERROR,
  versions, publisher, timestamps, URL, HTTP status, error.
- `findings` — classification, score, reasons, missing evidence, resolution
  JSON, CWE, title.
- `registry_cache` — TTL cache of successful and 404 responses. Transient
  failures are deliberately not cached.

Evidence bodies are stored gzip-compressed under `<data_dir>/evidence/<sha>.gz`;
only the hash and path are recorded in SQLite.

## Scope and network enforcement

Every outbound request passes through `SafeHttpClient`:

- Only `GET` and `HEAD`.
- URL must satisfy the scope policy:
  - web hosts (exact host, or subdomain when enabled), HTTP(S) only;
  - GitHub API host only for configured orgs/repos;
  - registry hosts are a fixed, code-defined allowlist.
- DNS results are checked against private, loopback, link-local, reserved,
  multicast, and unspecified ranges. Private targets require an explicit
  `allow_private_hosts: true` in the scope file (used by tests).
- Redirects are followed manually, re-validated at each hop, capped, and
  loop-detected.
- Response size caps, timeouts, retries with jitter, per-host rate limiting,
  and `Retry-After` handling.
- robots.txt is honored where configured; a 5xx robots response causes the
  host to be skipped rather than ignored.

There is no code path that issues `POST`/`PUT`/`PATCH`/`DELETE`, installs a
package, executes a shell command against a target, or contacts a callback.

## Confidence model

Classification is gate-based; a score is retained only to order findings.

- **CONFIRMED (static)** — internal intent + public package exists with no
  visible ownership relationship to the target + a *contradiction* proving a
  public resolution path. Contradictions are lockfile `resolved` URLs pointing
  at a public registry while the applicable registry configuration is private,
  or mixed private/public provenance for the same scope/ecosystem. Target-side
  confirmation still requires written authorization.
- **HIGH_CONFIDENCE** — internal intent + strong routing evidence (public
  registry reachable by default semantics or missing private pin) and either a
  publicly claimed package with no visible target ownership, or a package that
  is currently unclaimed publicly. No direct resolution contradiction.
- **CANDIDATE** — internal-looking name, unclaimed/claimed package, or an
  unqualified Docker image, without proof that resolution can select an
  unintended public package.
- **INSUFFICIENT_EVIDENCE** — registry errors, contradictory data, explicit
  local/VCS/direct-URL sources, or a public package plausibly owned by the
  target. Not reported as a finding.

Registry errors are never interpreted as "package does not exist". A `MISSING`
result requires an authoritative 404 from the ecosystem registry. Findings based
on missing registry data are excluded.

## Ecosystem routing semantics encoded

- **npm**: scoped registry pins only protect their scope; unscoped names use
  the default registry. Lockfile `resolved` URLs are provenance evidence.
  `file:`, `link:`, `workspace:`, git, and tarball deps are explicit-safe.
- **pip**: `--extra-index-url` adds PyPI/public indexes to the search set and
  pip chooses the highest version across indexes. A single private
  `--index-url` without extras removes the public path. Direct URLs/VCS are
  explicit-safe.
- **NuGet**: all configured sources participate unless `packageSourceMapping`
  pins an ID pattern; prefix reservation is noted but cannot be proven via API.
- **Maven/Gradle**: repository declarations and dynamic versions are captured;
  groupId ownership/squatting controls cap confidence.
- **Go**: module paths are domain-bound; private vanity domains are not
  squattable. Public proxy absence is not proof of private intent.
- **RubyGems**: source blocks and `git:`/`path:` pins are captured; unbounded
  global sources are the risk signal.
- **Composer**: canonical/private repositories and Packagist fallback are
  modeled; maintainer metadata is queried where available.
- **Cargo**: crates.io default, `path`/`git`/`registry` pins, and
  `.cargo/config.toml` source replacement are captured; workspace members are
  local-safe.
- **Docker**: Dockerfile/compose images; digest pins are safe, unqualified
  internal-looking names are candidates only.

## Resumability and idempotency

- URL and repo-file queues persist; completed work is skipped on resume.
- Dependency insertion is unique per scan + source location + name + constraint.
- Config facts are unique per scan + source + type + value.
- Analysis replaces prior registry checks/findings for the scan.
- Registry cache keys include ecosystem + normalized name + TTL; only
  authoritative 200/404 responses are cached.
- Reports are pure renderings of stored data.

## Extension points

- Add an extractor: subclass `BaseExtractor`, declare filename matchers,
  return dependencies/config facts; register in `extractors/__init__.py`.
- Add a registry: subclass `RegistryClient`, implement URL + parser, register
  in `RegistryManager`, and add the host to the fixed allowlist.
- Add a report format: render from the `ReportContext` assembled in
  `reporting/manager.py`.
