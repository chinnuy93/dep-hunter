# Threat Model

## 1. System overview

Dep-Hunter is an offline-first security research tool. It fetches public
content from explicitly scoped hosts, parses untrusted manifests, queries
public registries, stores evidence locally, and produces reports. It has no
server, no agent, no callback listener, and no publishing capability.

## 2. Assets

- The user's local machine and credentials (GitHub token, registry tokens in
  fetched `.npmrc`/NuGet configs).
- The scan database, evidence archive, and generated reports.
- Third-party target availability and integrity.
- Public registry availability.
- The integrity of the tool's findings and the reputation of the researcher.

## 3. Trust boundaries

| Boundary | Untrusted side | Trusted side |
|---|---|---|
| Network | target assets, GitHub API, registries | scanner process |
| Parsers | manifest/lockfile/JS/XML/TOML/YAML content | in-memory models |
| Persistence | SQLite rows, evidence files | reporting |
| CLI input | scope file, flags, environment | execution policy |
| Reports | repository metadata, publisher strings | rendered report |

## 4. Adversaries and failure modes

### A1 — SSRF / scope escape by a malicious target

A crawled page links to `http://169.254.169.254/`, `http://127.0.0.1:8080/`, or
an external domain; a redirect points elsewhere.

Mitigations:

- All requests go through `SafeHttpClient` with an allowlisted host policy.
- Redirects are manual, capped, loop-detected, and re-validated at every hop.
- DNS answers are resolved and rejected if private/loopback/link-local/reserved
  unless the scope explicitly permits private hosts (tests only).
- Registry and GitHub hosts are fixed, not derived from crawled data.
- Only GET/HEAD are implemented.

### A2 — Malicious manifest content (parser exploitation / DoS)

Billion-laughs XML, huge JSON/TOML files, deeply nested YAML, pathological
regexes, or enormous lockfiles.

Mitigations:

- Per-artifact size caps (default 5 MiB, JS/source maps 8 MiB).
- XML containing `<!DOCTYPE` or `<!ENTITY` is rejected before parsing.
- `yaml.safe_load` only.
- `tomllib` and `json` standard parsers with size caps.
- Bounded iteration counts and warning records instead of crashes.
- Parse errors are recorded as warnings; a failed parse never fabricates
  findings.

### A3 — Credential leakage from fetched configuration

Leaked `.npmrc` `_authToken`, NuGet `packageSourceCredentials`, or CI secrets
could end up in logs, the database, or reports.

Mitigations:

- Secret-bearing keys are detected and stored as `[REDACTED]` markers only.
- A logging filter redacts token-like strings (`npm_`, `ghp_`, `Authorization`,
  `_authToken`, passwords).
- Reports never include raw fetched content; they include bounded excerpts
  chosen by parsers (package names, registry URLs, line references).
- CLI and environment GitHub/GitLab tokens are not written to the database or
  reports. Configuration files are user-managed; never commit one containing a
  token.

### A4 — False accusations / report integrity

A registry timeout mistaken for absence, a scoped public package mistaken for
an internal name, or an explicitly pinned local dependency reported as
confusion.

Mitigations:

- `ERROR` vs `MISSING` vs `EXISTS` are distinct; errors never feed findings.
- Explicit local/VCS/direct URLs are excluded from findings.
- A public package with a repository/owner link to the target is marked
  likely-owned and excluded from findings.
- CONFIRMED requires resolution-contradiction evidence; everything else is
  capped.
- Every finding lists supporting evidence and missing evidence.
- Reports state that target-side confirmation requires written authorization.

### A5 — Target or registry abuse (availability)

Aggressive crawling, querying thousands of lockfile entries, or ignoring
robots.txt.

Mitigations:

- Per-host rate limiting, global concurrency caps, timeouts, retries with
  backoff and jitter, `Retry-After` handling.
- robots.txt compliance with crawl-delay; 5xx robots means skip host.
- URL, depth, repository, file, history, and registry-query limits.
- Registry cache with TTL; no cache of transient failures (avoids hammering).
- Conservative default of 2 req/s for web, 5 req/s for npm/PyPI, 1 req/s for
  crates.io (their published guidance).
- Scope file requires program and authorization metadata.

### A6 — Supply-chain compromise of the tool itself

Malicious PyPI dependency, postinstall script, or optional tool installation.

Mitigations:

- Two runtime dependencies only: aiohttp and PyYAML, pinned in
  `requirements.lock`.
- No install-time scripts in this project.
- Optional ecosystem CLIs are never required for scanning and are detected,
  not installed, by this tool.
- The scanner never downloads or executes packages from scanned ecosystems;
  manifests are parsed as data.
- Registry evidence is parsed from documented JSON/XML endpoints over HTTPS.

### A7 — Evidence tampering / non-reproducibility

Edited evidence files or inconsistent reports.

Mitigations:

- Evidence is content-addressed by SHA-256; rows store hashes.
- Reports cite immutable references (URL + SHA-256, or repo + commit + path).
- Analysis can be re-run against stored rows and registry cache.

### A8 — Privacy and data retention

Evidence may include public-but-sensitive metadata.

Mitigations:

- Evidence access is local; no telemetry.
- Reports include only dependency evidence relevant to findings.
- Users can delete the data directory; the tool does not write outside it
  except the optional config file and report output directory.

## 5. Explicitly out of scope

- Package publishing, name reservation, and callback verification (the
  platform marks these as requiring written authorization and never performs
  them).
- Authenticated scanning of private registries or private repositories.
- Denial-of-service payloads, credential collection, persistence, lateral
  movement.
- Automated submission of bug bounty reports.

## 6. Security invariants enforced in code

1. No HTTP method other than GET/HEAD.
2. No URL outside the scope policy reaches the socket.
3. No private-range destination unless scope explicitly allows it.
4. No secret values stored or logged.
5. No finding without a successful authoritative registry response.
6. No CONFIRMED classification without static resolution-contradiction
   evidence.
7. No package installation or execution anywhere in the codebase.
