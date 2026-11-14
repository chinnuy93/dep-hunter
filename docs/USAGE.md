# Usage

This guide covers the normal authorized-assessment workflow. Read
[`THREAT_MODEL.md`](THREAT_MODEL.md) and the program policy before scanning.

## Before you scan

1. Confirm that the program permits dependency-confusion research, public web
   collection, and public repository review.
2. Record the policy, ticket, or engagement reference in the scope file.
3. Add only the in-scope web hosts, GitHub organizations/repositories, and GitLab
   projects.
4. Start with conservative crawl and query limits. Do not exceed the target's or
   registry's published rate limits.
5. Never test package ownership, publishing, callbacks, or exploitation without
   separate written authorization.

## Scope file

`program` and `authorization` are required. The authorization string must be at least
10 characters and should identify the basis for testing.

```yaml
program: "Example Bug Bounty Program"
authorization: "Program policy #0000, authorized 2026-01-01; public web and repo review only."
contact: "security-research@example.org"
allow_private_hosts: false

web:
  - url: "https://www.example.com"
    include_subdomains: true

github:
  orgs: ["example-org"]
  repos: ["example-org/frontend"]

registries:
  enabled: [npm, pypi, maven, nuget, go, rubygems, packagist, crates, docker]

analysis:
  org_patterns: ["example", "examplecorp"]
  min_classification: "CANDIDATE"
```

Use [`../examples/scope.example.yaml`](../examples/scope.example.yaml) as the full
reference.

### Scope fields

| Section | Field | Default / notes |
|---|---|---|
| root | `program` | Required; copied into reports |
| root | `authorization` | Required; copied into reports |
| root | `contact` | Recommended; included in the HTTP user agent |
| root | `allow_private_hosts` | `false`; set `true` only for tests or isolated labs |
| `web` | `url`, `include_subdomains` | At least one target is required unless GitHub/GitLab is configured |
| `crawl` | `max_depth` | `3` |
| `crawl` | `max_urls` | `500` |
| `crawl` | `concurrency` | `6` |
| `crawl` | `requests_per_second` | `2.0` |
| `crawl` | `respect_robots` | `true`; leave enabled for real targets |
| `crawl` | `source_maps` | `true`; mines JavaScript source maps |
| `crawl` | `probe_manifests` | `false`; only enable if policy permits direct manifest requests |
| `crawl` | `exclude_paths` | Optional path prefixes such as `/logout` |
| `github` | `orgs`, `repos` | Public repositories only |
| `github` | `include_history` | `true` |
| `github` | `history_commits_per_file` | `20` |
| `github` | `max_repos` | `50` |
| `github` | `max_files_per_repo` | `200` |
| `github` | `include_forks`, `include_archived` | `false`, `true` |
| `gitlab` | `projects` | Public GitLab project paths |
| `gitlab` | `include_history` | `false` |
| `gitlab` | `max_files_per_project` | `200` |
| `registries` | `enabled` | npm, pypi, maven, nuget, go, rubygems, packagist, crates, docker |
| `registries` | `query_limit` | `400` |
| `registries` | `cache_ttl_hours` | `24` |
| `registries` | `requests_per_second` | `5.0` |
| `analysis` | `org_patterns` | Organization names used for internal-intent scoring |
| `analysis` | `internal_keywords` | Defaults include `internal`, `private`, `corp`, `platform`, `shared` |
| `analysis` | `min_classification` | `CANDIDATE`, `HIGH_CONFIDENCE`, or `CONFIRMED` |

`probe_manifests` sends direct GET requests for conventional manifest paths. Keep it
disabled unless the target explicitly permits it.

## Scan phases

| Phase | What it does |
|---|---|
| `crawl` | Crawls authorized web assets and captures JavaScript, manifests, and source maps |
| `github` | Harvests public repository trees, files, and optional history |
| `gitlab` | Harvests public GitLab project files and optional history |
| `analyze` | Scores intent, routes dependency sources, queries registries, classifies findings |
| `report` | Renders Markdown, HTML, and JSON reports |

Run the default scan:

```bash
dep-hunter scan scope.yaml
```

Run selected phases:

```bash
dep-hunter scan scope.yaml --phase crawl
dep-hunter scan scope.yaml --phase crawl --phase github
dep-hunter scan scope.yaml --phase analyze --phase report
dep-hunter scan scope.yaml --phase all
```

`report` automatically adds `analyze` when needed. Use `--no-report` to skip report
generation. Report formats are `md`, `html`, and `json`; pass `--format` multiple
times or comma-separate values.

## Live progress and colours

The banner and progress display are written to stderr so stdout stays usable for
scripts. The display includes:

- current phase
- weighted percentage
- elapsed time
- crawl and registry counters
- completion status

Colours are enabled only when stderr is a TTY. Disable them with:

```bash
dep-hunter scan scope.yaml --no-color
NO_COLOR=1 dep-hunter scan scope.yaml
```

Set `CLICOLOR_FORCE=1` to force colour in a pipe. `TERM=dumb` also disables colour.

## Review findings

```bash
dep-hunter scans
dep-hunter show --scan-id 1
dep-hunter show --scan-id 1 --json
dep-hunter report --scan-id 1 --format md --format html --format json
```

Filter reports by confidence:

```bash
dep-hunter report --scan-id 1 --min-classification HIGH_CONFIDENCE
```

Each finding includes the ecosystem, package name, classification, score, evidence
references, missing evidence, and a static verification verdict. `CONFIRMED` means
static resolution evidence contradicts the intended private source; it does not mean a
package was published or compromised. Do not attempt target-side confirmation without
separate written authorization and an isolated environment.

## Re-run analysis and reports

Collection is stored in SQLite, so analysis and reporting can be repeated without
re-crawling:

```bash
dep-hunter analyze scope.yaml --scan-id 1
dep-hunter analyze scope.yaml --scan-id 1 --report
```

Resume collection phases by scan ID:

```bash
dep-hunter scan scope.yaml --scan-id 1 --phase crawl --phase github
```

Registry results are cached according to `registries.cache_ttl_hours`; authoritative
200/404 responses are cacheable, while errors are not.

## Tokens and rate limits

Public GitHub and GitLab content is available without authentication, but tokens raise
rate limits:

```bash
export DEPHUNTER_GITHUB_TOKEN="github_pat_..."
export DEPHUNTER_GITLAB_TOKEN="glpat-..."
dep-hunter scan scope.yaml
```

`GITHUB_TOKEN` and `GITLAB_TOKEN` are accepted as fallbacks. CLI/env tokens are not
written to the database or reports. Prefer env or CLI tokens; avoid putting secrets in
committed configuration files.

Lower limits if a scan is too slow or a target requests it:

```yaml
crawl:
  max_urls: 100
  max_depth: 2
  requests_per_second: 1

registries:
  query_limit: 100
  requests_per_second: 2
```

## Local data

| Path | Contents |
|---|---|
| `dep-hunter-data/dep-hunter.sqlite3` | Scans, dependencies, findings, registry cache |
| `dep-hunter-data/evidence/` | Content-addressed evidence bodies |
| `dep-hunter-data/setup-report.json` | Latest setup/update result |
| `reports/` | Generated Markdown, HTML, and JSON reports |

Override locations with `--data-dir`, `--reports-dir`, or the
`DEPHUNTER_DATA_DIR` / `DEPHUNTER_REPORTS_DIR` environment variables.

Back up `dep-hunter-data/` if you need to keep an audit trail. Delete it to remove all
local scan state. Reports can contain target metadata; handle them according to the
program's disclosure policy.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Operational failure, unhealthy doctor result, or setup/update failure |
| `2` | Configuration, scope, argument, or lookup error |
| `130` | Interrupted |

## Troubleshooting

- **All phases skipped:** add at least one web target, GitHub org/repo, or GitLab
  project, and confirm the registries you need are enabled.
- **Lots of skipped registry checks:** inspect the scan warnings and increase
  `registries.query_limit` only if it is consistent with program policy.
- **Crawl is slow:** leave `respect_robots: true`; reduce `max_urls` and `max_depth`
  rather than bypassing rate limits.
- **No findings:** this is a normal result. Review warnings and evidence before
  assuming the target is clear.
- **Report says `INVALID`:** the static verification guardrail rejected the evidence;
  do not report it without independent, authorized confirmation.
