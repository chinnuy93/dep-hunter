# Dep-Hunter

[![CI](https://github.com/chinnuy93/dep-hunter/actions/workflows/ci.yml/badge.svg)](https://github.com/chinnuy93/dep-hunter/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Status: beta](https://img.shields.io/badge/status-beta-orange)](#project-status)

**Passive, read-only dependency-confusion discovery for authorized security research.**

Dep-Hunter maps public web assets and public repositories, extracts dependency
references from ten package ecosystems, checks public registry metadata, and produces
evidence-backed Markdown, HTML, and JSON reports. It is built for bug-bounty,
penetration-testing, and supply-chain review work where the target has explicitly
authorized this kind of testing.

> [!WARNING]
> **Authorized targets only.** Use Dep-Hunter only against programs that explicitly
> permit dependency-confusion research and public-asset collection. The tool never
> publishes packages, installs target dependencies, executes target code, sends
> callbacks, or performs target-side exploitation. A finding is a static indicator,
> not proof of compromise.

## What it does

- Crawls authorized public web assets with GET/HEAD only, respecting `robots.txt`,
  scope, redirects, DNS/IP policy, and response-size limits.
- Harvests public GitHub and GitLab repository trees, files, and optional history.
- Parses npm, PyPI, Maven, NuGet, Go, RubyGems, Packagist, crates.io, Cargo, Docker,
  and CI configuration.
- Detects internal-looking names, public registry presence, missing packages, and
  static resolution contradictions.
- Classifies findings as `CONFIRMED`, `HIGH_CONFIDENCE`, `CANDIDATE`, or
  `INSUFFICIENT_EVIDENCE` with explicit supporting and missing evidence.
- Produces reports with run time, scan progress, per-phase timings, confidence badges,
  verification verdicts, and reproducible evidence references.
- Stores scan state locally in SQLite so analysis and reports can be re-run without
  repeating collection.

## What it never does

- Publish, reserve, or install packages.
- Run package lifecycle scripts or target code.
- Send callbacks, beacons, or exfiltration requests.
- Make POST/PUT/PATCH/DELETE requests against targets.
- Treat a timeout, rate-limit, or API error as proof that a package is unclaimed.
- Submit reports to a bug-bounty platform automatically.
- Collect credentials or scan private/authenticated repositories.

## Requirements

- Python **3.11 or newer**
- Network access to the targets and public registries listed in the scope file
- Linux, macOS, or WSL2 recommended (CI covers Linux; native Windows is not currently
  part of CI)

Optional ecosystem CLIs such as `node`, `npm`, `java`, `ruby`, `cargo`, `go`, `dotnet`,
and `docker` are **not required** for scanning. `dep-hunter doctor` reports whether
they are present.

## Install

PyPI publication is not available yet; install from a source checkout.

### 1. Clone the repository

```bash
git clone https://github.com/chinnuy93/dep-hunter.git
cd dep-hunter
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

On native Windows, activate with `.venv\Scripts\activate` instead, but WSL2 is
recommended for the intended workflow.

### 3. Install

```bash
python -m pip install --upgrade pip
python -m pip install -e .
```

For development and tests:

```bash
python -m pip install -e '.[dev]'
```

### 4. Verify

```bash
dep-hunter --version
dep-hunter doctor
```

The repository also includes a setup helper that creates `.venv` and installs the
project in editable mode:

```bash
dep-hunter setup --yes
```

### Upgrade

```bash
git pull --ff-only
source .venv/bin/activate
python -m pip install --upgrade -e .
```

Or use the built-in helper from a source checkout:

```bash
dep-hunter update --yes --git
```

### Uninstall

Deactivate the environment, then remove the checkout and its local data:

```bash
deactivate
rm -rf .venv dep-hunter-data reports
```

## Quick start

### 1. Create a scope file

Copy the example and edit the authorization details and targets. `program` and
`authorization` are mandatory and are copied into every report.

```bash
cp examples/scope.example.yaml scope.yaml
```

Minimal example:

```yaml
program: "Example Bug Bounty Program"
authorization: "Program policy #0000, authorized 2026-01-01; public web and repo review only."
contact: "security-research@example.org"

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

See [`examples/scope.example.yaml`](examples/scope.example.yaml) for every option.

### 2. Check the environment

```bash
dep-hunter doctor
```

### 3. Run a scan

```bash
dep-hunter scan scope.yaml
```

The default scan runs web crawl, GitHub/GitLab harvesting, analysis, and report
generation. A live banner and progress bar show the phase, percentage, elapsed time,
and counters. Colours are enabled only on a TTY; use `--no-color` or `NO_COLOR=1` to
disable them.

Run selected phases or skip reports:

```bash
dep-hunter scan scope.yaml --phase crawl --phase github
dep-hunter scan scope.yaml --no-report
dep-hunter scan scope.yaml --format md --format json
```

Resume or re-analyze an existing scan:

```bash
dep-hunter scan scope.yaml --scan-id 1 --phase analyze
dep-hunter analyze scope.yaml --scan-id 1 --report
```

### 4. Review results

```bash
dep-hunter scans
dep-hunter show --scan-id 1
dep-hunter show --scan-id 1 --json
dep-hunter report --scan-id 1 --format html --format md --format json
```

Reports are written to `reports/` by default:

```text
reports/dep-hunter-<program>-<scan-id>-<timestamp>.md
reports/dep-hunter-<program>-<scan-id>-<timestamp>.html
reports/dep-hunter-<program>-<scan-id>-<timestamp>.json
```

Local scan state is stored in `dep-hunter-data/dep-hunter.sqlite3`, and evidence is
kept under `dep-hunter-data/evidence/`.

## Commands

| Command | Purpose |
|---|---|
| `scan` | Run a scoped scan and optionally generate reports |
| `analyze` | Re-run analysis for an existing scan |
| `report` | Render Markdown, HTML, and/or JSON reports |
| `scans` | List recent scans |
| `show` | Show one scan and its findings |
| `doctor` | Check tools, dependencies, and writable directories |
| `setup` | Create a virtual environment and install Dep-Hunter |
| `update` | Upgrade the virtual-environment installation |

Use `--config`, `--data-dir`, and `--reports-dir` to override local defaults.
`--github-token` and `--gitlab-token` are accepted for public API rate limits and are
not persisted.

## Scope and safety model

- Scope enforcement is mandatory: every target must be listed in the scope file.
- Private, loopback, link-local, and reserved destinations are rejected unless the
  scope explicitly sets `allow_private_hosts: true` for tests or an isolated lab.
- Only GET and HEAD requests are implemented.
- Redirects are manual, bounded, loop-detected, and re-validated at every hop.
- `robots.txt` is respected with crawl-delay handling.
- Registry and GitHub/GitLab hosts are fixed and never derived from crawled content.
- Network errors and registry API failures never become findings.
- Explicit local, VCS, or direct-URL dependencies are excluded from confusion findings.
- A public package with a visible repository or owner link to the target is treated as
  likely owned and excluded.

Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full threat model and
invariants.

## How it works

```text
scope.yaml ──► scope policy ──► safe HTTP client ──► crawl / GitHub / GitLab
                                      │
                                      ▼
                             extractors + evidence
                                      │
                                      ▼
                          SQLite + public registry cache
                                      │
                                      ▼
                     analysis + static verification
                                      │
                                      ▼
                       Markdown / HTML / JSON reports
```

The pipeline is resumable by scan ID. Each phase records timing and progress in scan
stats, so reports include the actual run duration and completion percentage.

## Confidence model

| Classification | Meaning |
|---|---|
| `CONFIRMED` | Internal intent, public package exists without visible target ownership, and static resolution evidence contradicts the intended private source |
| `HIGH_CONFIDENCE` | Strong public routing plus internal-intent signals, but not all confirmation evidence is present |
| `CANDIDATE` | Internal-looking, unclaimed, or unqualified package reference that needs review |
| `INSUFFICIENT_EVIDENCE` | Registry errors, explicit local/VCS sources, likely-owned packages, or ambiguous routing |

Go and Docker findings are capped at `CANDIDATE`; Maven and NuGet findings are capped at
`HIGH_CONFIDENCE`. Reports include verification verdicts: `READY_FOR_REVIEW`,
`NEEDS_REVIEW`, or `INVALID`.

## Configuration

The optional config file is `~/.config/dep-hunter/config.toml`:

```toml
data_dir = "/home/me/.local/share/dep-hunter"
reports_dir = "/home/me/dep-hunter-reports"
user_agent_contact = "security@example.org"
log_level = "INFO"
```

Environment overrides:

| Variable | Purpose |
|---|---|
| `DEPHUNTER_DATA_DIR` | Scan database and evidence directory |
| `DEPHUNTER_REPORTS_DIR` | Report output directory |
| `DEPHUNTER_CONTACT` | Contact string in the HTTP user agent |
| `DEPHUNTER_GITHUB_TOKEN` | GitHub API token (fallback: `GITHUB_TOKEN`) |
| `DEPHUNTER_GITLAB_TOKEN` | GitLab API token (fallback: `GITLAB_TOKEN`) |
| `NO_COLOR` | Disable ANSI colours |

Tokens are used only for API requests and are not written to the database or reports.

## Documentation

- [`docs/INSTALL.md`](docs/INSTALL.md) — detailed install, upgrade, uninstall, and
  troubleshooting steps
- [`docs/USAGE.md`](docs/USAGE.md) — scope fields, scan workflow, reports, and
  troubleshooting
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — components, data flow, and scan
  lifecycle
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — adversaries, mitigations, and
  security invariants
- [`CHANGELOG.md`](CHANGELOG.md) — release history

## Development

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
python -m compileall -q dephunter tests
python -m build
```

The focused crawl integration test is:

```bash
python -m pytest tests/integration/test_crawl_pipeline.py -q
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request. Do not include
real target data, authorization files, tokens, or generated reports in commits.

## Project status

Dep-Hunter is beta software. The core collection, analysis, reporting, and safety
controls are covered by tests, but interfaces may change before a stable release.
Security issues in the tool itself should be reported privately as described in
[`SECURITY.md`](SECURITY.md), not in a public issue.

## License

MIT. See [`LICENSE`](LICENSE).
