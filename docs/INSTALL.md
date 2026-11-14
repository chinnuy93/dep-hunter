# Installation

Dep-Hunter is a Python 3.11+ command-line application. PyPI publication is not
available yet, so the supported installation path is a source checkout.

## Supported platforms

- Linux (CI-tested)
- macOS (expected to work; not part of CI)
- WSL2 (recommended for Windows users)
- Native Windows is not currently part of CI; use WSL2 if possible

## Prerequisites

- Python 3.11 or newer
- `git`
- A shell with `python3`, `pip`, and `venv`
- Network access to the targets and public registries you are authorized to query

Check Python:

```bash
python3 --version
```

If your distribution splits the standard library, install the venv package first.
On Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
```

Do not install Dep-Hunter with `sudo`. Install it into a virtual environment.

## Recommended install

```bash
git clone https://github.com/chinnuy93/dep-hunter.git
cd dep-hunter
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Verify:

```bash
dep-hunter --version
dep-hunter doctor
```

`dep-hunter doctor` checks the Python version, runtime dependencies, writable data and
report directories, and optional ecosystem tools. Optional tools such as `node`,
`java`, or `docker` are not required for scanning.

## Development install

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
```

Run the package build check:

```bash
python -m build
```

The wheel and source distribution are written to `dist/`.

## Setup helper

After the project is installed, the CLI can create `.venv` and reinstall the project:

```bash
dep-hunter setup --yes
```

Install development dependencies as well:

```bash
dep-hunter setup --yes --dev
```

The helper writes a local `dep-hunter-data/setup-report.json` with the commands and
results. It only works from a source checkout containing `pyproject.toml`.

## Upgrade

From the checkout:

```bash
git pull --ff-only
source .venv/bin/activate
python -m pip install --upgrade -e .
```

Or use the helper:

```bash
dep-hunter update --yes --git
```

The `--git` flag runs `git pull --ff-only` before upgrading the editable install.

## Uninstall

```bash
deactivate
cd ..
rm -rf dep-hunter
```

Local scan data and reports are not removed automatically. Delete them explicitly if
you no longer need the evidence:

```bash
rm -rf dep-hunter/dep-hunter-data dep-hunter/reports
```

## WSL2 notes

- Clone the repository into the Linux filesystem (for example `~/tools/dep-hunter`)
  rather than `/mnt/c/...` for faster Python and SQLite performance.
- Keep the virtual environment inside the Linux filesystem as well.
- Use `python3 -m venv .venv` and `source .venv/bin/activate` as shown above.
- If a Windows browser or editor is used, the Linux path is still accessible from
  Windows through `\\wsl$`.

## Troubleshooting

### `dep-hunter: command not found`

Activate the virtual environment first:

```bash
source .venv/bin/activate
dep-hunter --version
```

Or call the environment directly:

```bash
.venv/bin/dep-hunter --version
```

### `externally-managed-environment`

The system Python is protected by PEP 668. Do not use `--break-system-packages`.
Create and use a virtual environment instead.

### `ModuleNotFoundError: No module named 'aiohttp.typedefs'`

This indicates an incomplete aiohttp installation, often caused by an interrupted
download. Reinstall the pinned runtime version:

```bash
python -m pip install --force-reinstall --no-cache-dir aiohttp==3.13.4
```

Then reinstall the project:

```bash
python -m pip install -e .
```

### `doctor` reports optional tools as missing

This is expected. Optional ecosystem CLIs improve environment reporting but are not
used for scanning. The required checks are Python, `aiohttp`, `PyYAML`, and writable
data/report directories.

### Reports are not generated

Check that the `report` phase ran. The default `scan` includes it; `--no-report`
skips it. Generate reports later with:

```bash
dep-hunter report --scan-id 1 --format md --format html --format json
```

### A scan is slow

Crawling and registry checks are deliberately rate-limited. Reduce `crawl.max_urls`,
`crawl.max_depth`, or `registries.query_limit` in the scope file. Do not raise request
rates beyond the target and registry policies.
