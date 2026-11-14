# Contributing to Dep-Hunter

Thanks for helping improve Dep-Hunter. Contributions must preserve its passive,
read-only, authorization-first design.

## Before contributing

- Use the tool only against targets with explicit authorization.
- Never include real target data, scope files, tokens, evidence, or generated reports
  in an issue, pull request, test fixture, or commit.
- Do not add package publishing, installation, callback, exploitation, or
  state-changing target functionality.
- Report security issues in the tool privately as described in
  [`SECURITY.md`](SECURITY.md), not in a public issue.

## Development setup

```bash
git clone https://github.com/chinnuy93/dep-hunter.git
cd dep-hunter
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m pytest -q
```

Required checks before opening a pull request:

```bash
python -m pytest -q
python -m compileall -q dephunter tests
python -m build
```

## Pull requests

- Keep changes focused and explain the behavior being changed.
- Add or update tests for parser, scope, safety, reporting, or CLI changes.
- Preserve the GET/HEAD-only, scope-enforced, no-execution invariants.
- Treat registry errors as unknown, never as evidence that a package is absent.
- Keep report and CLI output deterministic and script-friendly.
- Update documentation when user-facing behavior changes.
- Match the existing code style and type-hint conventions.
- Do not commit generated files such as `.venv`, `dist/`, `dep-hunter-data/`, or
  `reports/`.

## Test fixtures

Use synthetic package names, hosts, and manifests. Preferred fixtures use reserved
domains such as `example.com`, loopback services bound to ephemeral ports, and fake
tokens that are clearly marked as test values.

## License

By contributing, you agree that your contribution is licensed under the project's MIT
License.
