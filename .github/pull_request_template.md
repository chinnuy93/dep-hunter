## Summary

Describe the change and why it is needed.

## Testing

- [ ] `python -m pytest -q`
- [ ] `python -m compileall -q dephunter tests`
- [ ] `python -m build`

## Safety checklist

- [ ] The change preserves GET/HEAD-only, scope-enforced, passive behavior.
- [ ] No publishing, installation, execution, callback, or exploitation behavior was added.
- [ ] Registry errors are not treated as package absence.
- [ ] Tests use synthetic targets and do not contain real target data, tokens, or reports.
- [ ] Documentation was updated for user-facing behavior changes.
