# Contributing to LxPerun

Thanks for helping improve LxPerun.

## Workflow

1. Create a branch for your change.
2. Keep changes small and focused.
3. Run the test suite before opening a PR.
4. Update `README.md` if you add or change user-facing behavior.

## Local checks

```bash
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -q
python -m lxperun.cli help
```

## Style

- Prefer clear, minimal changes.
- Keep user-facing output in English.
- Keep new dependencies to a minimum.
- Add or update tests when behavior changes.

## Release notes

If your change affects packaging, release flow, or CLI flags, mention it in the PR
description so it is easier to include in release notes.
