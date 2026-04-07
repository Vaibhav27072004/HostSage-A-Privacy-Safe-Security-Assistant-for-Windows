# Contributing to HostSage

Thank you for your interest in improving HostSage.

This project is open source, and contributions are welcome from:

- students
- security learners
- Python developers
- Windows users
- researchers and practitioners who want to make security easier to understand

## Good Ways to Contribute

- improve alert explanations for beginners
- strengthen privacy-safe report redaction
- add tests
- improve Windows usability and terminal workflows
- fix bugs
- improve documentation
- propose carefully designed detection improvements

## Before You Open a Pull Request

1. Create a branch for your change.
2. Keep changes focused and easy to review.
3. Add or update tests when behavior changes.
4. Run the test suite:

```powershell
python -m unittest discover -s tests -v
```

5. Make sure no sensitive runtime data from `logs/` is included.

## Contribution Guidelines

- prefer clear, readable code over clever code
- preserve the beginner-friendly and privacy-safe direction of the project
- avoid committing local logs, databases, or personal configuration
- update documentation when you add or change user-facing behavior

## Reporting Issues

When opening an issue, try to include:

- what you expected
- what actually happened
- steps to reproduce
- your environment details if relevant

If the issue involves sensitive machine data, do not paste raw logs publicly. Use a privacy-safe summary instead.

## Project Direction

HostSage is not only about detecting suspicious behavior. It is also about:

- making alerts understandable
- making incident review easier for normal users
- making sharing safer through privacy-aware reporting

Contributions that support this direction are especially encouraged.
