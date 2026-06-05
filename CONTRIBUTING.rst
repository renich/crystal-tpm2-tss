============
Contributing
============

First off, thank you for considering contributing to the EVALinux Crypto Suite! It's people like you that make open-source secure and robust.

Code of Honor
=============

This project strictly adheres to the `Code of Honor <docs/technical/CODE_OF_HONOR.rst>`_. By participating, you are expected to uphold this code.

Development Guidelines
======================

1. **Test-Driven Development**: All new features or bug fixes must be accompanied by relevant specifications (`spec/`).
2. **Coverage**: The test suite must maintain strict `> 80%` coverage.
3. **Linting**: We enforce a strict 132-character line limit. Run `make lint` (which utilizes `ameba --fix --all`) prior to committing. Absolutely no linter suppressions (`# ameba:disable` or `# flaw:disable`) are allowed.
4. **Build System**: All tasks (testing, linting, building docs) must utilize the existing `GNUmakefile`.

Pull Request Process
====================

1. Create a descriptive branch from `master`.
2. Ensure your changes compile and pass `make test` and `make lint` against the Alpine CI container specifications.
3. Update the `CHANGELOG.rst` following the `Keep a Changelog 1.1.0` guidelines.
4. Add your `Signed-off-by` to your commits.
