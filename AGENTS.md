# Agent Architecture & Maintenance Knowledge

This repository was co-developed and orchestrated by the Google Antigravity Agent Orchestrator and Rénich Bon Ćirić. 
This document serves as a persistent memory and maintenance guide for the project, detailing the architecture, design decisions, and strict protocols established during development.

## Project Domain: TPM 2.0 Trusted Software Stack Integration

### Domain-Specific Knowledge
- Thread-safe session management using M:N Crystal scheduling.
- FIFO eviction strategies and KDF key derivation implemented deterministically.
- Memory safety isolated from direct hardware polling loops.

## Maintenance Protocols

To ensure the codebase remains exemplary, any future modifications or agent orchestrations MUST adhere to the following established knowledge:

### 1. Build & Dependencies
- **System Libraries**: This project compiles directly against system libraries.
  - **Fedora/RHEL**: Requires `sudo dnf install -y libsodium-devel tpm2-tss-devel`.
  - **Alpine (CI/CD)**: Requires `apk add --no-cache make git libsodium-dev tpm2-tss-dev pcre2-dev`.
- **Build System**: The project explicitly uses a `GNUmakefile` for orchestration (`make test`, `make lint`, `make docs`, `make install`).
- **Deployment**: The `make install` target is fully compliant with FHS 3 standards (defaulting to `/usr/local/share/doc/`).

### 2. Testing & Quality Assurance
- **TDD Requirement**: Code MUST be written alongside functional tests.
- **Coverage**: Total coverage must remain strictly `> 80%`.
- **Environment**: Tests should be capable of running identically on local Fedora environments and Alpine CI containers.

### 3. Linting & Formatting
- **No Suppressions**: We do not suppress linter errors. There should be absolutely no `# ameba:disable` or `# flaw:disable` comments anywhere in the codebase.
- **Line Length**: The `Layout/LineLength` in `.ameba.yml` is explicitly configured to `132` characters.
- **Formatting**: Always execute `crystal tool format .` and `bin/ameba --fix --all` before committing.
- **Security**: The `flaw` binary is used for static application security testing. Fix vulnerabilities rather than silencing them.

### 4. Continuous Integration
- **GitLab Pipeline**: The `.gitlab-ci.yml` strictly uses the `crystallang/crystal:latest-alpine` footprint.
- **Documentation**: Whitepapers (`docs/whitepaper.rst`) and architectural documentation are built and deployed via GitLab Pages on the `master` branch.
- **No GitHub Actions**: We strictly do not use GitHub workflows (no `.github/` folder).

### 5. AI Agent Roles Used
For historical context or future orchestration, the following roles were defined during genesis:
- **Lead Dev**: Architected TDD specs and interface boundaries.
- **Junior Dev**: Implemented specifications to pass tests.
- **QA Engineer**: Pushed coverage >80% via adversarial edge-case testing.
- **Documentator**: Maintained `docs/technical/` files.

## Code of Honor
The entire AI orchestration pipeline and generated codebase is completely bound to and respects the [Code of Honor](docs/technical/CODE_OF_HONOR.rst) drafted by Rénich Bon Ćirić. Any future agents interacting with this repository MUST digest and adhere to it.

## Disclosures
- **Co-developed-by**: Gemini AI <renich+gemini@woralelandia.com>
- **Signed-off-by**: Rénich Bon Ćirić <renich@woralelandia.com>
