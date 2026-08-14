# crystal-tpm2-tss

[![CI](https://gitlab.com/renich/crystal-tpm2-tss/badges/master/pipeline.svg)](https://gitlab.com/renich/crystal-tpm2-tss/-/pipelines)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

A native, high-security [Crystal](https://crystal-lang.org/) **TPM 2.0 Software Stack (TSS)** implementation with hardware-backed Key Derivation Function (KDF) persistence, session-based authorization, and FIDO2/CTAP2 credential management.

## Features

- **Hardware-Bound KDF Persistence**: Derives root authorization and application keys stored in persistent TPM Non-Volatile (NV) indices.
- **Session Management & Nonce Tracking**: Tracks caller nonces and TPM response nonces across authentication and encryption sessions.
- **$\mathcal{O}(1)$ Nonce Reuse Detection**: High-performance `SignatureRTracker` utilizing `Set(String)` for constant-time lookups and `Deque(String)` for chronological eviction.
- **FIDO2 Credential Lifecycle**: Primary key generation, auth value derivation, and challenge signing with hardware backing.
- **Memory-Safe HMAC Concatenation**: Pre-allocated byte buffers preventing heap leakage.

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  crystal-tpm2-tss:
    github: renich/crystal-tpm2-tss
    version: ~> 0.2.0
```

Then run:

```bash
shards install
```

## Usage

```crystal
require "crystal-tpm2-tss"

# Initialize TPM device interface
tpm = TPMDevice.new

# Derive hardware-bound auth key via KDF manager
platform_secret = Random::Secure.random_bytes(32)
kdf_manager = KDFKeyManager.new(tpm, platform_secret)
root_key = kdf_manager.kdf_key
puts "Root KDF Key: #{root_key.hexstring}"

# Create FIDO2 credential manager with nonce reuse protection
credential_manager = FIDO2CredentialManager.new(tpm, platform_secret)
auth_value = credential_manager.derive_auth_value("user-credential-1234")
puts "Hardware-bound auth value: #{auth_value.hexstring}"
```

## Development & Verification

Build targets and test suites are managed via GNU Make:

```bash
make all      # Runs linting (Ameba & Flaw) and the full test suite
make test     # Executes crystal spec
make lint     # Executes Ameba static analysis and Flaw scanner
make docs     # Generates API documentation into docs/technical/api
```

## Documentation

- **API Documentation**: Generated HTML docs located at [`docs/technical/api/`](docs/technical/api/index.html).
- **Technical Specification**: [`docs/technical/spec.rst`](docs/technical/spec.rst)
- **Project Roadmap**: [`docs/project/roadmap.rst`](docs/project/roadmap.rst)
- **Changelog**: [`CHANGELOG.rst`](CHANGELOG.rst)
- **Code of Honor**: [`docs/technical/CODE_OF_HONOR.rst`](docs/technical/CODE_OF_HONOR.rst)

## License

This project is licensed under the **GNU Affero General Public License v3.0 or later** ([AGPL-3.0-or-later](LICENSE)).
