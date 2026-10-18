# crystal-tpm2-tss

[![CI](https://gitlab.com/renich/crystal-tpm2-tss/badges/master/pipeline.svg)](https://gitlab.com/renich/crystal-tpm2-tss/-/pipelines)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

A native, high-security [Crystal](https://crystal-lang.org/) **TPM 2.0 Software Stack (TSS)** implementation with hardware-backed Key Derivation Function (KDF) persistence, session-based HMAC authorization, KDFa XOR and AES-128-CFB parameter encryption, and FIDO2/CTAP2 credential management.

## Features

- **Hardware-Bound KDF Persistence**: Derives root authorization and application keys stored in persistent TPM Non-Volatile (NV) indices.
- **Session Management & Parameter Encryption**: Tracks caller and TPM response nonces (`nonceCaller`, `nonceTPM`) with TCG TPM 2.0 Part 1 KDFa key derivation for both XOR and AES-128-CFB parameter encryption.
- **$\mathcal{O}(1)$ Atomic Nonce Reuse Detection**: Thread-safe `SignatureRTracker` utilizing `Set(String)` for constant-time membership checks and `Deque(String)` for bounded chronological FIFO eviction.
- **Complete FIDO2 Credential Lifecycle**: End-to-end `CreatePrimary`, `Create`, `Load`, `EvictControl`, `FlushContext`, `NV_DEFINESPACE`, `NV_WRITE`, `NV_READ`, and `Sign` command execution with disjoint NV index linear probing (`0x01800000..0x01BFFFFF`) for collision resistance.
- **Fail-Closed Hardware Transport**: Stack-allocated frame I/O over `/dev/tpmrm0` with deterministic stateful simulation when running in virtual/in-memory mode.

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  crystal-tpm2-tss:
    gitlab: renich/crystal-tpm2-tss
    version: ~> 0.3.0
```

Then run:

```bash
shards install
```

## Usage

```crystal
require "crystal-tpm2-tss"

# Initialize TPM device interface (virtual by default, or pass "/dev/tpmrm0")
tpm = TPMDevice.new

# Derive hardware-bound auth key via KDF manager
platform_secret = Random::Secure.random_bytes(32)
kdf_manager = KDFKeyManager.new(tpm, platform_secret)
root_key = kdf_manager.kdf_key
puts "Root KDF Key: [REDACTED #{root_key.size}-byte key]"

# Create FIDO2 credential manager with nonce reuse protection
credential_manager = FIDO2CredentialManager.new(tpm, platform_secret)
credential = credential_manager.get_or_create_credential("user-credential-1234")
signature = credential.sign(Random::Secure.random_bytes(32))
puts "ECDSA Signature r: #{signature.r.hexstring}"
```

## Development & Verification

Build targets and test suites are managed via GNU Make:

```bash
make all      # Runs linting (format check, Ameba --all, Flaw) and the full test suite
make check    # Executes crystal spec
make lint     # Executes crystal tool format --check, Ameba --all, and Flaw scanner
make docs     # Generates API documentation into docs/technical/api
```

## Documentation

- **API Documentation**: Generated HTML docs located at [`docs/technical/api/`](docs/technical/api/index.html)
- **Architectural Whitepaper**: [`docs/whitepaper.rst`](docs/whitepaper.rst)
- **Technical Specification**: [`docs/technical/spec.rst`](docs/technical/spec.rst)
- **Project Roadmap**: [`docs/project/roadmap.rst`](docs/project/roadmap.rst)
- **Changelog**: [`CHANGELOG.rst`](CHANGELOG.rst)
- **Code of Honor**: [`docs/technical/CODE_OF_HONOR.rst`](docs/technical/CODE_OF_HONOR.rst)

## License

This project is licensed under the **GNU Affero General Public License v3.0 or later** ([AGPL-3.0-or-later](LICENSE)).
