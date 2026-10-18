# crystal-tpm2-tss

[![CI](https://gitlab.com/renich/crystal-tpm2-tss/badges/master/pipeline.svg)](https://gitlab.com/renich/crystal-tpm2-tss/-/pipelines)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

A native, high-security [Crystal](https://crystal-lang.org/) **TPM 2.0 Software Stack (TSS)** implementation with hardware-backed Key Derivation Function (KDF) persistence, session-based HMAC authorization (`cpHash`/`rpHash`), KDFa XOR and AES-128-CFB parameter encryption, and FIDO2/CTAP2 credential management with OpenSSL 3.5 NIST P-256 ECDSA verification.

## Features

- **Hardware-Bound KDF Persistence**: Derives root authorization and application keys stored in persistent TPM Non-Volatile (NV) indices (`0x01C00000`).
- **Session Management & Parameter Encryption**: Tracks caller and TPM response nonces (`nonceCaller`, `nonceTPM`) with TCG TPM 2.0 Part 1 §19.6.5 `cpHash`/`rpHash` calculation and §11.4.9.2 KDFa key derivation for both XOR and AES-128-CFB parameter encryption.
- **$\mathcal{O}(1)$ Atomic Nonce Reuse Detection**: Thread-safe `SignatureRTracker` utilizing `Set(String)` for constant-time membership checks and `Deque(String)` for bounded chronological FIFO eviction.
- **Complete FIDO2 Credential Lifecycle & NIST P-256 Verification**: End-to-end `CreatePrimary`, `Create`, `Load`, `EvictControl`, `ReadPublic`, `FlushContext`, `NV_DEFINESPACE`, `NV_WRITE`, `NV_READ`, and `Sign` command execution with dynamic persistent handle derivation (`0x81010001..0x8101FFFF`), disjoint NV index linear probing (`0x01800000..0x01BFFFFF`), and real OpenSSL 3.5 NIST P-256 signature verification.
- **Fail-Closed Hardware & Stateful Virtual Transport**: Stack-allocated frame I/O over `/dev/tpmrm0` with an OpenSSL 3.5 NIST P-256 stateful virtual simulator when running in virtual/in-memory mode.

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  crystal-tpm2-tss:
    gitlab: renich/crystal-tpm2-tss
    version: ~> 0.4.0
```

Then run:

```bash
shards install
```

## Usage

```crystal
require "crystal-tpm2-tss"

# Initialize TPM device interface (virtual simulator by default, or pass "/dev/tpmrm0")
tpm = TPMDevice.new

# Derive hardware-bound auth key via KDF manager
platform_secret = Random::Secure.random_bytes(32)
kdf_manager = KDFKeyManager.new(tpm, platform_secret)
root_key = kdf_manager.kdf_key
puts "Root KDF Key: [REDACTED #{root_key.size}-byte key]"

# Create FIDO2 credential manager with nonce reuse protection and P-256 verification
credential_manager = FIDO2CredentialManager.new(tpm, platform_secret)
credential = credential_manager.get_or_create_credential("user-credential-1234")
digest = Random::Secure.random_bytes(32)
signature = credential.sign(digest)
puts "ECDSA Signature valid? #{credential.verify(digest, signature)}"
```

## Development & Verification

Build targets and test suites are managed via GNU Make:

```bash
make all        # Runs linting (format check, Ameba --all, Flaw), doc-check, and the full test suite
make check      # Executes lint, doc-check, and crystal spec
make lint       # Executes crystal tool format --check, Ameba --all, and Flaw scanner
make doc-check  # Validates all .rst files with crstlint and rstcheck
make docs       # Generates Crystal API docs and Sphinx dirhtml documentation portal
```

## Documentation

- **Documentation Portal**: [`docs/index.rst`](docs/index.rst)
- **Business Specifications**: [`docs/business/spec.rst`](docs/business/spec.rst)
- **Functional Specifications**: [`docs/functional/spec.rst`](docs/functional/spec.rst)
- **Technical Architecture**: [`docs/technical/spec.rst`](docs/technical/spec.rst)
- **Architecture Decision Records**: [`docs/adrs/index.rst`](docs/adrs/index.rst)
- **Project Roadmap**: [`docs/project/roadmap.rst`](docs/project/roadmap.rst)
- **User Guide**: [`docs/user/guides/getting-started.rst`](docs/user/guides/getting-started.rst)
- **Changelog**: [`CHANGELOG.rst`](CHANGELOG.rst)
- **Code of Honor**: [`CODE_OF_HONOR.rst`](CODE_OF_HONOR.rst)

## License

- **Source Code**: Licensed under the **GNU Affero General Public License v3.0 or later** ([`LICENSE`](LICENSE)).
- **Documentation**: Licensed under the **Creative Commons Attribution-ShareAlike 4.0 International** ([`LICENSE-DOCS`](LICENSE-DOCS)).
