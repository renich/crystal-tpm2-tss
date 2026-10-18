=========
Changelog
=========

All notable changes to this project will be documented in this file.

The format is based on `Keep a Changelog <https://keepachangelog.com/en/1.1.0/>`__,
and this project adheres to `Semantic Versioning <https://semver.org/spec/v2.0.0.html>`__.

[Unreleased]
============

[0.4.1] - 2026-10-18
====================

.. rubric:: Added

- Implemented ``Tpm2bCodec`` in ``src/crystal-tpm2-tss/tpm2b_codec.cr`` providing deterministic big-endian TCG TPM 2.0 Part 2 binary marshaling and unmarshaling for ``TPM2B`` length-prefixed buffers, ``TPMS_AUTH_COMMAND``, ``TPMS_AUTH_RESPONSE``, ``TPM2B_SENSITIVE_CREATE``, ``TPM2B_PUBLIC`` with nested ``TPMS_ECC_PARMS``, and ``TPMT_SIGNATURE``, fulfilling ``[FUNC-006]`` and ``[TECH-006]``.
- Implemented ``Session.start_auth_session``, ``Session#policy_pcr``, and ``Session#flush`` alongside ``TPM2::Commands::PolicyPCR`` (``0x0000017f_u32``) in ``Session`` and ``TPMDevice``, supporting salted and bound ``sessionKey`` derivation via ``ParameterEncryption.kdfa`` and cumulative SHA-256 ``PolicyPCR`` digest extension, fulfilling ``[FUNC-007]`` and ``[TECH-007]``.
- Added automatic ``TPMS_AUTH_COMMAND`` session attachment, caller nonce rolling, and constant-time ``TPMS_AUTH_RESPONSE`` HMAC verification inside ``TPMDevice#execute(command, session)``.
- Added ``ADR-002`` in ``docs/adrs/2026-10-18-phase-2-tcg-part2-marshaling-and-policypcr.rst`` and dependency-tracked phased roadmaps in ``docs/project/roadmap.rst``, ``docs/project/roadmaps/phase-1-mvp.rst``, and ``docs/project/roadmaps/phase-2-enhancement.rst``.
- Added D2 source diagrams and compiled SVG visual artifacts in ``docs/diagrams/architecture.d2``, ``docs/diagrams/roadmaps/roadmap.d2``, ``docs/diagrams/roadmaps/phase-1-mvp.d2``, and ``docs/diagrams/roadmaps/phase-2-enhancement.d2``, plus ``assets/icon.svg`` and ``assets/banner.svg``.

[0.4.0] - 2026-10-18
====================

.. rubric:: Added

- Added real OpenSSL 3.5 NIST P-256 elliptic curve keypair generation, ECDSA digest signing, and public-key signature verification in ``P256Key``.
- Added ``TPM2::Commands::ReadPublic`` coordinate extraction, ``StartAuthSession`` virtual simulation, and stateful ``@key_store`` tracking in ``TPMDevice``.
- Added ``FIDO2Credential#public_key_xy`` and ``FIDO2Credential#verify`` for cryptographic verification of hardware and virtual FIDO2 signatures.
- Added TCG TPM 2.0 Part 1 §19.6.5 ``Session#compute_cp_hash`` and ``Session#compute_rp_hash`` parameter hash calculations.
- Added full Sphinx ``dirhtml`` documentation portal (``docs/business/``, ``docs/functional/``, ``docs/technical/``, ``docs/adrs/``, ``docs/project/``, and ``docs/user/``), ``LICENSE-DOCS``, ``CODE_OF_HONOR.rst``, and ``.crstlint.yaml``.

.. rubric:: Changed

- Decomposed ``FIDO2CredentialManager`` into three focused modules under 200 lines each: ``FIDO2Credential``, ``NVMetadataStore``, and ``FIDO2CredentialManager``.
- Derived distinct persistent TPM handles (``0x81010001..0x8101FFFF``) per credential ID in ``FIDO2CredentialManager#derive_persistent_handle``.

[0.3.0] - 2026-10-18
====================

.. rubric:: Security

- Implemented full TPM 2.0 command lifecycle (``Create``, ``Load``, ``EvictControl``, ``FlushContext``, ``NV_DEFINESPACE``, ``NV_WRITE``, ``NV_READ``, ``Sign``) and NV linear probing in ``FIDO2CredentialManager``.
- Added AES-128-CFB session parameter encryption and decryption alongside KDFa XOR in ``ParameterEncryption``.
- Enforced fail-closed hardware device I/O in ``TPMDevice`` using stack-allocated buffers and eliminated TOCTOU file checks.
- Added atomic ``SignatureRTracker#check_and_add!`` and thread-safe mutex synchronization across ``Session`` and ``KDFKeyManager``.
- Validated non-zero ECDSA signature ``(r, s)`` components and overflow-safe ``TPMResponse.parse`` session area bounds.

.. rubric:: Changed

- Converted ``ECDSASignature`` to an immutable value ``struct`` and added ``TPMCommand.build_password_auth`` to deduplicate password session framing.
- Upgraded minimum Crystal version to ``>= 1.21.0`` and overhauled ``GNUmakefile`` and ``.gitlab-ci.yml``.

[0.2.1] - 2026-09-19
====================

.. rubric:: Security

- Implemented genuine TCG TPM 2.0 Part 1 §21 KDFa XOR counter-mode parameter encryption and decryption in ``ParameterEncryption``.
- Added constant-time response HMAC verification using ``Crypto::Subtle.constant_time_compare`` in ``Session``.
- Hardened ``Session``, ``SignatureRTracker``, and ``KDFKeyManager`` with ``Sync::Mutex`` concurrency primitives for Crystal 1.21 Execution Context safety.
- Bound ECDSA nonce reuse tracker using Set and Deque for O(1) membership and bounded FIFO eviction.
- Defaulted ``TPMDevice`` to safe simulated fallback while allowing explicit hardware binding to ``/dev/tpmrm0``.

.. rubric:: Added

- Exposed top-level backwards compatibility aliases for all relocated subcomponents.
- Expanded test suite to 29 specs covering parameter encryption/decryption roundtrips and error handling.

.. rubric:: Refactored

- Decomposed monolithic 734-line ``core.cr`` into 9 modular submodules under 210 lines each.
- Moved all types into the canonical ``Crystal::Tpm2::Tss`` module namespace.

[0.2.0] - 2026-08-13
====================

.. rubric:: Changed

- Renamed ``KDFKeyManager#get_kdf_key`` to ``KDFKeyManager#kdf_key`` adhering to Crystal accessor conventions.
- Overhauled ``SignatureRTracker`` from linear array lookup to ``Set(String)`` for O(1) membership and ``Deque(String)`` for O(1) chronological eviction.

.. rubric:: Fixed

- Corrected HMAC session key concatenation by pre-allocating byte buffers with ``copy_to``.
- Modernized GNUmakefile test target to use ``$(CRYSTAL) spec``.
- Cleaned up spec formatting and removed obsolete placeholder comments.

[0.1.0] - 2026-06-05
====================

.. rubric:: Added

- Initial orchestrated release of the architecture.
- Full TDD specifications with >80% code coverage.
- Code of Honor integration.
- FHS 3 compliant GNUmakefile.
- GitLab CI/CD Alpine pipeline.
