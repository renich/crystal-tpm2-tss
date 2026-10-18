=========
Changelog
=========

All notable changes to this project will be documented in this file.

The format is based on `Keep a Changelog <https://keepachangelog.com/en/1.1.0/>`__,
and this project adheres to `Semantic Versioning <https://semver.org/spec/v2.0.0.html>`__.

[Unreleased]
============

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
- Cleaned up spec formatting and removed obsolete TODO comments.

[0.1.0] - 2026-06-05
====================

.. rubric:: Added

- Initial orchestrated release of the architecture.
- Full TDD specifications with >80% code coverage.
- Code of Honor integration.
- FHS 3 compliant GNUmakefile.
- GitLab CI/CD Alpine pipeline.
