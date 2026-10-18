==============================================================
Phase 2: Crucible Protocol Refactoring & Release Stabilization
==============================================================

Timeline and Objectives
-----------------------

Execute Crucible and Echelon zero-trust review loops to eliminate linear lookup complexity in nonce reuse tracking, complete the TPM 2.0 FIDO2 lifecycle with real OpenSSL 3.5 NIST P-256 verification, and align documentation and build pipelines.

Milestones and Deliverables
---------------------------

* **Milestone 2.1: Cryptographic Hardening and Lifecycle Completion**:

  - [x] ``[TPM-005]`` Overhaul ``SignatureRTracker`` to use ``Set(String)`` and ``Deque(String)`` for ``O(1)`` membership and FIFO eviction.
  - [x] ``[TPM-006]`` Implement TCG TPM 2.0 Part 1 KDFa ``XOR`` and ``AES-128-CFB`` parameter encryption in ``ParameterEncryption``.
  - [x] ``[TPM-007]`` Add TCG TPM 2.0 Part 1 §19.6.5 ``cpHash`` and ``rpHash`` calculation in ``Session``.
  - [x] ``[TPM-008]`` Integrate OpenSSL 3.5 ``P256Key`` signer/verifier, ``TPM2_ReadPublic`` coordinate extraction, and dynamic persistent handle derivation.
  - [x] ``[TPM-009]`` Decompose ``FIDO2Credential``, ``NVMetadataStore``, and ``FIDO2CredentialManager`` into modular files under 200 lines and build full Sphinx documentation portal.
