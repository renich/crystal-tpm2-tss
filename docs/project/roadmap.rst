=======================================
Crystal TPM2-TSS Project Master Roadmap
=======================================

Executive Summary
=================

This document outlines the phased engineering milestones and release lifecycle for ``crystal-tpm2-tss``, implementing a lightweight TPM 2.0 Software Stack for Crystal with support for NV storage KDF key persistence, session-based parameter encryption, and FIDO2 credential management.

Roadmap Phases
--------------

* `Phase 1: TPM 2.0 Software Stack Core MVP <roadmaps/phase-1-mvp.rst>`__
* `Phase 2: Crucible Protocol Refactoring & Release Stabilization <roadmaps/phase-2-release.rst>`__

Phase Breakdown
===============

* **Phase 1 — MVP Baseline**: TPM2 command marshaling, NV memory definition and KDF key derivation, session nonce tracking, and FIDO2 credential lifecycle.
* **Phase 2 — Crucible Refactoring & Release Stabilization**: Replaced O(N) array search in ``SignatureRTracker`` with O(1) ``Set``/``Deque``, fixed HMAC session key concatenation, standardized ``kdf_key`` accessor naming, and ``v0.2.0``/``v0.2.1`` production releases.
* **Phase 3 — Echelon and Crucible v0.3.0 Hardening**: Completed full TPM 2.0 command lifecycle in ``FIDO2CredentialManager``, added AES-128-CFB parameter encryption alongside KDFa XOR, implemented disjoint NV index linear probing, enforced fail-closed hardware transport, and optimized CI/CD execution.
