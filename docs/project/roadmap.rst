========================================
Crystal TPM2-TSS Project Master Roadmap
========================================

.. toctree::
   :maxdepth: 2
   :caption: Roadmap Phases

   roadmaps/phase-1-mvp
   roadmaps/phase-2-release

Executive Summary
=================
This document outlines the phased engineering milestones and release lifecycle for ``crystal-tpm2-tss``, implementing a lightweight TPM 2.0 Software Stack (TSS) for Crystal with support for NV storage KDF key persistence, session-based parameter encryption, and FIDO2 credential management.

Phase Breakdown
===============
* **Phase 1 (MVP Baseline)**: TPM2 command marshaling, NV memory definition and KDF key derivation, session nonce tracking, and FIDO2 credential lifecycle.
* **Phase 2 (Crucible Refactoring & Release Stabilization)**: Replaced O(N) array search in ``SignatureRTracker`` with O(1) ``Set``/``Deque``, fixed HMAC session key concatenation, standardized ``kdf_key`` accessor naming, and v0.2.0 production release.
