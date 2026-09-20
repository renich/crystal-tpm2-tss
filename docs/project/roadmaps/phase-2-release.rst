=============================================================
Phase 2: Crucible Protocol Refactoring & Release Stabilization
=============================================================

Status: Completed
Target Version: 0.2.0

Overview
========
Execute Crucible Protocol zero-trust review loop to eliminate linear O(N) lookup complexity in nonce reuse tracking, correct HMAC buffer concatenation, standardize accessor method naming, and achieve 0 lint warnings.

Milestones & Deliverables
=========================
* **[TPM-005] O(1) Nonce Reuse Tracking**: Overhaul ``SignatureRTracker`` to use a ``Set(String)`` for O(1) membership checks and ``Deque(String)`` for O(1) chronological eviction.
* **[TPM-006] Memory-Safe HMAC Key Concatenation**: Replace unsafe slice addition in ``Session#compute_hmac`` with pre-allocated buffer copy.
* **[TPM-007] Crystal Naming Modernization**: Rename ``KDFKeyManager#get_kdf_key`` to ``KDFKeyManager#kdf_key`` per language idioms.
* **[TPM-008] Spec Cleanliness & Formatting**: Eliminate TODO comments, format all spec files, and fix GNUmakefile test targets.
* **[TPM-009] Documentation & Release**: Update ``CHANGELOG.rst`` with ``.. rubric::``, add AGPL-3.0-or-later licensing, and publish API docs to ``docs/technical/api``.
