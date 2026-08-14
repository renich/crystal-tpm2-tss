=========
Changelog
=========

All notable changes to this project will be documented in this file.

The format is based on `Keep a Changelog <https://keepachangelog.com/en/1.1.0/>`_,
and this project adheres to `Semantic Versioning <https://semver.org/spec/v2.0.0.html>`_.

[Unreleased]
============

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
