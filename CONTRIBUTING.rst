================================
Contributing to Crystal TPM2-TSS
================================

Thank you for your interest in contributing to ``crystal-tpm2-tss``. We welcome contributions from human engineers and autonomous agents who share our commitment to cryptographic rigor, memory safety, and empirical verification.

Code of Honor
=============

All contributors must uphold the principles defined in `CODE_OF_HONOR.rst <CODE_OF_HONOR.rst>`__. We build resilient, well-tested software, demand intellectual honesty, operate transparently, and verify all library behaviors empirically.

Development Workflow
====================

Prerequisites
-------------

* `Crystal <https://crystal-lang.org/>`__ ``>= 1.21.0``
* OpenSSL 3.5 development headers via ``openssl-devel`` on Fedora Linux
* `GNU Make <https://www.gnu.org/software/make/>`__
* `cRSTLint <https://gitlab.com/renich/crstlint>`__ and ``rstcheck`` for documentation linting

Setting Up the Workspace
------------------------

#. Clone the repository:

   .. code-block:: bash

      git clone git@gitlab.com:renich/crystal-tpm2-tss.git
      cd crystal-tpm2-tss

#. Build linter dependencies:

   .. code-block:: bash

      make deps

#. Verify the test suite, static analysis, and documentation gates:

   .. code-block:: bash

      make check

Testing and Quality Standards
=============================

We adhere strictly to Test-Driven Development and the principle of **Do Not Assume; Always Verify**.

Running Checks
--------------

* **Run test suite**:

   .. code-block:: bash

      make test

* **Run static linters** with Ameba and Flaw:

   .. code-block:: bash

      make lint

* **Validate RST Documentation**:

   .. code-block:: bash

      make doc-check

* **Build Sphinx and Crystal API Documentation**:

   .. code-block:: bash

      make docs

Git Commit Standards
====================

We enforce the Conventional Commits specification:

* ``feat(p256): add OpenSSL 3.5 NIST P-256 signer and verifier``
* ``fix(session): add cpHash and rpHash parameter digest calculation``
* ``docs(adrs): record decision on TPM 2.0 wire framing and virtual simulation``
* ``test(spec): add end-to-end FIDO2 ECDSA signature verification specs``

All commits must be signed and authored with full technical ownership.
