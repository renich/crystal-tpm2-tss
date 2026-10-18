=========================================
Release Procedure and Versioning Playbook
=========================================

Overview
--------

This document defines the deterministic, repeatable release workflow for ``crystal-tpm2-tss``. It enforces Semantic Versioning 2.0.0, Keep a Changelog 1.1.0 compliance, multi-file version alignment, local pre-push linting, signed GPG Git tags, and automated GitLab CI release artifact creation.

Requirement Mapping
-------------------

Fulfills ``[FUNC-001]`` in :doc:`../../functional/specs/core-requirements`.

Multi-File Version Alignment Checklist
--------------------------------------

Prior to tagging any release, the version string must be updated across the codebase:

#. **``shard.yml``**:

   .. code-block:: yaml

      version: 0.4.1

#. **``src/crystal-tpm2-tss.cr``**:

   .. code-block:: crystal

      VERSION = "0.4.1"

#. **``docs/conf.py``**:

   .. code-block:: python

      release = '0.4.1'

#. **``CHANGELOG.rst``**:
   Promote items from ``[Unreleased]`` under a new version header using ``.. rubric::`` sections:

   .. code-block:: rst

      [0.4.1] - 2026-10-18
      ====================

      .. rubric:: Added

      - Real OpenSSL 3.5 NIST P-256 key generation, signing, and verification.

Step-by-Step Release Execution Playbook
---------------------------------------

Step 1: Local Quality Assurance and Spec Verification
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Execute the full test suite and quality gates locally:

.. code-block:: bash

   make all
   make doc-check
   make docs

All specs must pass with 0 failures, 0 errors, 0 Ameba lint issues, 0 Flaw security findings, and 0 ``crstlint`` or ``rstcheck`` warnings.

Step 2: Commit Version Bump and Changelog Update
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Stage and commit version changes adhering to Conventional Commit standards:

.. code-block:: bash

   git add shard.yml src/crystal-tpm2-tss.cr docs/conf.py CHANGELOG.rst
   git commit -m "chore(release): bump version to 0.4.1"

Step 3: Create Signed Annotated Git Tag
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create a GPG-signed Git tag for the release:

.. code-block:: bash

   git tag -s v0.4.1 -m "Release v0.4.1"

Step 4: Push Branch and Tags to GitLab
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Push the release commit and tag to the remote GitLab repository:

.. code-block:: bash

   git push origin master --tags

Step 5: Automated GitLab CI Release Trigger
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pushing to the default branch or a release tag triggers the GitLab CI pipeline in ``.gitlab-ci.yml``, which executes ``make all`` and publishes the documentation portal to GitLab Pages.
