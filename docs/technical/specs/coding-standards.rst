================
Coding Standards
================

Requirement Mapping
-------------------

Fulfills ``[FUNC-001]``, ``[FUNC-003]``, and ``[FUNC-005]`` in :doc:`../../functional/specs/core-requirements`.

Technical Specification
-----------------------

* **[TECH-004] Zero-Suppression Static Analysis and Modularity Boundaries**:
  Fulfills ``[FUNC-001]``, ``[FUNC-003]``, and ``[FUNC-005]``. All source and spec files in ``crystal-tpm2-tss`` must satisfy the following engineering invariants:

  #. **Strict Static Analysis**:
     Full rule sets for Ameba ``--all`` and Flaw SAST are enforced in ``make lint`` with zero inline suppression comments.

  #. **Defensive Nil Handling**:
     Calling ``.not_nil!`` is prohibited across ``src/`` and ``spec/``. All nilable types must use explicit type narrowing with ``if``, ``case``, or ``.try``.

  #. **File and Method Granularity**:
     Every Crystal source file in ``src/`` must remain ``<= 220`` lines, every method ``<= 25`` lines, and cyclomatic complexity ``<= 10``.

  #. **Line Length**:
     Maximum line length is 120 characters as configured in ``.ameba.yml``.

  #. **Execution Context Concurrency Safety**:
     All shared mutable state must be synchronized using Crystal 1.21 ``Sync::Mutex`` primitives rather than legacy ``Mutex`` classes.

  #. **API Documentation Comments**:
     Every public class, struct, module, constant, and method must include Markdown doc comments and explicit parameter and return type annotations.
