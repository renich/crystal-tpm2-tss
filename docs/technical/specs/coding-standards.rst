================
Coding Standards
================

Requirement Mapping
-------------------

Fulfills ``[FUNC-001]``, ``[FUNC-002]``, ``[FUNC-003]``, ``[FUNC-004]``, ``[FUNC-005]``.

Core Directives
---------------

#. **Strict Static Analysis**:
   Full rule sets for Ameba (``--all``) and Flaw are enforced with zero inline suppression comments (``# ameba:disable`` or ``# flaw:disable``).

#. **Defensive Nil Handling**:
   Never call ``.not_nil!``. Use explicit type narrowing with ``if``, ``case``, or ``.try``.

#. **File and Method Granularity**:
   Every Crystal source file must remain ``<= 220`` lines, every method ``<= 25`` lines, and cyclomatic complexity ``<= 10``.

#. **Line Length**:
   Maximum line length is 120 characters (``Layout/LineLength: MaxLength: 120`` in ``.ameba.yml``).

#. **API Documentation Comments**:
   Every public class, struct, module, constant, and method must include Markdown doc comments and explicit parameter and return type annotations.
