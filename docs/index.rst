==============================
Crystal TPM2-TSS Documentation
==============================

**Native Crystal TPM 2.0 Software Stack with Hardware-Backed KDF Persistence, Session Encryption, and FIDO2 Credential Management.**

Welcome to the official documentation portal for ``crystal-tpm2-tss``.

Documentation Architecture
--------------------------

.. list-table::
   :widths: 25 45 30
   :header-rows: 1

   * - Guide
     - Purpose & Scope
     - Entrypoint
   * - **Business & Strategy**
     - Strategic vision, hardware root-of-trust goals, and user personas.
     - `Business Specifications <business/spec.rst>`__
   * - **Functional Specifications**
     - Requirements ``[FUNC-001]``..``[FUNC-005]``, behavioral contracts, and interfaces.
     - `Functional Specifications <functional/spec.rst>`__
   * - **Technical Architecture**
     - TPM 2.0 wire framing, OpenSSL P-256 verification, threat model, and release strategy.
     - `Technical Architecture <technical/spec.rst>`__
   * - **Architecture Decisions**
     - Immutable Architecture Decision Records and trade-off analyses.
     - `Architecture Decisions <adrs/index.rst>`__
   * - **Project Roadmap**
     - Sequenced phase milestones, delivery tracking, and audit records.
     - `Project Roadmap <project/roadmap.rst>`__
   * - **User Guides**
     - Integration guides, code examples, and API tutorials.
     - `User Manual <user/index.rst>`__
   * - **Crystal API Reference**
     - Compiler-generated API documentation covering all classes, structs, and modules.
     - `Crystal API Reference <technical/api/index.html>`__

.. toctree::
   :maxdepth: 2
   :caption: Documentation Suite

   business/spec
   functional/spec
   technical/spec
   adrs/index
   project/roadmap
   user/index

Indices and Tables
------------------

* :ref:`genindex`
* :ref:`search`
