===================
ROI and Key Metrics
===================

Measurable Objectives
---------------------

#. **Hardware Root-of-Trust Sovereignty**: Eliminate external C TSS library dependencies by framing TCG TPM 2.0 Part 2 and Part 3 binary structures and commands directly in Crystal.
#. **Cryptographic Nonce Safety**: Enforce ``O(1)`` ECDSA ``r``-component tracking across a bounded 10,000-signature FIFO ring window to prevent private key leakage under RNG faults.
#. **Deterministic CI Verification**: Provide a stateful virtual TPM 2.0 simulator backed by real OpenSSL 3.5 NIST P-256 ECDSA key generation, signing, and verification for 100% hardware-free test execution.
#. **Zero-Defect Quality Gates**: Enforce 100% pass rates across 41 Crystal specs, Ameba ``--all``, Flaw SAST, ``crstlint``, ``rstcheck``, and Sphinx ``dirhtml`` builds with zero inline linter suppressions.
