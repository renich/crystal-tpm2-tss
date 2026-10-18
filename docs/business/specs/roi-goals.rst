===================
ROI and Key Metrics
===================

Measurable Objectives
---------------------

#. **Hardware Root-of-Trust Sovereignty**: Eliminate external C TSS library dependencies by framing TCG TPM 2.0 Part 3 binary commands directly in Crystal.
#. **Cryptographic Nonce Safety**: Enforce ``O(1)`` ECDSA ``r``-component tracking across a bounded 10,000-signature window to prevent private key leakage under RNG faults.
#. **Deterministic CI Verification**: Provide a stateful virtual TPM 2.0 simulator backed by real OpenSSL 3.5 NIST P-256 ECDSA key generation, signing, and verification for 100% hardware-free test execution.
#. **Zero Initial Defects**: Enforce 100% pass rates across Crystal specs, Ameba, Flaw, ``crstlint``, and ``rstcheck``.
