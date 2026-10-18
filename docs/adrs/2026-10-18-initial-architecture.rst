=================================================================
ADR-001: Native TPM 2.0 Wire Framing and OpenSSL P-256 Simulation
=================================================================

:Status: Accepted
:Date: 2026-10-18
:Deciders: Core Shard Architecture Team

Context
-------

Interfacing with TPM 2.0 hardware from high-level languages traditionally relies on multi-layered C libraries such as ``tpm2-tss`` ``libtss2-esys`` and ``libtss2-sys``, which introduce complex FFI state management, opaque memory lifecycles, and fragile testing environments when physical ``/dev/tpmrm0`` hardware is unavailable in CI containers.

Decision
--------

#. **Direct TCG TPM 2.0 Wire Framing**: Marshal and unmarshal big-endian TPM 2.0 commands and responses directly in pure Crystal via ``TPMCommand`` and ``TPMResponse`` over ``/dev/tpmrm0``, fulfilling ``[FUNC-001]`` and ``[TECH-001]``.
#. **Real OpenSSL 3.5 NIST P-256 Virtual Simulator**: Back the virtual ``TPMDevice`` simulator with genuine OpenSSL 3.5 ``EVP_PKEY`` NIST P-256 key generation, ``TPM2_ReadPublic`` coordinate extraction, and cryptographic ECDSA signing so unit and integration suites verify real elliptic curve signatures without requiring physical TPM hardware, fulfilling ``[FUNC-002]`` and ``[TECH-002]``.
#. **Disjoint NV Persistence and O(1) Nonce Tracking**: Store KDF master keys at ``0x01C00000``, allocate FIDO2 credential metadata in ``0x01800000..0x01BFFFFF`` with bounded linear probing, and guard all signatures with ``SignatureRTracker``, fulfilling ``[FUNC-003]``, ``[FUNC-004]``, ``[FUNC-005]``, and ``[TECH-003]``.

Consequences
------------

* **Positive**: Zero C TSS library dependencies, deterministic cryptographic verification in CI, full thread safety under Crystal 1.21 ``Sync::Mutex``, and immediate protection against hardware RNG nonce reuse.
* **Negative**: Additional TPM 2.0 structures and policy sessions beyond the Phase 1 FIDO2/KDF/Session subset must be framed explicitly in Crystal, motivating ``[FUNC-006]`` and ``[FUNC-007]`` in :doc:`2026-10-18-phase-2-tcg-part2-marshaling-and-policypcr`.
