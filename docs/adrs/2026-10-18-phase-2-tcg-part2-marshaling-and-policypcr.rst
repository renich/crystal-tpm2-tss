====================================================================
ADR-002: Phase 2 TCG Part 2 Binary Marshaling and PolicyPCR Sessions
====================================================================

:Status: Accepted
:Date: 2026-10-18
:Deciders: Core Shard Architecture Team

Context
-------

Phase 1 ``v0.4.0`` delivers a complete FIDO2 NIST P-256 credential lifecycle, KDFa ``XOR`` and ``AES-128-CFB`` parameter encryption, ``cpHash``/``rpHash`` calculation, and ``O(1)`` ECDSA nonce-reuse tracking validated against the stateful OpenSSL 3.5 virtual simulator. However, executing complex multi-command authorization flows against physical ``/dev/tpmrm0`` kernel resource managers requires complete TCG TPM 2.0 Part 2 nested binary structure marshaling and stateful hardware session handshakes for salted/bound HMAC and ``PolicyPCR`` sessions.

Decision
--------

#. **Dedicated TCG Part 2 Binary Codec**: Introduce ``Crystal::Tpm2::Tss::Tpm2bCodec`` in Phase 2 ``v0.5.0`` to encode and decode ``TPMS_AUTH_COMMAND``, ``TPMS_AUTH_RESPONSE``, ``TPM2B_SENSITIVE_CREATE``, ``TPM2B_PUBLIC``, ``TPMS_ECC_PARMS``, and ``TPMT_SIGNATURE`` with strict big-endian length validation, fulfilling ``[FUNC-006]`` and ``[TECH-006]``.
#. **Hardware Salted/Bound HMAC and PolicyPCR Session Lifecycle**: Extend ``Session`` and ``TPMDevice`` in Phase 2 ``v0.5.0`` to execute ``TPM2_StartAuthSession``, ``TPM2_PolicyPCR``, and ``TPM2_FlushContext`` with salted/bound ``KDFa`` session key derivation and automatic ``TPMS_AUTH_COMMAND``/``TPMS_AUTH_RESPONSE`` framing inside ``TPMDevice#execute``, fulfilling ``[FUNC-007]`` and ``[TECH-007]``.

Consequences
------------

* **Positive**: Physical ``/dev/tpmrm0`` hardware deployments gain wire-accurate TCG Part 2 marshaling, PCR state attestation binding, and automated multi-command session nonce synchronization without introducing C ``libtss2`` dependencies.
* **Negative**: Requires strict boundary fuzzing specs for nested ``TPM2B_*`` length prefixes to preserve the overflow-safe unmarshaling guarantees defined in ``[TECH-005]``.
