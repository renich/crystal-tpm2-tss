=================
Core Requirements
=================

Traceability Matrix
-------------------

.. list-table::
   :widths: 15 40 25 20
   :header-rows: 1

   * - Requirement ID
     - Capability Summary
     - Technical Specs
     - Roadmap Tasks
   * - ``[FUNC-001]``
     - TPM 2.0 Command/Response Framing and Transport
     - ``[TECH-001]``, ``[TECH-004]``
     - ``TASK-101`` (Phase 1 ``v0.4.0``)
   * - ``[FUNC-002]``
     - Real NIST P-256 Key Generation, ``TPM2_ReadPublic``, and ECDSA Verification
     - ``[TECH-002]``, ``[TECH-005]``
     - ``TASK-102`` (Phase 1 ``v0.4.0``)
   * - ``[FUNC-004]``
     - KDFa Key Derivation, Parameter Encryption, and Session ``cpHash``/``rpHash``
     - ``[TECH-003]``, ``[TECH-005]``
     - ``TASK-103`` (Phase 1 ``v0.4.0``)
   * - ``[FUNC-005]``
     - Bounded O(1) ECDSA Nonce-Reuse Detection
     - ``[TECH-003]``, ``[TECH-004]``, ``[TECH-005]``
     - ``TASK-104`` (Phase 1 ``v0.4.0``)
   * - ``[FUNC-003]``
     - Stateful FIDO2 Credential Lifecycle and NV Metadata Persistence
     - ``[TECH-002]``, ``[TECH-004]``, ``[TECH-005]``
     - ``TASK-105`` (Phase 1 ``v0.4.0``)
   * - ``[FUNC-006]``
     - Full TCG TPM 2.0 Part 2 Binary Structure Marshaling
     - ``[TECH-005]``, ``[TECH-006]``
     - ``TASK-201``, ``TASK-202`` (Phase 2 ``v0.5.0``)
   * - ``[FUNC-007]``
     - Hardware Salted/Bound HMAC and ``PolicyPCR`` Session Lifecycle
     - ``[TECH-005]``, ``[TECH-007]``
     - ``TASK-203``, ``TASK-204`` (Phase 2 ``v0.5.0``)

Phase 1 Functional Requirements
-------------------------------

* **[FUNC-001] TPM 2.0 Command/Response Framing and Transport**:
  The library must serialize big-endian ``TPMCommand`` packets containing structure tags ``TPM_ST_NO_SESSIONS`` or ``TPM_ST_SESSIONS``, 32-bit command codes, handle areas, 4-byte length-prefixed ``TPMS_AUTH_COMMAND`` authorization areas, and parameter buffers. ``TPMResponse.parse`` must validate minimum 10-byte response headers, widen session ``auth_size`` bounds checks to ``UInt64`` to prevent integer wraparound, extract ``nonceTPM`` fields into active ``Session`` instances, and raise ``TPMError`` on malformed frames. ``TPMDevice`` must support fail-closed character device I/O over ``/dev/tpmrm0`` using stack-allocated ``StaticArray(UInt8, 4096)`` buffers alongside a thread-safe in-memory virtual simulator. Fulfilled by ``[TECH-001]`` in :doc:`../../technical/specs/architecture-overview`, ``[TECH-004]`` in :doc:`../../technical/specs/coding-standards`, and :doc:`../../technical/specs/release-procedure`.

* **[FUNC-002] Real NIST P-256 Key Generation, TPM2_ReadPublic, and ECDSA Verification**:
  ``P256Key`` must bind directly to OpenSSL 3.5 ``libcrypto`` ``EVP_PKEY`` APIs to generate prime256v1/secp256r1 keypairs, extract uncompressed 32-byte affine ``x`` and ``y`` public coordinates, sign 32-byte SHA-256 digests, and verify ``ECDSASignature`` structs via ASN.1 ``SubjectPublicKeyInfo`` DER reconstruction. ``FIDO2Credential#public_key_xy`` and ``FIDO2Credential#verify`` must retrieve public coordinates via ``TPM2_ReadPublic`` and cryptographically verify signatures produced by both hardware and virtual TPM transports. Fulfilled by ``[TECH-002]`` in :doc:`../../technical/specs/architecture-overview` and ``[TECH-005]`` in :doc:`../../technical/specs/threat-model`.

* **[FUNC-003] Stateful FIDO2 Credential Lifecycle and NV Metadata Persistence**:
  ``FIDO2CredentialManager`` and ``NVMetadataStore`` must orchestrate the end-to-end FIDO2 credential lifecycle across ``TPM2_CreatePrimary``, ``TPM2_Create``, ``TPM2_Load``, ``TPM2_EvictControl``, ``TPM2_ReadPublic``, ``TPM2_FlushContext``, ``TPM2_NV_DefineSpace``, ``TPM2_NV_Write``, ``TPM2_NV_Read``, and ``TPM2_Sign``. Each ``credential_id`` must map to a collision-free dynamic persistent handle ``0x81010000 | hash_u16`` in the ``0x81010001..0x8101FFFF`` range and persist its ``persistent_handle`` and ``credential_id`` record in the disjoint ``0x01800000..0x01BFFFFF`` NV address space using bounded linear probing up to 16 attempts. Fulfilled by ``[TECH-002]`` in :doc:`../../technical/specs/architecture-overview`, ``[TECH-004]`` in :doc:`../../technical/specs/coding-standards`, and ``[TECH-005]`` in :doc:`../../technical/specs/threat-model`.

* **[FUNC-004] KDFa Key Derivation, Parameter Encryption, and Session cpHash/rpHash**:
  ``KDFKeyManager`` must provision and cache a 32-byte root key at NV index ``0x01C00000`` authorized by the SHA-256 digest of ``platform_secret``. ``ParameterEncryption`` must implement TCG TPM 2.0 Part 1 Section 11.4.9.2 ``KDFa`` counter-mode key derivation and provide symmetric parameter encryption and decryption for both ``XOR`` obfuscation and ``AES-128-CFB`` cipher feedback mode, raising ``SecurityError`` if ``session_key``, ``nonceCaller``, or ``nonceTPM`` is empty. ``Session`` must compute TCG TPM 2.0 Part 1 Section 19.6.5 ``cpHash`` and ``rpHash`` digests, roll caller nonces, and verify response HMACs in constant time via ``Crypto::Subtle.constant_time_compare``. Fulfilled by ``[TECH-003]`` in :doc:`../../technical/specs/architecture-overview` and ``[TECH-005]`` in :doc:`../../technical/specs/threat-model`.

* **[FUNC-005] Bounded O(1) ECDSA Nonce-Reuse Detection**:
  ``SignatureRTracker`` must track observed ECDSA ``r`` components in constant ``O(1)`` time using a ``Set(String)`` membership index paired with a ``Deque(String)`` FIFO eviction ring guarded by ``Sync::Mutex``. Calling ``SignatureRTracker#check_and_add!`` must atomically raise ``SecurityError`` upon detecting any duplicate ``r`` value within the active window and evict the oldest half of entries when capacity exceeds ``max_size``. Fulfilled by ``[TECH-003]`` in :doc:`../../technical/specs/architecture-overview`, ``[TECH-004]`` in :doc:`../../technical/specs/coding-standards`, and ``[TECH-005]`` in :doc:`../../technical/specs/threat-model`.

Phase 2 Functional Requirements
-------------------------------

* **[FUNC-006] Full TCG TPM 2.0 Part 2 Binary Structure Marshaling**:
  Targeted for Phase 2 ``v0.5.0``, ``Tpm2bCodec`` must provide deterministic binary encoders and decoders for TCG TPM 2.0 Part 2 wire structures required by physical ``/dev/tpmrm0`` hardware command execution, including ``TPMS_AUTH_COMMAND``, ``TPMS_AUTH_RESPONSE``, ``TPM2B_SENSITIVE_CREATE``, ``TPM2B_PUBLIC``, ``TPMS_ECC_PARMS``, and ``TPMT_SIGNATURE``. All decoders must enforce strict big-endian length prefix validation and reject truncated or trailing bytes with ``TPMError``. Fulfilled by ``[TECH-006]`` in :doc:`../../technical/specs/architecture-overview` and ``[TECH-005]`` in :doc:`../../technical/specs/threat-model`.

* **[FUNC-007] Hardware Salted/Bound HMAC and PolicyPCR Session Lifecycle**:
  Targeted for Phase 2 ``v0.5.0``, ``Session`` and ``TPMDevice`` must implement the full hardware session lifecycle across ``TPM2_StartAuthSession``, ``TPM2_PolicyPCR``, and ``TPM2_FlushContext``. ``Session`` must support salted and bound session key derivation via ``KDFa``, maintain rolling ``nonceCaller`` and ``nonceTPM`` state across multi-command policy sequences, and automatically attach and verify ``TPMS_AUTH_COMMAND`` and ``TPMS_AUTH_RESPONSE`` frames during ``TPMDevice#execute``. Fulfilled by ``[TECH-007]`` in :doc:`../../technical/specs/architecture-overview` and ``[TECH-005]`` in :doc:`../../technical/specs/threat-model`.
